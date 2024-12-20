package vaulttoken

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/cenkalti/backoff/v3"
	"github.com/jimsnab/go-lane"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type (
	gcpAuthJwt struct {
		cfg *gcpAuthConfig
	}
)

const (
	kJwtTokenTimeoutMins      = 1 // corresponds to Vault policy
	kJwtClientIdleTimeoutSecs = 1
	kGcpAuthUrl               = "https://www.googleapis.com/auth/cloud-platform"
	kGcpMetadataUrl           = "http://metadata.google.internal/computeMetadata/v1"
	kGcpIamCredentialsUrl     = "https://iamcredentials.googleapis.com/v1"
)

// newGcpAuthJwt creates a structure that wraps a Google Service Account (gsa)
// signed JWT token. It is a worker class used by gcpAuthToken.
func newGcpAuthJwt(gcpcfg *gcpAuthConfig) *gcpAuthJwt {
	return &gcpAuthJwt{
		cfg: gcpcfg,
	}
}

// try creating the signed JWT until success or the number of attempts has been exhausted.
// On success, the returned JWT is signed by the gsa.
func (jwt *gcpAuthJwt) createSignedJwtWithRetry(l lane.Lane, maxRetries int) (signedJwt string, err error) {

	b := backoff.NewExponentialBackOff()

	err = backoff.Retry(func() error {
		signedJwt, err = jwt.createSignedJwt(l)
		return err
	}, backoff.WithMaxRetries(b, uint64(maxRetries)))

	if err != nil {
		l.Errorf("unable to sign JWT after %d retries: %v", maxRetries, err)
		return
	}

	return signedJwt, nil
}

// Create a JWT signed by the Google Service Account (gsa) associated with this service.
// Vault must be configured with GCP Auth and a Vault role binding to the same gsa.
// see https://www.vaultproject.io/docs/auth/gcp.html#the-iam-authentication-token and
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
func (jwt *gcpAuthJwt) createSignedJwt(l lane.Lane) (signedJwt string, err error) {
	var saEmail string
	var tokenSrc oauth2.TokenSource
	if saEmail, tokenSrc, err = jwt.getSaInfo(l); err != nil {
		l.Errorf("unable to get service account from environment: %v", err)
		return
	}

	// derive an http client that has the gsa token source
	defaultClient := jwt.getHttpClient()
	hc := &http.Client{
		Timeout: defaultClient.Timeout,
		Transport: &oauth2.Transport{
			Source: tokenSrc,
			Base:   defaultClient.Transport,
		},
	}

	var claim []byte
	claim, err = json.Marshal(map[string]interface{}{
		"aud": "vault/" + jwt.cfg.role,
		"sub": saEmail,
		"exp": time.Now().UTC().Add(kJwtTokenTimeoutMins * time.Minute).Unix(),
	})
	if err != nil {
		l.Errorf("inner jwt marshalling error: %v", err)
		return
	}

	l.Tracef("claim: %s", string(claim))

	// escape the claim json per https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
	var payload []byte
	if payload, err = json.Marshal(string(claim)); err != nil {
		l.Errorf("outer jwt marshalling error: %v", err)
		return
	}

	reqBody := []byte(`{"payload":` + string(payload) + "}")
	url := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:signJwt", kGcpIamCredentialsUrl, url.PathEscape(saEmail))

	l.Tracef("request url: %s", url)
	l.Tracef("request body: %s", string(reqBody))

	var resp *http.Response
	resp, err = hc.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		l.Errorf("error posting to gcp oauth2: %v", err)
		return
	}
	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		l.Errorf("error receiving gcp oauth2 response: %v", err)
		return
	}

	var data map[string]any
	if err = json.Unmarshal(body, &data); err != nil {
		l.Errorf("error parsing gcp oauth2 response: %v", err)
		l.Infof("body: %s", string(body))
		return
	}

	jwtErr, exists := data["error"]
	if exists {
		m := jwtErr.(map[string]any)
		l.Errorf("error requesting jwt signing %d %s %s", int(m["code"].(float64)), m["status"].(string), m["message"].(string))
		err = errors.New(m["message"].(string))
		return
	}

	signedJwt, exists = data["signedJwt"].(string)
	if !exists {
		l.Errorf("unexpected jwt signing response: %s", string(body))
		err = errors.New("unexpected jwt signing response")
		return
	}
	return
}

// The current running context provides a Kubernetes Service Account (ksa)
// which maps to a Google Service Account (gsa) via Google's Workload Identity.
// If that mechanism isn't set up properly, the code here will fall back to
// the default gsa.
func (jwt *gcpAuthJwt) getSaInfo(l lane.Lane) (saEmail string, tokenSrc oauth2.TokenSource, err error) {
	l.Tracef("vault-auth-gcp: requesting GCP default credentials at %s", kGcpAuthUrl)

	var creds *google.Credentials
	if creds, err = google.FindDefaultCredentials(l, kGcpAuthUrl); err != nil {
		l.Errorf("unable to find default google credentials for service account: %v", err)
		return
	}

	if saEmail, err = jwt.parseCredentials(l, creds); err != nil {
		l.Errorf("unable to get client e-mail from default google credentials: %v", err)
		return
	}

	if saEmail == "" {
		if saEmail, err = jwt.getDefaultSaEmail(l); err != nil {
			return
		}
	}

	tokenSrc = creds.TokenSource
	return
}

// see https://cloud.google.com/compute/docs/metadata/overview
func (jwt *gcpAuthJwt) getDefaultSaEmail(l lane.Lane) (saEmail string, err error) {
	saEmail, err = metadata.EmailWithContext(l, "")
	if err != nil {
		l.Errorf("vault-auth-gcp: can't get default sa email: %v", err)
		return
	}

	l.Tracef("vault-auth-gcp: default sa email is %s", saEmail)
	if !strings.Contains(saEmail, "@") {
		l.Warnf("vault-auth-gcp: ensure your workload is running in the intended kubernetes service account context; check the deployment resource serviceAccountName setting")
	}
	return
}

// worker that pulls out client e-mail address from credentials provided by
// the Google client SDK
func (jwt *gcpAuthJwt) parseCredentials(l lane.Lane, creds *google.Credentials) (email string, err error) {
	if len(creds.JSON) > 0 {
		var data map[string]string
		if err = json.Unmarshal(creds.JSON, &data); err != nil {
			l.Errorf("unable to parse credentials: %v", err)
			l.Info("credentials: %s", string(creds.JSON))
			return
		}

		email = data["client_email"]
		if email == "" {
			l.Debug("vault-auth-gcp: client_email is empty")
		}
	} else {
		l.Debug("vault-auth-gcp: creds.JSON is empty")
	}

	return
}

// Creates an http client for REST requests, with test hook possibility
func (jwt *gcpAuthJwt) getHttpClient() *http.Client {
	// allow test hook
	if jwt.cfg.testClient != nil {
		return jwt.cfg.testClient
	}
	return &http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: kJwtClientIdleTimeoutSecs * time.Second,
		},
	}
}
