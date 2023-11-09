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
	cJwtTokenTimeoutMins      = 1 // corresponds to Vault policy
	cJwtClientIdleTimeoutSecs = 1
	cGcpAuthUrl               = "https://www.googleapis.com/auth/cloud-platform"
	cGcpMetadataUrl           = "http://metadata.google.internal/computeMetadata/v1"
	cGcpIamCredentialsUrl     = "https://iamcredentials.googleapis.com/v1"
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
		err = errors.Wrapf(err, "unable to sign JWT after %d retries", maxRetries)
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
		err = errors.Wrap(err, "unable to get service account from environment")
		return
	}

	// deriive an http client that has the gsa token source
	defaultClient := jwt.getHttpClient(l)
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
		"exp": time.Now().UTC().Add(cJwtTokenTimeoutMins * time.Minute).Unix(),
	})
	if err != nil {
		err = errors.Wrap(err, "inner jwt marshalling error")
		return
	}

	l.Tracef("claim: %s", string(claim))

	// escape the claim json per https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
	var payload []byte
	if payload, err = json.Marshal(string(claim)); err != nil {
		err = errors.Wrap(err, "outer jwt marshalling error")
		return
	}

	reqBody := []byte(`{"payload":` + string(payload) + "}")
	url := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:signJwt", cGcpIamCredentialsUrl, url.PathEscape(saEmail))

	l.Tracef("request url: %s", url)
	l.Tracef("request body: %s", string(reqBody))

	var resp *http.Response
	resp, err = hc.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		err = errors.Wrap(err, "error posting to gcp oauth2")
		return
	}
	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		err = errors.Wrap(err, "error receiving gcp oauth2 response")
		return
	}

	var data map[string]any
	if err = json.Unmarshal(body, &data); err != nil {
		err = errors.Wrap(err, "error parsing gcp oauth2 response")
		return
	}

	jwtErr, exists := data["error"]
	if exists {
		m := jwtErr.(map[string]any)
		err = fmt.Errorf("error requesting jwt signing %d %s %s", int(m["code"].(float64)), m["status"].(string), m["message"].(string))
		return
	}

	signedJwt, exists = data["signedJwt"].(string)
	if !exists {
		err = fmt.Errorf("unexpected jwt signing response: %s", string(body))
		return
	}
	return
}

// The current running context provides a Kubernetes Service Account (ksa)
// which maps to a Google Service Account (gsa) via Google's Workload Identity.
// If that mechanism isn't set up properly, the code here will fall back to
// the default gsa.
func (jwt *gcpAuthJwt) getSaInfo(l lane.Lane) (saEmail string, tokenSrc oauth2.TokenSource, err error) {
	var creds *google.Credentials
	if creds, err = google.FindDefaultCredentials(l, cGcpAuthUrl); err != nil {
		err = errors.Wrap(err, "unable to find default google credentials for service account")
		return
	}

	if saEmail, err = jwt.parseCredentials(l, creds); err != nil {
		err = errors.Wrap(err, "unable to get client e-mail from default google credentials")
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
	c := jwt.getHttpClient(l)

	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, cGcpMetadataUrl+"/instance/service-accounts/default/email", nil)
	if err != nil {
		err = errors.Wrap(err, "unable create metadata request")
		return
	}
	req.Header.Add("Metadata-Flavor", "Google")

	var resp *http.Response
	if resp, err = c.Do(req); err != nil {
		err = errors.Wrap(err, "error connecting to metadata server")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = errors.Errorf("unexpected status response from metadata service: %d", resp.StatusCode)
		return
	}

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		err = errors.Wrap(err, "unable to read metadata response")
		return
	}

	result := strings.TrimSpace(string(body))
	if result == "" {
		err = errors.New("unexpected empty response from metadata service")
		return
	}

	return result, nil
}

// worker that pulls out client e-mail address from credentials provided by
// the Google client SDK
func (jwt *gcpAuthJwt) parseCredentials(l lane.Lane, creds *google.Credentials) (email string, err error) {
	if len(creds.JSON) > 0 {
		var data map[string]string
		if err = json.Unmarshal(creds.JSON, &data); err != nil {
			err = errors.Wrap(err, "unable to parse credentials")
			return
		}

		email = data["client_email"]
		if email == "" {
			l.Debug("vault-auth-gcp: client_email is empty")
			l.Debugf("vault-auth-gcp: gcp credentials: %v", creds)
		}
	} else {
		l.Debug("vault-auth-gcp: creds.JSON is empty")
		l.Debugf("vault-auth-gcp: gcp credentials: %v", creds)
	}

	return
}

// Creates an http client for REST requests, with test hook possibility
func (jwt *gcpAuthJwt) getHttpClient(l lane.Lane) *http.Client {
	// allow test hook
	if jwt.cfg.testClient != nil {
		return jwt.cfg.testClient
	}
	return &http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: cJwtClientIdleTimeoutSecs * time.Second,
		},
	}
}
