package vaulttoken

import (
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jimsnab/go-lane"
	"github.com/pkg/errors"
)

type (
	gcpAuthToken struct {
		token      *vaultapi.Secret
		expiration time.Time
		cfg        *gcpAuthConfig
		client     *vaultapi.Client
	}
)

// newGcpAuthToken returns a struct for a class of functions that perform a Vault
// login with a Google Service Account (gsa) signed JWT, and maintain the token
func newGcpAuthToken(gcpcfg *gcpAuthConfig, client *vaultapi.Client) *gcpAuthToken {
	return &gcpAuthToken{
		cfg:    gcpcfg,
		client: client,
	}
}

// getToken performs a fresh login to Vault using a gsa-signed JWT
func (gat *gcpAuthToken) getToken(l lane.Lane) (token *vaultapi.Secret, err error) {
	if gat.token == nil {
		jwt := newGcpAuthJwt(gat.cfg)

		var signedJwt string
		if signedJwt, err = jwt.createSignedJwtWithRetry(l, 5); err != nil {
			err = errors.Wrap(err, "can't get signed jwt token for auth")
			return
		}

		jsonData := map[string]any{
			"role": gat.cfg.role,
			"jwt":  signedJwt,
		}

		// capture time before the login request
		now := time.Now()

		var resp *vaultapi.Secret
		if resp, err = gat.client.Logical().Write(gat.cfg.authPath+"/login", jsonData); err != nil {
			err = errors.Wrap(err, "vault login request error")
			return
		}

		var tokenTtl time.Duration
		if tokenTtl, err = resp.TokenTTL(); err != nil {
			err = errors.Wrap(err, "vault token ttl error")
			return
		}

		gat.token = resp
		gat.expiration = now.Add(tokenTtl)
	}

	token = gat.token
	return
}

// isExpired looks at the current time and indicates if the token has expired. A nil
// token is considered expired.
func (gat *gcpAuthToken) isExpired(l lane.Lane) (expired bool, err error) {
	if gat.token == nil {
		expired = true
	} else {
		expired = time.Now().After(gat.expiration)
	}
	return
}

// isRevoked asks Vault to look up the token, and if any error occurs, the token is
// considered revoked. A nil token is also considered revoked.
func (gat *gcpAuthToken) isRevoked(l lane.Lane) (revoked bool, err error) {
	if gat.token == nil {
		revoked = true
	} else {
		var client *vaultapi.Client
		if client, err = gat.client.Clone(); err != nil {
			err = errors.Wrap(err, "can't clone vault api client to check revocation")
			return
		}
		client.SetToken(gat.token.Auth.ClientToken)

		_, testErr := client.Auth().Token().LookupSelfWithContext(l)
		revoked = (testErr == nil)
	}
	return
}

// refresh asks Vault to extend the life of the token, and suggests a number of
// seconds to add via nextTtlInSeconds. Vault doesn't have to use the suggested
// new TTL.
func (gat *gcpAuthToken) refresh(l lane.Lane, nextTtlInSeconds int) (err error) {
	if gat.token == nil {
		err = fmt.Errorf("can't refresh nil token")
		return
	}

	var token *vaultapi.Secret
	if token, err = gat.client.Auth().Token().RenewSelfWithContext(l, nextTtlInSeconds); err != nil {
		err = errors.Wrap(err, "can't refresh vault api token")
		return
	}

	var tokenTtl time.Duration
	if tokenTtl, err = token.TokenTTL(); err != nil {
		err = errors.Wrap(err, "vault token refresh ttl error")
		return
	}

	gat.expiration = time.Now().Add(tokenTtl)
	return
}

// revoke asks Vault to discontinue use of the current token. A new login is required
// upon success.
func (gat *gcpAuthToken) revoke(l lane.Lane) (err error) {
	if gat.token != nil {
		if err = gat.client.Auth().Token().RevokeSelfWithContext(l, ""); err != nil {
			err = errors.Wrap(err, "revoke vault token error")
			return
		}

		gat.token = nil
	}
	return
}
