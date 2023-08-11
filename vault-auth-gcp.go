package vaulttoken

import (
	"net/http"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jimsnab/go-lane"
)

type (
	gcpAuthConfig struct {
		role       string
		authPath   string
		testClient *http.Client
	}

	gcpAuth struct {
	}
)

// getConfig provides a config object for newVaultToken
func (auth *gcpAuth) getConfig(l lane.Lane, vaultRole string) (cfg VaultAuthConfig, err error) {
	// This specifies Vault's auth config
	gcpcfg := gcpAuthConfig{
		role:     vaultRole,
		authPath: "auth/gcp",
	}

	cfg = gcpcfg
	return
}

func (auth *gcpAuth) newVaultToken(l lane.Lane, authCfg VaultAuthConfig, client *vaultapi.Client) (token VaultToken, err error) {
	gcpcfg := authCfg.(gcpAuthConfig)
	gat := newGcpAuthToken(&gcpcfg, client)
	token = gat
	return
}
