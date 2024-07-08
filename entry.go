package vaulttoken

import (
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jimsnab/go-lane"
)

type (
	VaultClientConnection struct {
		vc      *vaultapi.Client
		auth    VaultAuth
		authCfg VaultAuthConfig
	}
)

// Makes a new Vault client. This is a setup operation, preparing the auth,
// but not connecting to Vault server except for possibly getting a JWT.
//
// The caller can then call vcc.GetApiInterface() to access server APIs
// with a fresh token.
//
// Specify caCert or caPath, not both. These provide the public cert of the
// server (e.g., root-ca).
//
// vaultRole is the role name in the Vault server for the cloud account
// that can mint a JWT token.
func NewVaultClient(l lane.Lane, uri, caCert, caPath, vaultToken, vaultRole string) (vcc *VaultClientConnection, err error) {
	vcc = &VaultClientConnection{}

	vcfg := vaultapi.DefaultConfig()
	vcfg.Address = uri

	tlsConfig := vaultapi.TLSConfig{
		CACert: caCert, // server ca pem file path
		CAPath: caPath, // server ca pem(s) dir path
	}
	vcfg.ConfigureTLS(&tlsConfig)

	var vc *vaultapi.Client
	if vc, err = vaultapi.NewClient(vcfg); err != nil {
		l.Errorf("vault client: failed to get vault client: %v", err)
		return
	}
	vcc.vc = vc

	// if token env variable is set, use it (typical for local hosting)
	if vaultToken != "" {
		vc.SetToken(vaultToken)
		return
	}

	// otherwise assume the environment is GKE with workload identity
	// providing auth to get a JWT

	// get a GCP auth config
	auth := VaultAuth(&gcpAuth{})
	vcc.auth = auth

	var authCfg VaultAuthConfig
	if authCfg, err = auth.getConfig(l, vaultRole); err != nil {
		l.Errorf("vault client: failed to get GCP auth config: %v", err)
		return
	}

	vcc.authCfg = authCfg
	return
}

// Returns a vault client with a fresh auth token.
// See https://github.com/hashicorp/vault-examples/blob/main/examples/_quick-start/go/example.go.
func (vcc *VaultClientConnection) GetApiInterface(l lane.Lane) (vc *vaultapi.Client, err error) {
	// if static token, just return the client
	vc = vcc.vc
	if vcc.auth == nil {
		return
	}

	// otherwise refresh the token
	var tokenProvider VaultToken
	if tokenProvider, err = vcc.auth.newVaultToken(l, vcc.authCfg, vc); err != nil {
		l.Errorf("vault client: error creating auth token: %v", err)
		return
	}

	var token *vaultapi.Secret
	if token, err = tokenProvider.getToken(l); err != nil {
		l.Errorf("vault client: error in vault authentication: %v", err)
		return
	}

	vc.SetToken(token.Auth.ClientToken)
	return
}
