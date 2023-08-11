package vaulttoken

import (
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jimsnab/go-lane"
)

type (
	VaultAuthConfig interface {
	}

	VaultToken interface {
		getToken(l lane.Lane) (*vaultapi.Secret, error)
		isExpired(l lane.Lane) (bool, error)
		isRevoked(l lane.Lane) (bool, error)
		refresh(l lane.Lane, nextTtlInSeconds int) error
		revoke(l lane.Lane) error
	}

	VaultAuth interface {
		getConfig(l lane.Lane, vaultRole string) (VaultAuthConfig, error)
		newVaultToken(l lane.Lane, authCfg VaultAuthConfig, client *vaultapi.Client) (VaultToken, error)
	}
)
