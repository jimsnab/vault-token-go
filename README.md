# Vault-Token

This library manages a Hashicorp Vault Client that connects to a Vault server using
cloud provider supported authentication, or via a directly provided token.

The directly provided token is used for local development/testing.

# GCP Only

Currently only GCP is supported by this library, and Workload Identity must be configured
between the app and the Vault server.

The interface will go through revision as other cloud providers are added.

# Usage

```go
import (
    "context"
    "fmt"

    "github.com/jimsnab/go-lane"
    "github.com/jimsnab/vault-token-go"
)

func main() {
    d := mydata{}

    // get config from your method of choice
    uri := os.Getenv("VAULT_URI")
    caCert := os.Getenv("VAULT_CA_CERT")        // optional - the server CA cert file
    caPath := os.Getenv("VAULT_CA_PATH")        // optional - a directory of CA certs - use caCert or caPath, not both
    token := os.Getenv("VAULT_TOKEN")           // empty string for cloud hosting; a Vault-issued auth token for local development/testing

    appName := os.Getenv("APP_NAME")

    l := lane.NewLogLane(context.Background())  // provide your choice of log lane

    vaultRole := fmt.Sprintf("%s-app-role", appName)        // find vaultRole from the server, ex: vault list auth/gcp/roles

    // keep the client around long term
    vcc, err := NewVaultClient(l, d.uri, d.caCert, d.token, vaultRole)
    if err != nil {
        l.Fatal(err)
    }

    // get the API interface when a fresh token is needed; the frequency
    // depends on Vault server token expiration settings
    vc, err := vcc.GetApiInterface(l)
	if err != nil {
		l.Fatal(err)
	}

	secret, err := vc.KVv2("my-kv-v2-engine").Get(l, "my-secret")

	if err != nil {
		if !strings.Contains(err.Error(), "secret not found") {
			l.Fatal(err)
		}
        fmt.Println("my-secret doesn't exist in Vault under my-kv-v2-engine")
	} else {
		password, exists = secret.Data["password"].(string)
        if exists {
            fmt.Println("password: ", password)
        } else {
            fmt.Println("password not set in Vault")
        }
	}
}
```