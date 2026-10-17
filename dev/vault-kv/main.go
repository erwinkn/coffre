// The calls ESO v2.13.0's Vault provider makes with tokenSecretRef, through
// the client it pins (hashicorp/vault/api v1.22.0), plus `vault kv get`'s
// mount lookup, against `pnpm dev`'s Vault adapter (docs/design/plugins.md).
// It expects the seed: ci-deploy reads market/prod, not market/dev. From
// this directory, with ci-deploy's token from the seed's output:
//
//   docker run --rm --network host -v "$PWD":/src -w /src \
//     -e VAULT_ADDR=http://127.0.0.1:3000 -e VAULT_TOKEN=coffre_svc_… \
//     golang:1.25-alpine go run .
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	vault "github.com/hashicorp/vault/api"
)

func check(step string, err error) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", step, err)
		os.Exit(1)
	}
}

func main() {
	ctx := context.Background()
	client, err := vault.NewClient(vault.DefaultConfig()) // reads VAULT_ADDR, VAULT_TOKEN
	check("client", err)

	// SecretStore validation (validate.go -> checkToken, auth.go:166-220).
	self, err := client.Auth().Token().LookupSelfWithContext(ctx)
	check("lookup-self", err)
	_, isString := self.Data["type"].(string)
	_, isNumber := self.Data["ttl"].(json.Number)
	_, hasExpire := self.Data["expire_time"]
	fmt.Printf("ok   lookup-self: type string=%v ttl number=%v expire_time present=%v display_name=%v\n", isString, isNumber, hasExpire, self.Data["display_name"])

	// GetSecret / GetSecretMap (client_get.go:123-160): Logical().ReadWithDataWithContext on <path>/data/<key>.
	secret, err := client.Logical().ReadWithDataWithContext(ctx, "secret/data/market/prod", nil)
	check("read env", err)
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		check("read env", fmt.Errorf("data.data is not an object"))
	}
	keys := []string{}
	for k := range data {
		keys = append(keys, k)
	}
	fmt.Printf("ok   read secret/data/market/prod: %d keys %v\n", len(keys), keys)

	one, err := client.KVv2("secret").Get(ctx, "market/prod/DATABASE_URL")
	check("kv v2 get key", err)
	fmt.Printf("ok   KVv2(secret).Get(market/prod/DATABASE_URL): %d key, version %d\n", len(one.Data), one.VersionMetadata.Version)

	// A 404: the client answers nil, nil, which ESO turns into NoSecretError.
	missing, err := client.Logical().ReadWithDataWithContext(ctx, "secret/data/market/nowhere", nil)
	check("read missing", err)
	fmt.Printf("ok   read missing: secret is nil=%v\n", missing == nil)

	// A refusal: ResponseError with 403.
	_, err = client.Logical().ReadWithDataWithContext(ctx, "secret/data/market/dev", nil)
	if re, ok := err.(*vault.ResponseError); ok {
		fmt.Printf("ok   read forbidden: status %d errors %v\n", re.StatusCode, re.Errors)
	} else {
		fmt.Printf("FAIL read forbidden: %v\n", err)
		os.Exit(1)
	}

	// A write: refused.
	_, err = client.Logical().WriteWithContext(ctx, "secret/data/market/prod", map[string]interface{}{"data": map[string]interface{}{"X": "y"}})
	if re, ok := err.(*vault.ResponseError); ok {
		fmt.Printf("ok   write refused: status %d\n", re.StatusCode)
	} else {
		fmt.Printf("FAIL write: %v\n", err)
		os.Exit(1)
	}

	// `vault kv get`'s mount lookup (command/client/kv_helpers.go).
	mount, err := client.Logical().ReadWithContext(ctx, "sys/internal/ui/mounts/secret/market/prod")
	check("ui mounts", err)
	options, _ := mount.Data["options"].(map[string]interface{})
	fmt.Printf("ok   ui/mounts: path=%v version=%v\n", mount.Data["path"], options["version"])
}
