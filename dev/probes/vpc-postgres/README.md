# VPC Postgres smoke probe (throwaway, do not merge)

A Worker that answers two questions before coffre 0.11's tunnel ships:

1. Does a Workers VPC **Network** binding's `connect("host:port")` work from inside a
   Durable Object? Cloudflare's docs only show it from a Worker.
2. Does a plaintext Postgres session reach Equisafe's private prod read replica
   through `cloudflared`, log in as `debug_ro` with SCRAM-SHA-256, and run `select 1`?

`GET /worker` dials from the Worker, `GET /do` from inside a Durable Object. Both run
the same code: SSLRequest, StartupMessage, SCRAM-SHA-256, two fixed queries, Terminate.
The probe never takes SQL from the request. Every request without
`Authorization: Bearer <PROBE_KEY>` gets an empty 404, whatever its path. Without a
`PROBE_KEY` secret of 32 characters or more, the probe answers nothing at all. It
never logs and never returns the password.

## What Infra provides

| Input | Goes in | Note |
| --- | --- | --- |
| Tunnel UUID | `wrangler.jsonc`, `vpc_networks[0].tunnel_id` | A `cloudflared` that can reach the replica. It must run 2025.7.0 or later, over QUIC (outbound UDP 7844). |
| Replica private IP | `vars.PG_HOST` | |
| Replica port | `vars.PG_PORT` | `5432` unless told otherwise |
| Database name | `vars.PG_DATABASE` | |
| `debug_ro` password | `wrangler secret put DEBUG_RO_PASSWORD` | Stored as SCRAM (`password_encryption = scram-sha-256`). ASCII only: the probe skips SASLprep. |
| Access rule | the replica | Allow plaintext SCRAM logins from the `cloudflared` pods' addresses, e.g. `host <db> debug_ro <cloudflared pods CIDR> scram-sha-256` (`host`, not `hostssl`). On a managed database, an ACL that allows those addresses and does not require TLS. |

The replica sees the connection come from `cloudflared`, not from Cloudflare.

## Credentials

Use the Equisafe account, `4d1bbbc86d9eb5a3976d7a3c61b1a478` (already set as `account_id`).

- **Easiest:** `pnpm exec wrangler login` as your own user. Your role on the account
  needs **Connectivity Directory Admin**, the only role that may bind a tunnel
  directly. Super Administrator includes it.
- **API token instead:** start from the "Edit Cloudflare Workers" template, limited to
  the Equisafe account. It brings **Workers Scripts: Edit** and **Account Settings:
  Read**. Add **Connectivity Directory Admin** if the token form lists it. The docs
  name it only as a role, so if `deploy` refuses the `vpc_networks` binding with a
  permission error, fall back to `wrangler login`. Then `export CLOUDFLARE_API_TOKEN=…`.

## Deploy and run

From a checkout of this branch:

```sh
cd dev/probes/vpc-postgres
pnpm install
# Edit wrangler.jsonc: replace the REPLACE_ME values with Infra's inputs.
pnpm check                      # typecheck + wrangler deploy --dry-run
pnpm exec wrangler deploy       # prints https://vpc-postgres-probe.<subdomain>.workers.dev

PROBE_KEY=$(openssl rand -hex 32)
printf %s "$PROBE_KEY" | pnpm exec wrangler secret put PROBE_KEY
```

Run this one alone: it prompts for the password, and lines pasted after it would be read as the password.

```sh
pnpm exec wrangler secret put DEBUG_RO_PASSWORD
```

Then:

```sh
URL=https://vpc-postgres-probe.<subdomain>.workers.dev
curl -sS -H "Authorization: Bearer $PROBE_KEY" "$URL/worker" | jq
curl -sS -H "Authorization: Bearer $PROBE_KEY" "$URL/do" | jq
curl -sS -H "Authorization: Bearer $PROBE_KEY" "$URL/do?hold=300" | jq   # idle 5 min, then query again
curl -sS -o /dev/null -w '%{http_code}\n' "$URL/do"                       # 404: the gate
```

`hold` takes whole seconds from 0 to 600, on either route. While it runs, the
response sends a space every 20 s so that nothing on the way drops a silent
response. `jq` skips the spaces.

## Reading the result

```json
{
  "route": "do",
  "colo": "CDG",
  "ok": true,
  "dialMs": 41,
  "sslRequest": "N",
  "sslRequestMs": 38,
  "authOffered": ["SCRAM-SHA-256"],
  "serverVersion": "16.4",
  "loginOk": true,
  "loginMs": 95,
  "select1": "1",
  "session": { "current_user": "debug_ro", "inet_server_addr": "10.0.0.12", "ssl": "f" },
  "afterHold": { "seconds": 300, "select1": "1", "ms": 37 },
  "totalMs": 300212
}
```

- **Question 1** is answered yes when `/do` returns `ok: true`. If `/worker` works and
  `/do` fails at `"stage": "dial"`, the binding does not work from a Durable Object.
- **Question 2** is answered yes when `loginOk` is true, `select1` is `"1"`,
  `session.current_user` is `debug_ro` and `session.ssl` is `"f"`: a plaintext session.
- `sslRequest`: `N` means the replica has TLS off. `S` means it would take TLS, which
  a VPC socket cannot start. The probe then dials again and starts in plaintext,
  shown by `"redialedPlaintext": true`.
- `dialMs` is the time to the binding's open socket. `sslRequestMs` is the first
  round trip through the tunnel, the closest number to the network latency.
- `afterHold` shows whether an idle session survives that long. A failure there reads
  `"stage": "hold"`.
- `colo` is the Worker's location. The Durable Object lives where it was first created,
  near your first `/do` request.

On a failure, `ok` is `false`, `stage` says where it stopped, and `error` gives the
message. Postgres's own errors come as `<severity> <SQLSTATE>: <message>`.

| `stage` | Likely cause |
| --- | --- |
| `config` | A var or `DEBUG_RO_PASSWORD` is missing. |
| `dial` | The binding refused or timed out: the tunnel id, a role, or `cloudflared` cannot reach the IP. Gateway's network logs list the session with **Workers VPC** as its source. |
| `ssl-request` | Connected, but nothing answered: wrong port, or something that is not Postgres. |
| `auth` | `28P01`: wrong password. `28000`: no access rule matches the address. Other methods are listed in `authOffered`. The probe answers only SCRAM-SHA-256, and to anything else it sends no password. |
| `query` | The login worked and a query failed. |
| `hold` | The idle session was closed during the hold. |
| `durable-object` | The call to the Durable Object itself failed. |

## Remove it

```sh
pnpm exec wrangler delete       # the Worker, its secrets and its Durable Object
```

Then ask Infra to remove the access rule, if they added one for this probe.

## Local check

`pnpm smoke` (Docker, Node 24) runs the probe under `wrangler dev` against a
Postgres 17 of its own on `127.0.0.1:56145`. It runs with TLS on, then off, with
`cloudflare:sockets` standing in for the VPC binding (`local/worker.ts`). It checks
the gate, both routes, a 25 s hold, a session killed mid-hold, a wrong password, a
server that asks for a cleartext password, and a closed port. It then runs the wire
code from Node against two hostile fake servers: a malformed error, and an endless
stream of messages. Then it removes its container. It does not reach Cloudflare: a
VPC binding only runs there.
