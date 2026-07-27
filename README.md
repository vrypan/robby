# robby

> [!CAUTION] 
> This pice of software is **EXPERIMENTAL** and in no way production-ready.
>

A lightweight AT Protocol Personal Data Server (PDS), built for a small
number of known users. Single static Go binary, SQLite storage, blobs on
disk. See [`plans/PLAN.md`](plans/PLAN.md) for the full design and build
plan.

**Status:** phases 1–5 implemented — identity/auth, repo core (records,
blobs), sync/firehose (`subscribeRepos`), app integration (service
proxying, app passwords), and account migration/lifecycle. Only OAuth
(phase 6, deferred) is not yet built.

## Requirements

- Go 1.26+
- A reachable [PLC directory](https://plc.directory) (the public one, or
  your own, for account creation and identity resolution)

## Install / build

```sh
git clone <this repo>
cd robby
go build -o robby ./cmd/robby
```

This produces a single `robby` binary that runs both the server and
the admin CLI.

## Configuration

robby reads a TOML config file (default path `robby.toml` in the
current directory, override with `--config`):

```toml
hostname     = "pds.example.com"
data_dir     = "/var/lib/robby"
listen       = ":3000"
plc_url      = "https://plc.directory"
appview_url  = "https://api.bsky.app"
appview_did  = "did:web:api.bsky.app"
relays       = ["https://bsky.network"]
```

`jwt_secret` and `admin_password` are generated automatically on first
run and written back into the config file if left blank — just don't
commit that file anywhere public. If it may have been exposed, rotate
both immediately; rotation invalidates all current JWTs. `data_dir` is
created automatically and holds:

```
data_dir/
  accounts.db          # accounts, sessions, firehose event log
  actors/<did>.db       # per-user repo (MST blocks, record index, blob meta)
  blobs/<did>/<cid>     # raw blob bytes
```

## Running the server

```sh
./robby --config robby.toml serve
```

This starts the HTTP server on `listen` (plain HTTP — put TLS at a
reverse proxy or tunnel in front of it; see `plans/PLAN.md` for the
intended Cloudflare Tunnel setup). It logs to stderr and shuts down
cleanly on SIGINT/SIGTERM.

A health check is available at `GET /xrpc/_health`.

## Managing accounts (admin CLI)

Admin commands talk to the **running server's** admin API over HTTP
(Basic auth, using `admin_password` from the config) — they never touch
the database files directly. Start `serve` first, then run these from
another terminal (same `--config`, so the CLI can find the server's
address and admin password):

```sh
# Create a new account. Generates a signing key + rotation key,
# registers a did:plc genesis operation, and creates an empty repo.
./robby --config robby.toml account create alice.pds.example.com
# (prompts for a password, or pass --password)

# List accounts
./robby --config robby.toml account list

# Change a password (also revokes that account's outstanding sessions)
./robby --config robby.toml account set-password <did>

# Deactivate an account
./robby --config robby.toml account deactivate <did>

# Take down an account (moderation action; blocks login entirely)
./robby --config robby.toml account takedown <did>

# Issue a one-time token authorizing identity.signPlcOperation or
# server.deleteAccount for an account — the admin-CLI-confirmation
# stand-in for email-gated confirmation flows. Share the printed token
# with the account owner out of band; it expires in 15 minutes.
./robby --config robby.toml account approve-plc-op <did>
./robby --config robby.toml account approve-delete <did>
```

There are no invite codes and no self-serve signup for brand-new
accounts — those are admin-created. Migrating an *existing* DID in from
another PDS is supported over XRPC (`server.createAccount` with a `did`
and a service-auth token proving control of it) — see below.

### Migrating an account in or out

Because service-auth verification, PLC identity resolution, and
`repo.importRepo`/`sync.getRepo` are all implemented, a real AT Protocol
client — `goat account migrate` — can move a DID onto or off this
server:

```sh
# On the OLD host, issue a token so the migration can update identity:
old-host$ robby --config old.toml account approve-plc-op <did>

# Then, authenticated against the OLD host:
goat account migrate --pds-host https://new.pds.example.com \
  --new-handle alice.new.pds.example.com \
  --new-password <new-password> \
  --plc-token <token from approve-plc-op>
```

This creates the account on the new host, imports the repo and blobs,
updates the DID's PLC document to point at the new host/keys,
deactivates the account on the old host, and activates it on the new
one — the whole flow verified end-to-end between two robby
instances.

### Handles

Each account's handle must resolve to its DID, either via a
`_atproto.<handle>` DNS TXT record (`did=<did>`) or via
`https://<handle>/.well-known/atproto-did`, which this server serves
itself (virtual-hosted by the `Host` header) for any handle whose
account lives on it.

## Using it as an AT Protocol client would

Once an account exists, any standard AT Protocol / Bluesky client
tooling can talk to it over XRPC. For example with
[`goat`](https://github.com/bluesky-social/goat)
(`go install github.com/bluesky-social/goat@latest`):

```sh
goat account login --pds-host https://pds.example.com \
  -u alice.pds.example.com -p <password>

goat record create post.json      # create a record
goat record list <did>            # list records
goat repo export <did>            # download a CAR file
goat firehose --relay-host wss://pds.example.com   # stream the firehose
```

The official Bluesky app should mostly work for reading (feeds,
profiles, notifications — proxied to the AppView) and for posting/
following/blob upload (served directly). Anything needing account
migration or OAuth-only login is not implemented yet.

### Service proxying & app passwords

Requests for NSIDs this server doesn't implement itself (`app.bsky.*`
reads, mainly) are forwarded to `appview_url`/`appview_did` from the
config, signed with a short-lived service-auth JWT for the calling
account. A client can redirect a request elsewhere with an
`atproto-proxy: <did>#<serviceId>` header — the target DID's document is
resolved to find that service's endpoint.

```sh
# Ask the PDS for a service-auth token to call another service directly
goat account service-auth --aud did:web:api.bsky.app

# Create/list/revoke app passwords, for logging in third-party apps
# without handing out the account's main password (no dedicated goat
# subcommand yet, so call the XRPC procedures directly)
goat xrpc procedure @pds com.atproto.server.createAppPassword name=my-app
goat xrpc query @pds com.atproto.server.listAppPasswords
goat xrpc procedure @pds com.atproto.server.revokeAppPassword name=my-app
```

## What's implemented (XRPC surface)

**Identity & auth**
`server.describeServer`, `server.createSession`, `refreshSession`,
`deleteSession`, `getSession`, `identity.resolveHandle`,
`/.well-known/atproto-did`, `server.getServiceAuth`,
`server.createAppPassword`, `listAppPasswords`, `revokeAppPassword`,
`identity.updateHandle`

**Migration & lifecycle**
`server.reserveSigningKey`, `createAccount` (migration-in),
`repo.importRepo`, `repo.listMissingBlobs`, `server.activateAccount`,
`deactivateAccount`, `deleteAccount`, `checkAccountStatus`,
`identity.getRecommendedDidCredentials`, `signPlcOperation`,
`submitPlcOperation`

**Repo (records & blobs)**
`repo.createRecord`, `putRecord`, `deleteRecord`, `applyWrites`,
`getRecord`, `listRecords`, `describeRepo`, `uploadBlob` — records are
validated against real `com.atproto.*`/`app.bsky.*` Lexicon schemas.

**Sync & firehose**
`sync.getRepo`, `getRepoStatus`, `getLatestCommit`, `getRecord`,
`getBlocks`, `listBlobs`, `getBlob`, `listRepos`, `subscribeRepos`
(websocket firehose with cursor backfill and live tail).

**App integration**
Everything else under `/xrpc/*` (mainly `app.bsky.*`) is service-proxied
to the configured AppView, or to an `atproto-proxy` header's target —
see below.

**Admin** (`net.vrypan.robby.admin.*`, HTTP Basic auth, not part of the
public AT Protocol lexicon)
`createAccount`, `listAccounts`, `setPassword`, `deactivateAccount`,
`takedownAccount`, `approveToken`.

## Not yet implemented

- OAuth authorization server — phase 6 (deferred).

## Known simplifications

- `sync.getRecord`/`getRepo` return the full block set rather than a
  minimal MST inclusion proof (indigo's `mst` package doesn't expose
  proof generation) — still valid, just non-minimal.
- `server.deleteAccount` doesn't purge the actor's repo DB or blob files
  on disk; it removes the account and its auth/token state from
  `accounts.db` only.

## Development

```sh
go build ./...
go vet ./...
gofmt -l .
```

There's no test suite yet; verification so far has been manual/CLI
(`goat`) driven — see commit history for what's been exercised.
