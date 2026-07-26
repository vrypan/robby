# Migrating a bsky.social account to robby

How to move an existing Bluesky account — `something.bsky.social` —
onto a self-hosted robby instance, with a new handle under your own
domain (`somethingelse.vrypan.net`).

This is the *migration-in* case. The README covers robby-to-robby
migration, which differs in one important way: there, the PLC signing
token comes from the old robby host via `account approve-plc-op`. When
migrating away from bsky.social the token is emailed to you by Bluesky
instead, so `approve-plc-op` plays no part in this flow.

## What actually moves

Your identity is the **DID** (`did:plc:…`), not the handle. Migration
keeps the DID and changes what it points at:

- the repo (all your posts, likes, follows) is exported from
  bsky.social and imported into robby,
- blobs (images, video) are re-uploaded to robby,
- the DID document is updated so its `atproto_pds` service endpoint
  names your PDS and its `alsoKnownAs` names the new handle,
- the account is activated on robby and deactivated on bsky.social.

Followers, follows, likes and post URIs all survive, because they
reference the DID. What does **not** move: direct messages (they live
on Bluesky's chat service, not in your repo) and the old handle, which
is released once you migrate.

## Prerequisites

- robby running and reachable over HTTPS at your PDS hostname
  (e.g. `https://pds.vrypan.net`).
- The **full account password** for the bsky.social account. App
  passwords cannot migrate — account creation and the PLC signature
  both require privileged auth.
- Control of DNS for the domain of the new handle.
- `goat` installed (the indigo CLI). It drives the whole migration.
- Access to the email address on the bsky.social account, to receive
  the PLC signing token.

> **Deploy a current robby build first.** Before commit `ed99cb9`,
> robby bumped an account's auth version on *every* status change,
> including activation — which invalidated the session driving the
> migration and broke it at the final step. Activation is deliberately
> non-revoking now (`store.ActivateAccount`). Make sure what is
> deployed includes that fix.

## Step 1 — Find the DID

```sh
goat account status -u something.bsky.social
```

or:

```sh
curl -s "https://bsky.social/xrpc/com.atproto.identity.resolveHandle\
?handle=something.bsky.social"
```

Note the `did:plc:…` value; the next step needs it.

## Step 2 — Publish the new handle in DNS

The new handle must resolve to that DID before the network will treat
it as valid. Add a TXT record on the parent domain:

```
_atproto.somethingelse    TXT    "did=did:plc:XXXXXXXX"
```

so that the full name is `_atproto.somethingelse.vrypan.net`. Confirm
it is live before continuing:

```sh
dig +short TXT _atproto.somethingelse.vrypan.net
# "did=did:plc:XXXXXXXX"
```

Do this *first*. If the record is missing when the migration completes,
the AppView caches a verification failure and the account shows
"Invalid Handle" until something forces a re-check (see
[Troubleshooting](#troubleshooting)).

Alternatively, robby serves `/.well-known/atproto-did` for handles
whose accounts it hosts, so pointing the handle's hostname at robby
also works. DNS TXT is simpler and does not require the bare hostname
to resolve anywhere.

## Step 3 — Run the migration

```sh
# Authenticate against the OLD host, with the real password
goat account login -u something.bsky.social -p '<password>'

# Ask bsky.social to email a PLC signing token
goat account plc request-token

# Migrate (the token arrives by email within a minute)
goat account migrate \
  --pds-host https://pds.vrypan.net \
  --new-handle somethingelse.vrypan.net \
  --new-password '<new password>' \
  --plc-token 'XXXXX-XXXXX'
```

`goat account migrate` performs the whole sequence: it creates the
account on robby (presenting a service-auth token that proves you
control the DID), exports and imports the repo, uploads missing blobs,
copies preferences, signs and submits the PLC operation, activates the
account on robby and deactivates it on bsky.social.

The PLC token is short-lived — request it immediately before running
the migration.

## Step 4 — Verify

```sh
# The DID document should now name your PDS and the new handle
goat account plc current

# Hosting status as seen from the network
goat account status

# robby's own view of the repo
curl -s "https://pds.vrypan.net/xrpc/com.atproto.sync.getRepoStatus\
?did=did:plc:XXXXXXXX"
```

Expect `"active": true` from robby, an `atproto_pds` service endpoint
of `https://pds.vrypan.net`, and `alsoKnownAs` of
`at://somethingelse.vrypan.net`.

## Step 5 — Make the network notice

```sh
# Ask the configured relays to crawl this PDS
robby --config ./robby.toml relay request-crawl
```

Note that `request-crawl` takes a *relay* URL (it defaults to the
relays in your config, e.g. `https://bsky.network`). Pointing it at
your own PDS returns `501 MethodNotImplemented` — a PDS does not
implement `requestCrawl`; relays do.

Then log in at bsky.app as `somethingelse.vrypan.net`. If handle
resolution has not caught up yet, use "set your hosting provider
manually" and enter `https://pds.vrypan.net`.

## Troubleshooting

### "Invalid Handle" badge, or login says the account was not found

The AppView cached a failed handle verification. Confirm DNS is
correct first:

```sh
dig +short TXT _atproto.somethingelse.vrypan.net
curl -s "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle\
?handle=somethingelse.vrypan.net"
```

If DNS is right but the AppView still reports `handle.invalid`, force a
re-resolution by re-emitting an identity event — a relay must be
crawling the PDS for this to reach the network:

```sh
robby --config ./robby.toml relay request-crawl
robby --config ./robby.toml account refresh-identity did:plc:XXXXXXXX
```

Re-running `goat account update-handle` with the same handle also works:
robby's `updateHandle` is idempotent for an account's own handle.

### Migration fails partway

The flow is resumable. Each phase is independently repeatable — the
account already exists, so re-running `goat account migrate` will fail
at creation. Finish the remaining phases manually using the sequence in
the appendix, starting from wherever it stopped.

### Blob upload fails on large media

robby caps a single blob at 100 MiB and a repo import at 500 MiB
(`maxBlobSize` in `internal/xrpc/repo.go`, `maxImportSize` in
`internal/xrpc/migration.go`). Raise them and rebuild if a genuinely
larger repo needs to move.

### "Failed to load preference" in Privacy and Security

The account is missing `app.bsky.notification.declaration/self`. A
migrated bsky.social account normally brings this record with it; if it
is absent, create it:

```sh
echo '{"$type":"app.bsky.notification.declaration",\
"allowSubscriptions":"followers"}' | goat record create --rkey self -
```

## Rolling back

Until you delete the old account, migration is reversible: the DID is
still yours and the PLC log is append-only. Migrating back means
running the same flow in the opposite direction, using robby's
`account approve-plc-op` to authorize the identity update.

Keep the bsky.social account **deactivated rather than deleted** until
the new host has been running to your satisfaction.

## Appendix — the manual XRPC sequence

What `goat account migrate` automates, for recovery or for
understanding the flow. `OLD` is `https://bsky.social`, `NEW` is your
robby host.

1. `NEW  com.atproto.server.reserveSigningKey` (optional; public) —
   reserves a stable signing key for the DID before the account exists.
2. `OLD  com.atproto.server.getServiceAuth` with `aud` = the new PDS's
   DID and `lxm=com.atproto.server.createAccount` — proves DID control.
3. `NEW  com.atproto.server.createAccount` with `did`, `handle`,
   `password`, and the service-auth token as bearer. Returns a session;
   the account starts **deactivated**.
4. `OLD  com.atproto.sync.getRepo?did=…` — download the repo CAR.
5. `NEW  com.atproto.repo.importRepo` — upload that CAR.
6. `NEW  com.atproto.repo.listMissingBlobs`, then for each CID:
   `OLD com.atproto.sync.getBlob` → `NEW com.atproto.repo.uploadBlob`.
7. `OLD  app.bsky.actor.getPreferences` →
   `NEW app.bsky.actor.putPreferences`.
8. `NEW  com.atproto.identity.getRecommendedDidCredentials` — the
   rotation keys, signing key, `alsoKnownAs` and service endpoint the
   new host wants published.
9. `OLD  com.atproto.identity.requestPlcOperationSignature` — emails
   the token.
10. `OLD  com.atproto.identity.signPlcOperation` with that token and
    the credentials from step 8 — returns a signed operation.
11. `NEW  com.atproto.identity.submitPlcOperation` — publishes it to
    the PLC directory. The DID now points at the new host.
12. `NEW  com.atproto.server.activateAccount`.
13. `OLD  com.atproto.server.deactivateAccount`.

Steps 5, 6 (`listMissingBlobs`) and 12 accept a migration session on a
deactivated account (`requireMigrationAccessToken`); the rest require a
privileged session on an **active** account — see the known limitation
below.

## Known limitation: blob upload during migration

`com.atproto.repo.uploadBlob` and `app.bsky.actor.putPreferences`
currently call `requireAccessToken`, which since the credential-scoping
work (commit `81f0ab1`) rejects any account that is not `active`. A
migrating account is `deactivated` from creation (step 3) until
activation (step 12), so **steps 6 and 7 will fail with 401 for as long
as that ordering holds**.

In practice this means a migration carrying media (any account with an
avatar, banner or image posts) will import the repo successfully but
fail to transfer blobs, leaving records that reference blobs the new
host does not have. `listMissingBlobs` will keep reporting them.

Workaround until this is fixed: complete the migration through step 12
so the account is active, then re-run the blob transfer (step 6) and
preferences copy (step 7) against the now-active account. Verify with:

```sh
curl -s "https://pds.vrypan.net/xrpc/com.atproto.repo.listMissingBlobs" \
  -H "Authorization: Bearer <access jwt>"
```

An empty `blobs` array means every referenced blob is present.

The proper fix is to let these two endpoints accept a migration session,
as `importRepo` and `listMissingBlobs` already do — plan 003 scoped the
deactivated-account exception to repo import, DID credentials and
activation, and did not account for blob upload.
