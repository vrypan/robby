# Security remediation plans

Generated 2026-07-25 at commit e17e8d5. These plans supplement the existing
PLAN.md; do not rename or edit that product-design document.

| Plan | Title | Priority | Effort | Depends on | Status |
|---|---|---|---|---|---|
| 001 | Protect generated configuration secrets | P1 | S | — | DONE |
| 002 | Close the DID-resolution SSRF bypass | P1 | M | — | DONE |
| 003 | Scope, revoke, and atomically consume credentials | P1 | L | — | DONE |
| 004 | Prevent unauthenticated persistent state allocation | P1 | M | — | DONE |
| 005 | Bound inbound and outbound HTTP resource use | P1 | M | 002 | DONE |

Run plans in numerical order where practical. Plans 002 and 005 share
outbound-client code; complete 002 first so plan 005 can extend the hardened
client rather than create a parallel implementation.

## Accepted-risk items

- Plain HTTP at the application listener and plaintext private keys in SQLite
  are documented deployment decisions: Cloudflare Tunnel terminates TLS and
  the project explicitly accepts local key storage.
- Open CORS and a public subscribeRepos websocket are required for browser
  clients and the public firehose; no cookie credentials are enabled.
- Generic rate limiting is an explicit design trade-off for a small known-user
  PDS. The plans still add bounded resource handling at high-risk public endpoints.
