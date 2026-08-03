# Running robby under systemd

`robby.service` runs the PDS as a system service. The optional
`cloudflared.service` puts a Cloudflare Tunnel in front of it, which is
the intended exposure model (TLS at the Cloudflare edge, no open inbound
ports, no reverse proxy on the box).

## 1. Install the binary

Either download a release tarball and:

```sh
sudo install -m 0755 robby /usr/local/bin/robby
```

or build from source:

```sh
git clone https://github.com/vrypan/robby
cd robby
make build
sudo install -m 0755 robby /usr/local/bin/robby
```

## 2. Create the service user

A system account with no login shell and no home directory:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin robby
```

## 3. Install the config

```sh
sudo mkdir -p /etc/robby
sudo -e /etc/robby/robby.toml
```

```toml
hostname     = "pds.example.com"
data_dir     = "/var/lib/robby"
listen       = "127.0.0.1:3000"
plc_url      = "https://plc.directory"
appview_url  = "https://api.bsky.app"
appview_did  = "did:web:api.bsky.app"
relays       = ["https://bsky.network"]
```

Two values matter to the unit file:

- `data_dir` **must** be `/var/lib/robby` — systemd creates and owns
  that path via `StateDirectory=robby`.
- `listen` should bind localhost when cloudflared runs on the same box;
  nothing else needs to reach the port directly.

Leave `jwt_secret` and `admin_password` unset — robby generates them on
first start and writes them back into the config. That write-back is why
the config must be owned by the service user:

```sh
sudo chown robby:robby /etc/robby/robby.toml
sudo chmod 0600 /etc/robby/robby.toml
```

## 4. Install and start the unit

```sh
sudo cp deploy/systemd/robby.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now robby.service
```

Check it:

```sh
systemctl status robby.service
curl -s http://127.0.0.1:3000/xrpc/_health
# {"version":"robby/v0.2.2"}
journalctl -u robby -f
```

After the first successful start, `/etc/robby/robby.toml` contains the
generated `jwt_secret` and `admin_password`. From then on robby never
writes to `/etc/robby` again, so you can tighten the sandbox by deleting
the `ReadWritePaths=/etc/robby` line from the unit (then
`daemon-reload` + `restart`). **Back that file up** — it now holds the
admin credential, and losing `jwt_secret` invalidates every session.

The admin CLI reads the same config, so admin commands run as the
service user:

```sh
sudo -u robby robby --config /etc/robby/robby.toml account list
```

## Upgrading

```sh
sudo install -m 0755 robby /usr/local/bin/robby
sudo systemctl restart robby.service
```

robby shuts down cleanly on SIGTERM (in-flight requests finish; SQLite
needs no recovery), so a restart is safe at any time. Firehose consumers
reconnect with their cursor and receive backfill.

## About the hardening

The unit runs with `ProtectSystem=strict`, an empty capability set and a
`@system-service` syscall filter. robby's writable world is exactly
`/var/lib/robby` (state) plus `/etc/robby` (first run only, see above).
If the service fails to start on an older or unusual kernel, remove
directives one at a time; `SystemCallFilter` is the usual culprit.
`systemd-analyze security robby.service` scores the result.

---

# Cloudflare Tunnel (optional)

One hostname is enough. Handles are verified with `_atproto.<handle>`
DNS TXT records (or served by robby at `/.well-known/atproto-did` for
domains pointed at it), so no wildcard hostname or certificate is
needed. WebSockets — the `subscribeRepos` firehose — work through the
tunnel; no extra configuration.

There are two ways to run cloudflared as a service. Both start from:

```sh
# Install cloudflared (Debian/Ubuntu; see Cloudflare's docs for others)
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install cloudflared
```

## Option A — dashboard-managed tunnel (simplest)

Create the tunnel in the Cloudflare dashboard (Zero Trust → Networks →
Tunnels), add a public hostname `pds.example.com` → service
`http://localhost:3000`, then install the connector with the token the
dashboard shows:

```sh
sudo cloudflared service install <token>
```

That command installs and enables Cloudflare's own systemd unit;
`deploy/systemd/cloudflared.service` is not needed. Ingress rules are
edited in the dashboard.

## Option B — locally-managed tunnel (config in git)

Configuration lives on the box instead of the dashboard:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared
cloudflared tunnel login                 # one-time; writes cert.pem
cloudflared tunnel create robby          # writes <TUNNEL_ID>.json credentials
cloudflared tunnel route dns robby pds.example.com

sudo mkdir -p /etc/cloudflared
sudo cp ~/.cloudflared/<TUNNEL_ID>.json /etc/cloudflared/
sudo -e /etc/cloudflared/config.yml
```

```yaml
tunnel: <TUNNEL_ID>
credentials-file: /etc/cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: pds.example.com
    service: http://localhost:3000
  - service: http_status:404
```

```sh
sudo chown -R cloudflared:cloudflared /etc/cloudflared
sudo chmod 0600 /etc/cloudflared/<TUNNEL_ID>.json
sudo cp deploy/systemd/cloudflared.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflared.service
```

Verify end to end:

```sh
curl -s https://pds.example.com/xrpc/_health
# {"version":"robby/v0.2.2"}
```

## Ordering

The two services are deliberately independent — neither unit declares a
dependency on the other. robby serves localhost happily with the tunnel
down, and cloudflared retries its origin, so start order does not
matter.
