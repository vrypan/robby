# Posting blog articles to atproto from a static site generator

How a static site generator can emit ready-to-publish atproto records
at build time — one JSON file per article, with a link card, text and
image — and how to publish them with `goat`.

The build stays offline and reproducible. Publishing is a separate,
idempotent step: re-running it never creates duplicate posts.

## Why a static build can emit a complete record

Two values that look like they need a server are in fact pure functions
of data the generator already has:

**The record key (TID).** An atproto record key for a post is a TID: 53
bits of microsecond timestamp plus a 10-bit clock ID. Derive the
timestamp from the article's publication date and the clock ID from a
hash of its permalink, and the same article always yields the same
record key — on any machine, in any build.

**The image reference (blob CID).** Blob refs are content-addressed:
CIDv1, raw codec, sha2-256. The CID is a hash of the image bytes, so the
generator can compute it without uploading anything.

Together these mean the generator can write a finished record — image
reference included — with no network access at all. Publishing is then
just "upload the bytes, write the record".

## The record

One file per article, e.g. `public/atproto/<tid>.json`:

```json
{
  "$type": "app.bsky.feed.post",
  "text": "New post: Migrating a Bluesky account to a self-hosted PDS",
  "createdAt": "2026-07-20T09:30:00Z",
  "langs": ["en"],
  "embed": {
    "$type": "app.bsky.embed.external",
    "external": {
      "uri": "https://blog.vrypan.net/some-post",
      "title": "Migrating a Bluesky account to a self-hosted PDS",
      "description": "What actually moves, and what breaks.",
      "thumb": {
        "$type": "blob",
        "ref": { "$link": "bafkreic5xk34r45ytz43vgbtrcusj7g3tla…" },
        "mimeType": "image/jpeg",
        "size": 84213
      }
    }
  }
}
```

`text` and `createdAt` are required on the post; `uri`, `title` and
`description` are required on the external embed. `thumb` is optional —
omit it and the card renders without an image.

## Build step 1 — the record key

```python
import hashlib, datetime

ALPHA = "234567abcdefghijklmnopqrstuvwxyz"   # base32-sortable

def tid(published_iso: str, permalink: str) -> str:
    """Deterministic TID: publication time + hash of the permalink."""
    dt = datetime.datetime.fromisoformat(
        published_iso.replace("Z", "+00:00"))
    micros = int(dt.timestamp() * 1_000_000)
    clock = int.from_bytes(
        hashlib.sha256(permalink.encode()).digest()[:2], "big") & 0x3FF
    v = ((micros & 0x1F_FFFF_FFFF_FFFF) << 10) | clock
    v &= 0x7FFF_FFFF_FFFF_FFFF
    out = []
    for _ in range(13):
        out.append(ALPHA[v & 0x1F])
        v >>= 5
    return "".join(reversed(out))
```

```python
>>> tid("2026-07-20T09:30:00Z", "https://blog.vrypan.net/some-post")
'3mr2yahvpk2cf'
```

This matches `goat syntax tid generate`'s encoding exactly — the TID
parses back to the publication timestamp, so posts sort in feeds by
when the article was published rather than when the script ran.

## Build step 2 — the image reference

```python
import hashlib, base64, os, mimetypes

def blob_ref(path: str) -> dict:
    """Content-addressed blob ref, computed without uploading."""
    data = open(path, "rb").read()
    cid = bytes([0x01, 0x55, 0x12, 0x20]) + hashlib.sha256(data).digest()
    link = "b" + base64.b32encode(cid).decode().lower().rstrip("=")
    return {
        "$type": "blob",
        "ref": {"$link": link},
        "mimeType": mimetypes.guess_type(path)[0] or "image/jpeg",
        "size": len(data),
    }
```

The four prefix bytes are CIDv1 (`0x01`), raw codec (`0x55`), sha2-256
(`0x12`) and digest length 32 (`0x20`). This produces byte-identical
output to the PDS's own blob hashing, so the ref you compute at build
time is the ref the upload will return.

**The bytes must still be uploaded.** Computing the CID does not put the
image on the PDS — see the publish step. A record referencing a blob the
host does not have will show up in `com.atproto.repo.listMissingBlobs`
and the card will render without its image.

Keep thumbnails under **1,000,000 bytes** — the lexicon's `maxSize` for
`external.thumb`. Resize at build time; a full-size hero image will be
rejected.

## Build step 3 — emit the records

```python
import json, pathlib

def emit(article, outdir="public/atproto"):
    key = tid(article["published"], article["url"])
    external = {
        "uri": article["url"],
        "title": article["title"][:300],
        "description": article["summary"][:1000],
    }
    if article.get("image"):
        external["thumb"] = blob_ref(article["image"])

    record = {
        "$type": "app.bsky.feed.post",
        "text": article["title"][:300],
        "createdAt": article["published"],
        "langs": ["en"],
        "embed": {
            "$type": "app.bsky.embed.external",
            "external": external,
        },
    }
    pathlib.Path(outdir).mkdir(parents=True, exist_ok=True)
    with open(f"{outdir}/{key}.json", "w") as f:
        json.dump(record, f, indent=2)

    # Drop a sidecar naming the image to upload, so the publish step
    # needs no manifest of its own.
    if article.get("image"):
        with open(f"{outdir}/{key}.image", "w") as f:
            f.write(article["image"])
    return key
```

Naming each file after its TID means the publish step needs no manifest:
the filename *is* the record key.

Any generator can do this — Hugo, Zola, Jekyll, Eleventy — as long as it
can run a script over its content and write files into the output
directory. The only inputs are title, permalink, summary, publication
date and an image path.

## Publish

Log in once. An app password is sufficient — ordinary repo writes do not
need a privileged session:

```sh
goat account login -u robby.vrypan.net -p '<app-password>'
```

Then, for each generated record:

```sh
#!/bin/sh
# publish.sh — upload images, then write records. Safe to re-run.
set -eu

for f in public/atproto/*.json; do
  rkey=$(basename "$f" .json)

  # Upload the thumbnail if the record references one. The CID is
  # already in the record, so the upload result needs no wiring in.
  img="public/atproto/$rkey.image"
  if [ -f "$img" ]; then
    goat blob upload "$(cat "$img")" >/dev/null
  fi

  # putRecord: creates on first run, overwrites identically after that
  goat record update --rkey "$rkey" "$f"
done
```

`goat record update` calls `com.atproto.repo.putRecord`, which creates
the record if it does not exist and replaces it if it does. That is what
makes the script safe to run on every deploy: an article that was
already posted is rewritten with identical content rather than posted
again.

## Why re-running is safe

The record key is derived from the article, not from when the script
ran. So:

- publishing the same article twice writes the same key twice — one
  post, not two;
- a build that dies partway can simply be re-run;
- a post edited in the source regenerates the same key and updates in
  place;
- uploading a blob that already exists is a no-op, because the CID is
  the same.

The one thing that breaks this: **changing an article's publication
date**. The date feeds the TID, so a changed date produces a new key and
therefore a second post. Treat `published` as immutable once an article
has shipped; use a separate `updated` field for edits.

## Constraints worth building around

| Field | Limit |
|---|---|
| `text` | 300 graphemes / 3000 bytes |
| `external.thumb` | 1,000,000 bytes, `image/*` |
| `external` | `uri`, `title`, `description` all required |
| record key | must be a TID for `app.bsky.feed.post` |
| `createdAt` | required, RFC 3339 |

Truncate `text` on a word boundary rather than mid-word. Note that the
limit is 300 *graphemes*, not bytes or runes — emoji and combining
characters count as one each, so a naive `[:300]` on a Python string is
close enough for ASCII but will under-count for other scripts.

## Clickable links in the post text

The link card is clickable on its own. If you also want a URL inside
`text` to be a link, add a facet with byte offsets covering exactly the
URL substring:

```json
"facets": [{
  "index": { "byteStart": 10, "byteEnd": 43 },
  "features": [{
    "$type": "app.bsky.richtext.facet#link",
    "uri": "https://blog.vrypan.net/some-post"
  }]
}]
```

Offsets are byte positions in the UTF-8 encoding of `text`, not
character positions — compute them with `text.encode().index(url)`.

## Verify

```sh
# List what is actually in the repo
goat record list -c app.bsky.feed.post

# Fetch one back
goat record get app.bsky.feed.post 3mr2yahvpk2cf

# Confirm no record references a blob the host does not have
curl -s https://pds.vrypan.net/xrpc/com.atproto.repo.listMissingBlobs \
  -H "Authorization: Bearer <access jwt>"
```

An empty `blobs` array from `listMissingBlobs` means every referenced
image was uploaded successfully.
