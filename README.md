# dl.kai.am

Link shortener and file share on one Cloudflare Worker.

- `dl.kai.am/<slug>` redirects to a URL or serves a file from R2 (range requests work, so video seeks).
- `dl.kai.am/admin` is where you create links, upload files, and delete them. Cloudflare Access protects it. The Worker also checks the Access JWT and returns 403 if Access isn't configured.

Storage: KV `LINKS` maps slug → `{type, target, ...}`. R2 bucket `kai-am-files` holds files under `<slug>/<filename>`. Admin-page uploads go through the Worker in 50 MB multipart chunks, so the 100 MB request cap doesn't limit file size. ShareX uploads are a single request, so they're capped at 100 MB.

Limits: URLs ≤ 800 chars and filenames ≤ 255 bytes, because each KV record must fit in 1 KB of metadata. Public lookups are rate limited to 120/min per IP with the Workers rate limiting binding.

## Free tier

Fits Workers Free comfortably for a handful of people:

- **Workers:** 100k requests/day. Paths that can't be a slug get a 404 before any KV read or rate-limit call. Files send `cache-control: max-age=3600` so browsers reuse bytes instead of re-requesting.
- **KV:** 100k reads and 1k writes/day. A lookup is one read and a new link is one write. The admin list uses `list` metadata, so it doesn't need one read per link.
- **R2:** 10 GB storage, zero egress cost. Downloads stream from R2 and don't count toward the Worker's 10 ms CPU limit.

## Dev

```sh
npm i
cp .dev.vars.example .dev.vars   # skips the Access check locally
npm run dev                      # http://localhost:8787/admin
```

## Access setup (one time)

1. Zero Trust dashboard → Access → Applications → Add → Self-hosted. Domain `dl.kai.am`, path `admin`. Add an Allow policy for your email (one-time PIN or GitHub login).
2. Add the app's **AUD tag** and your team domain (`<team>.cloudflareaccess.com`) as the GitHub secrets `ACCESS_AUD` and `ACCESS_TEAM_DOMAIN`. The deploy job pushes them to the Worker as Worker secrets.

## Deploys

Pushes to `master` deploy through GitHub Actions after the checks pass. Repo secrets:

- `CLOUDFLARE_API_TOKEN`: from the **Edit Cloudflare Workers** token template
- `CLOUDFLARE_ACCOUNT_ID`
- `ACCESS_AUD`, `ACCESS_TEAM_DOMAIN`

`npm run deploy` still works locally and leaves the Worker secrets alone.

## ShareX

1. Zero Trust → Access → Service credentials → create a service token.
2. On the `dl.kai.am/admin` Access app, add a policy with action **Service Auth** that includes that token.
3. Put the token's client ID and secret into `sharex/dl.kai.am-files.sxcu` and `sharex/dl.kai.am-links.sxcu`, then double-click each file to import it. Don't commit the filled-in files.

Files go to `POST /admin/api/files?filename=…` as a raw body. Links go to `POST /admin/api/links` as JSON. Both return `{ slug, url }`.
