# dl.kai.am

Link shortener and file share on one Cloudflare Worker.

- `dl.kai.am/<slug>` redirects to a URL or serves a file from R2 (range requests work, so video seeks).
- `dl.kai.am/admin` is where you create links, upload files, and delete them. Cloudflare Access protects it. The Worker also checks the Access JWT and returns 403 if Access isn't configured.

Storage: KV `LINKS` maps slug → `{type, target, ...}`. R2 bucket `kai-am-files` holds files under `<slug>/<filename>`. Uploads go through the Worker in 50 MB multipart chunks, so the 100 MB request cap doesn't limit file size.

## Dev

```sh
npm i
cp .dev.vars.example .dev.vars   # skips the Access check locally
npm run dev                      # http://localhost:8787/admin
```

## Access setup (one time)

1. Zero Trust dashboard → Access → Applications → Add → Self-hosted. Domain `dl.kai.am`, path `admin`. Add an Allow policy for your email (one-time PIN or GitHub login).
2. Copy the application's **AUD tag** into `ACCESS_AUD` in `wrangler.jsonc`, and your team domain (`<team>.cloudflareaccess.com`) into `ACCESS_TEAM_DOMAIN`.
3. `npm run deploy`.
