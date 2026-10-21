import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import adminHtml from "./admin.html";

type Link =
  | { type: "url"; target: string; created: number }
  | { type: "file"; target: string; filename: string; size: number; created: number };

type Bindings = Env & { DEV_NO_AUTH?: string };

const SLUG = /^[A-Za-z0-9_-]{1,64}$/;
const RESERVED: Record<string, true> = { admin: true, "favicon.ico": true, "robots.txt": true };
const INLINE_TYPE = /^(image\/(png|jpeg|gif|webp|avif)|video\/[\w.+-]+|audio\/[\w.+-]+|application\/pdf|text\/plain)(;|$)/i;

const json = (data: unknown, status = 200) => Response.json(data, { status });
const bad = (msg: string, status = 400) => json({ error: msg }, status);

function randomSlug(len = 7) {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

async function pickSlug(env: Bindings, wanted: unknown): Promise<string | Response> {
  if (wanted) {
    if (typeof wanted !== "string" || !SLUG.test(wanted) || RESERVED[wanted]) return bad("invalid slug");
    if (await env.LINKS.get(wanted)) return bad("slug taken", 409);
    return wanted;
  }
  for (;;) {
    const s = randomSlug();
    if (!(await env.LINKS.get(s))) return s;
  }
}

const saveLink = (env: Bindings, slug: string, link: Link) =>
  env.LINKS.put(slug, JSON.stringify(link), { metadata: link });

let jwks: JWTVerifyGetKey | undefined;

// Access already blocks unauthenticated requests at the edge; this guards against misconfiguration.
async function authorized(req: Request, env: Bindings) {
  if (env.DEV_NO_AUTH === "1") return true;
  const token = req.headers.get("cf-access-jwt-assertion");
  if (!token || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return false;
  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  jwks ??= createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  try {
    await jwtVerify(token, jwks, { issuer, audience: env.ACCESS_AUD });
    return true;
  } catch {
    return false;
  }
}

async function admin(req: Request, env: Bindings, parts: string[]): Promise<Response> {
  const [, api, resource, id, action] = parts;
  if (!api) return new Response(adminHtml, { headers: { "content-type": "text/html; charset=utf-8" } });
  if (api !== "api") return bad("not found", 404);
  const m = req.method;

  if (resource === "links" && !id && m === "GET") {
    const links = [];
    let cursor: string | undefined;
    do {
      const page = await env.LINKS.list<Link>({ cursor });
      for (const k of page.keys) links.push({ slug: k.name, ...k.metadata });
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return json(links);
  }

  if (resource === "links" && !id && m === "POST") {
    const body = await req.json<{ url?: string; slug?: string }>();
    let url: URL;
    try {
      url = new URL(body.url ?? "");
    } catch {
      return bad("invalid url");
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") return bad("invalid url");
    const slug = await pickSlug(env, body.slug);
    if (slug instanceof Response) return slug;
    await saveLink(env, slug, { type: "url", target: url.href, created: Date.now() });
    return json({ slug });
  }

  if (resource === "links" && id && m === "DELETE") {
    const link = await env.LINKS.get<Link>(id, "json");
    if (!link) return bad("not found", 404);
    if (link.type === "file") await env.FILES.delete(link.target);
    await env.LINKS.delete(id);
    return json({ ok: true });
  }

  // Multipart upload through the Worker: each part stays under the 100 MB request body cap.
  if (resource === "uploads" && !id && m === "POST") {
    const body = await req.json<{ filename?: string; contentType?: string; slug?: string }>();
    const filename = body.filename?.replace(/[/\\]/g, "_").trim();
    if (!filename) return bad("missing filename");
    const slug = await pickSlug(env, body.slug);
    if (slug instanceof Response) return slug;
    const key = `${slug}/${filename}`;
    const upload = await env.FILES.createMultipartUpload(key, {
      httpMetadata: { contentType: body.contentType || "application/octet-stream" },
    });
    return json({ slug, key, uploadId: upload.uploadId });
  }

  if (resource === "uploads" && id) {
    const key = new URL(req.url).searchParams.get("key");
    if (!key) return bad("missing key");
    const upload = env.FILES.resumeMultipartUpload(key, id);

    if (m === "PUT" && action) {
      const n = Number(action);
      if (!Number.isInteger(n) || n < 1 || n > 10000 || !req.body) return bad("invalid part");
      return json(await upload.uploadPart(n, req.body));
    }
    if (m === "POST" && action === "complete") {
      const body = await req.json<{ parts: R2UploadedPart[] }>();
      const slug = key.slice(0, key.indexOf("/"));
      if (!SLUG.test(slug) || RESERVED[slug]) return bad("invalid key");
      const obj = await upload.complete(body.parts);
      const filename = key.slice(slug.length + 1);
      await saveLink(env, slug, { type: "file", target: key, filename, size: obj.size, created: Date.now() });
      return json({ slug });
    }
    if (m === "DELETE") {
      await upload.abort();
      return json({ ok: true });
    }
  }

  return bad("not found", 404);
}

async function serveFile(req: Request, env: Bindings, link: Extract<Link, { type: "file" }>) {
  const obj = await env.FILES.get(link.target, { range: req.headers, onlyIf: req.headers });
  if (!obj) return new Response("not found", { status: 404 });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  headers.set("accept-ranges", "bytes");
  // Files share an origin with /admin: only render known-inert types, download everything else, never sniff.
  const type = headers.get("content-type") ?? "";
  const inline = INLINE_TYPE.test(type);
  headers.set("content-disposition", `${inline ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(link.filename)}`);
  headers.set("x-content-type-options", "nosniff");
  if (type !== "application/pdf") headers.set("content-security-policy", "sandbox");
  if (!("body" in obj)) return new Response(null, { status: 304, headers });
  const r = obj.range as { offset?: number; length?: number; suffix?: number } | undefined;
  if (req.headers.has("range") && r) {
    const start = r.suffix !== undefined ? obj.size - r.suffix : (r.offset ?? 0);
    const end = r.length !== undefined ? start + r.length - 1 : obj.size - 1;
    headers.set("content-range", `bytes ${start}-${end}/${obj.size}`);
    return new Response(req.method === "HEAD" ? null : obj.body, { status: 206, headers });
  }
  headers.set("content-length", String(obj.size));
  return new Response(req.method === "HEAD" ? null : obj.body, { headers });
}

export default {
  async fetch(req, env) {
    const parts = new URL(req.url).pathname.split("/").filter(Boolean).map(decodeURIComponent);

    if (parts[0] === "admin") {
      // Blocks cross-site form/no-cors POSTs riding the Access cookie.
      const site = req.headers.get("sec-fetch-site");
      if (req.method !== "GET" && site && site !== "same-origin") return new Response("forbidden", { status: 403 });
      if (!(await authorized(req, env))) return new Response("forbidden", { status: 403 });
      return admin(req, env, parts);
    }

    if (req.method !== "GET" && req.method !== "HEAD") return new Response("method not allowed", { status: 405 });
    if (parts.length === 0) return new Response("dl.kai.am\n");
    if (parts.length !== 1) return new Response("not found", { status: 404 });

    const link = await env.LINKS.get<Link>(parts[0], "json");
    if (!link) return new Response("not found", { status: 404 });
    if (link.type === "url") return Response.redirect(link.target, 302);
    return serveFile(req, env, link);
  },
} satisfies ExportedHandler<Bindings>;
