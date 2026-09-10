/**
 * Notes enrolment gate. Developed on the `notes-gate` branch and proven against
 * `notes-staging.techexplorations.com`; promoted to `main` (production) at step
 * B4 of coding_plans/notes-content-protection.md.
 *
 * Contract (see coding_plans/notes-content-protection.md, steps 2 A5 and A8):
 *  1. Verify the `te_notes` cookie HMAC in constant time, then check `exp`.
 *  2. On success call next() and re-apply step 1's headers on the response,
 *     because Pages Functions disable the `_headers` file for the whole project.
 *  3. On failure return 403 with a human-readable page, same headers applied.
 *  4. Skip the check for /robots.txt only. Assets are gated too.
 *  5. Honour the toolchain probe bypass (`X-TE-Notes-Probe`, step A8) ahead of
 *     the cookie path, so the deploy pipeline's cookie-less HEAD probes are not
 *     403ed. Verified here and nowhere else; disabled entirely when its secret
 *     is unset or empty.
 *  6. Stamp a successful cookie response with a per-reader licence line and an
 *     invisible `data-r` marker (step 3 of the same plan). The verified payload
 *     is the only place the edge learns who is reading, so this needs no new
 *     infrastructure. HTML responses only — figures and other binaries are
 *     passed through untouched, because HTMLRewriter cannot rewrite them.
 *  7. The probe bypass is honoured on HEAD only, and every use is logged (open
 *     items 5 and 6, closed with step 3). Rationale: a leaked probe secret is an
 *     unattributed key to the whole book, so it must not be able to download one
 *     and must not be usable invisibly.
 *
 * Step 1's four protections, re-applied here in code:
 *  - X-Robots-Tag: noindex, nofollow
 *  - Content-Security-Policy: frame-ancestors https://*.techexplorations.com https://techexplorations.com
 *  - Referrer-Policy: no-referrer
 *  - deletion of Access-Control-Allow-Origin (must stay absent, even with an
 *    explicit Origin header on the request)
 */

const COOKIE_NAME = "te_notes";
const SKIP_PATHS = new Set(["/robots.txt"]);

/**
 * Toolchain probe bypass header (step A8). Deliberately NOT the zone WAF's
 * `X-TE-Test` header: that one is matched by Cloudflare's zone rules against
 * `TE_CF_PROD_TOKEN`/`TE_CF_TEST_TOKEN`, and a single header cannot carry two
 * different secrets to two different verifiers. Two layers, two secrets, two
 * headers — neither substitutable for the other, so one leak cannot open both.
 */
const PROBE_HEADER_NAME = "X-TE-Notes-Probe";

const STEP1_HEADERS = {
  "X-Robots-Tag": "noindex, nofollow",
  "Content-Security-Policy":
    "frame-ancestors https://*.techexplorations.com https://techexplorations.com",
  "Referrer-Policy": "no-referrer",
};

function base64UrlToBytes(value) {
  const b64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Constant-time comparison; length mismatch returns false without leaking order. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Returns the decoded payload object, or null when the cookie is invalid/expired. */
async function verifyCookie(cookieValue, secret) {
  const dot = cookieValue.indexOf(".");
  if (dot <= 0 || dot === cookieValue.length - 1) return null;
  const payloadB64 = cookieValue.slice(0, dot);
  const signatureB64 = cookieValue.slice(dot + 1);

  let provided;
  try {
    provided = base64UrlToBytes(signatureB64);
  } catch {
    return null;
  }

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  // Signs the transmitted base64url payload string — byte-identical to what the
  // WordPress mu-plugin hashes, so no re-encoding rules can drift apart.
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(payloadB64))
  );
  if (!timingSafeEqual(expected, provided)) return null;

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
  } catch {
    return null;
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    typeof payload.exp !== "number" ||
    payload.exp <= Math.floor(Date.now() / 1000)
  ) {
    return null;
  }
  return payload;
}

function applyStep1Headers(headers) {
  for (const [name, value] of Object.entries(STEP1_HEADERS)) {
    headers.set(name, value);
  }
  headers.delete("Access-Control-Allow-Origin");
}

function gateResponse() {
  const body = [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Chapter locked</title></head>",
    '<body style="font-family:system-ui,sans-serif;padding:3rem;line-height:1.6;max-width:40rem;margin:auto">',
    "<h1>This chapter is part of the course</h1>",
    "<p>Open this chapter from your course at app.techexplorations.com</p>",
    "</body></html>",
  ].join("");
  const response = new Response(body, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
  applyStep1Headers(response.headers);
  return response;
}

/**
 * Step 3: per-reader watermark.
 *
 * Presentation normally belongs to the build — `TEMPLATE` in
 * `_toolchain/scripts/build-notes.py` carries a `.note-licence` rule with values
 * identical to WATERMARK_STYLE below. But every note bakes its CSS into an inline
 * `<style>` block (there is no shared `css/` directory to update), and Vol 2's
 * `make notes-sync` is blocked by the RENUMBER-2026-09-01 key collision, so the
 * already-deployed notes cannot all be rebuilt today. The middleware is therefore
 * self-sufficient via an inline `style` attribute and will agree with, rather than
 * fight, the class rule once notes are rebuilt.
 *
 * Two constraints from the plan, both honoured here:
 *  - the footer is appended to `body`, which lands it AFTER the closing
 *    `</div>` of `[data-lightbox-wrapper]`, so the planned language switcher
 *    (which swaps that wrapper's contents via fetch) cannot make it vanish;
 *  - the injected markup never contains the literal token that the deploy-time
 *    auto-height injector keys on, so `build-notes.py`'s hard-fail check stays
 *    satisfied and the height measurement is unaffected. The footer is part of
 *    the initial HTML, so the auto-height script measures it and the parent
 *    iframe simply grows to fit.
 */
const WATERMARK_CLASS = "note-licence";

const WATERMARK_STYLE = [
  "margin:3rem 0 0",
  "padding-top:0.9rem",
  "border-top:1px solid #e2e8f0",
  // Single quotes ONLY: this string is emitted inside a double-quoted style=""
  // attribute, so a double quote here would terminate the attribute early and
  // corrupt the markup. CSS accepts both quote styles, and the matching
  // `.note-licence` rule in build-notes.py uses single quotes to stay identical.
  "font-family:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif",
  "font-size:0.75rem",
  "line-height:1.5",
  "color:#64748b",
  "text-align:center",
].join(";");

/**
 * Cookie payload fields come from the WordPress user table and are inserted into
 * HTML, so they are escaped. A display name containing `<` or `"` would otherwise
 * break the note's markup or inject into it.
 */
function escapeHtml(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Cloudflare's Email Obfuscation rewrites any contiguous address it finds in a
 * response body — including one this Function just injected, because the
 * obfuscator runs downstream of Functions. Measured on staging 2026-09-10: the
 * watermark came back as
 *   Licensed to Ada Lovelace, <a href="/cdn-cgi/l/email-protection" class="__cf_email__" …
 * plus a de-obfuscation script, so with JavaScript disabled the reader would not
 * see their own email and the attribution the watermark exists to provide would be
 * degraded. Splitting the "@" into its own inline element renders identically in
 * every browser (a bare <span> is unstyled and inline) while presenting no
 * contiguous address for the obfuscator to match.
 */
function formatEmail(email) {
  const at = email.indexOf("@");
  if (at < 0) return escapeHtml(email);
  return (
    escapeHtml(email.slice(0, at)) + "<span>@</span>" + escapeHtml(email.slice(at + 1))
  );
}

function watermarkHtml(payload) {
  const name = escapeHtml(String(payload.name || "").trim());
  const email = String(payload.email || "").trim();
  const who = [name, email ? formatEmail(email) : ""]
    .filter(Boolean)
    .join(", ");
  return (
    `<div class="${WATERMARK_CLASS}" data-note-licence style="${WATERMARK_STYLE}">` +
    `Licensed to ${who || "a registered reader"}. Not for redistribution.</div>`
  );
}

/**
 * Stamp a verified reader's licence line onto an HTML response, and mark `body`
 * with `data-r="{uid}"` — an invisible per-reader marker that survives
 * view-source, print and browser "save as PDF", so a leaked copy names its source.
 *
 * Returns the response unchanged when it is not HTML (figures, CSS, anything
 * binary) or not a success, so assets cost no rewriting and a 404 page is not
 * decorated. Fails open on presentation only: if a note somehow had no `<body>`
 * the content is still served — and still gated.
 */
function applyWatermark(response, payload) {
  if (response.status < 200 || response.status >= 300) return response;
  const type = (response.headers.get("Content-Type") || "").toLowerCase();
  if (!type.includes("text/html")) return response;

  const uid = payload.uid;
  return new HTMLRewriter()
    .on("body", {
      element(body) {
        if (uid !== undefined && uid !== null && uid !== "") {
          body.setAttribute("data-r", escapeHtml(uid));
        }
        body.append(watermarkHtml(payload), { html: true });
      },
    })
    .transform(response);
}

function readCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);

  if (SKIP_PATHS.has(url.pathname)) {
    return next();
  }

  // Toolchain probe bypass (step A8), checked before the cookie path so a probe
  // never does HMAC work. `verify_notes_reachable()` HEADs every notes URL from
  // `requests`, which has no browser and therefore no cookie; without this the
  // gate would abort every future lesson-content apply. Unset or empty secret
  // disables the bypass entirely — the same fail-closed posture as the missing
  // TE_NOTES_SECRET case below. Compared byte-wise through the same
  // constant-time helper the cookie signature uses, never with ===.
  const probeSecret = env.TE_NOTES_PROBE_SECRET;
  const probeProvided = request.headers.get(PROBE_HEADER_NAME);
  if (probeSecret && probeProvided) {
    const probeEnc = new TextEncoder();
    if (
      timingSafeEqual(
        probeEnc.encode(probeSecret),
        probeEnc.encode(probeProvided)
      )
    ) {
      // Open item 6 (closed with step 3): HEAD only. Measured 2026-09-10 — this
      // origin answers HEAD with 200 for both notes and figures, and
      // `verify_notes_reachable()` HEADs first, falling back to GET only on
      // 405/501/403, so that fallback never fires and the toolchain needs no
      // change. A leaked probe secret can therefore establish that a slug exists
      // and how fast it answers, but cannot download a single byte of the book.
      if (request.method !== "HEAD") {
        return gateResponse();
      }
      // Open item 5 (closed with step 3): this is the highest-value secret in
      // the inventory — permanent and unattributed — so every accepted use is
      // logged. The record carries no secret value and no cookie.
      console.log(
        JSON.stringify({
          event: "notes_probe_bypass",
          method: request.method,
          host: url.hostname,
          path: url.pathname,
          country: request.cf ? request.cf.country : null,
          colo: request.cf ? request.cf.colo : null,
          ray: request.headers.get("CF-Ray"),
          ua: request.headers.get("User-Agent"),
        })
      );
      const probeResponse = await next();
      applyStep1Headers(probeResponse.headers);
      return probeResponse;
    }
  }

  const secret = env.TE_NOTES_SECRET;
  const cookieValue = readCookie(request.headers.get("Cookie"), COOKIE_NAME);

  // Missing secret (misconfigured deployment) fails closed: everything 403s
  // rather than silently serving the book unauthenticated.
  const payload =
    secret && cookieValue ? await verifyCookie(cookieValue, secret) : null;

  if (!payload) {
    return gateResponse();
  }

  const response = await next();
  // Step 3: stamp the reader first — HTMLRewriter returns a NEW Response, so the
  // step-1 headers must be applied to the stamped one or they would be lost.
  const stamped = applyWatermark(response, payload);
  applyStep1Headers(stamped.headers);
  return stamped;
}
