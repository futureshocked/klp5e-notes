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
  applyStep1Headers(response.headers);
  return response;
}
