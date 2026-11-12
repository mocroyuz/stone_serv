// Tests de bout en bout : vrai serveur + faux Supabase (HTTP local).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const SERVER_JS = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "server.js");
const FACTOR = { id: "11111111-1111-4111-8111-111111111111", factor_type: "totp", status: "verified" };
const USERS = {
  mfa: { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", email: "mfa@example.com", factors: [FACTOR] },
  plain: { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", email: "plain@example.com", factors: [] },
};
const SID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

const jwt = (user, sessionId, aal) => {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b({ alg: "none" })}.${b({ sub: user.id, session_id: sessionId, aal })}.sig`;
};

const sessions = []; // lignes de mfa_verified_sessions
let fake, fakePort, proc, base, logs = "";

function startFake() {
  return new Promise((resolve) => {
    fake = createServer((req, res) => {
      const url = new URL(req.url, "http://x");
      const json = (status, body) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      };
      req.resume();
      req.on("end", () => {
        if (url.pathname === "/auth/v1/user") {
          const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
          let sub = null;
          try {
            sub = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).sub;
          } catch {}
          const user = Object.values(USERS).find((u) => u.id === sub);
          if (!user) return json(401, { msg: "invalid" });
          return json(200, { ...user, aud: "authenticated", role: "authenticated", app_metadata: {}, user_metadata: {}, created_at: "2024-01-01T00:00:00Z" });
        }
        if (url.pathname === "/rest/v1/mfa_verified_sessions") {
          if (req.method === "DELETE") return json(204, {});
          if (req.method === "GET") {
            const q = (k) => (url.searchParams.get(k) || "").replace(/^(eq|gt)\./, "");
            const gt = url.searchParams.get("verified_at")?.replace(/^gt\./, "");
            const rows = sessions.filter(
              (r) => r.user_id === q("user_id") && r.session_id === q("session_id") && (!gt || r.verified_at > gt)
            );
            return json(200, rows.map((r) => ({ session_id: r.session_id })));
          }
        }
        json(404, { message: "not found" });
      });
    });
    fake.listen(0, "127.0.0.1", () => {
      fakePort = fake.address().port;
      resolve();
    });
  });
}

before(async () => {
  await startFake();
  const port = 39000 + Math.floor(Math.random() * 500);
  base = `http://127.0.0.1:${port}`;
  proc = spawn(process.execPath, [SERVER_JS], {
    env: {
      PATH: process.env.PATH,
      PORT: String(port),
      SUPABASE_URL: `http://127.0.0.1:${fakePort}`,
      SUPABASE_ANON_KEY: "anon",
      SUPABASE_SERVICE_ROLE_KEY: "service-role-key-for-tests-0123456789",
      MAX_POST_UPLOAD_TOTAL_MB: "1",
    },
  });
  proc.stdout.on("data", (d) => (logs += d));
  proc.stderr.on("data", (d) => (logs += d));
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not start:\n" + logs);
});

after(() => {
  if (process.env.DEBUG_LOGS) console.log(logs.slice(-3000));
  proc?.kill();
  fake?.close();
});

const call = (p, token, init = {}) =>
  fetch(`${base}${p}`, { ...init, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init.headers || {}) } });
const codeOf = async (r) => (await r.json().catch(() => ({}))).code;

test("MFA gate: AAL1 session of an MFA user is blocked on normal routes", async () => {
  const t = jwt(USERS.mfa, SID(1), "aal1");
  const r = await call("/api/tags", t);
  assert.equal(r.status, 403);
  assert.equal(await codeOf(r), "MFA_REQUIRED");
});

test("MFA gate: challenge routes stay reachable while pending", async () => {
  const t = jwt(USERS.mfa, SID(2), "aal1");
  const status = await call("/api/auth/mfa/status", t);
  assert.equal(status.status, 200);
  assert.equal((await status.json()).requires_challenge, true);
  assert.notEqual(await codeOf(await call("/api/mfa/factors", t)), "MFA_REQUIRED");
  assert.notEqual(await codeOf(await call("/api/user/profile", t)), "MFA_REQUIRED");
  const verify = await call("/api/mfa/verify", t, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: "12" }) });
  assert.equal(verify.status, 400); // atteint le handler (code invalide), pas la porte
});

test("MFA gate: AAL2 token and users without MFA pass", async () => {
  assert.notEqual(await codeOf(await call("/api/tags", jwt(USERS.mfa, SID(3), "aal2"))), "MFA_REQUIRED");
  assert.notEqual(await codeOf(await call("/api/tags", jwt(USERS.plain, SID(4), "aal1"))), "MFA_REQUIRED");
});

test("MFA gate: unauthenticated and invalid tokens still get 401", async () => {
  assert.equal((await call("/api/tags")).status, 401);
  assert.equal((await call("/api/tags", "garbage")).status, 401);
});

test("MFA gate: verified session unlocks API; step-up expires after 15 min; gate after 30 days", async () => {
  const mk = (n, ageMs) => {
    sessions.push({ user_id: USERS.mfa.id, session_id: SID(n), verified_at: new Date(Date.now() - ageMs).toISOString() });
    return jwt(USERS.mfa, SID(n), "aal1");
  };
  const fresh = mk(10, 60_000);
  assert.notEqual(await codeOf(await call("/api/tags", fresh)), "MFA_REQUIRED");
  assert.equal((await (await call("/api/auth/mfa/status", fresh)).json()).requires_challenge, false);

  const hourOld = mk(11, 3_600_000);
  assert.notEqual(await codeOf(await call("/api/tags", hourOld)), "MFA_REQUIRED");
  assert.equal((await (await call("/api/auth/mfa/status", hourOld)).json()).requires_challenge, true);
  const sensitive = await call("/api/mfa/recovery-codes", hourOld, { method: "POST" });
  assert.equal(sensitive.status, 403);
  assert.equal(await codeOf(sensitive), "MFA_REQUIRED");

  const ancient = mk(12, 31 * 86_400_000);
  assert.equal(await codeOf(await call("/api/tags", ancient)), "MFA_REQUIRED");

  // une vérification d'une autre session ne sert à rien
  assert.equal(await codeOf(await call("/api/tags", jwt(USERS.mfa, SID(13), "aal1"))), "MFA_REQUIRED");
});

test("CORS: exact allow-list only (no Vercel wildcard)", async () => {
  const ok = await fetch(`${base}/api/health`, { headers: { Origin: "https://stone-prod.vercel.app" } });
  assert.equal(ok.headers.get("access-control-allow-origin"), "https://stone-prod.vercel.app");
  for (const origin of [
    "https://stone-prod-abc123-xsdevs-projects.vercel.app",
    "https://stone-prod-xsdevs-projects.vercel.app",
    "https://evil.example",
  ]) {
    const r = await fetch(`${base}/api/health`, { headers: { Origin: origin } });
    assert.equal(r.headers.get("access-control-allow-origin"), null, origin);
  }
});

function multipart(parts) {
  const boundary = "----stonetest" + Math.random().toString(16).slice(2);
  const chunks = [];
  for (const p of parts) {
    const head =
      `--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"` +
      (p.filename ? `; filename="${p.filename}"` : "") +
      "\r\n" + (p.type ? `Content-Type: ${p.type}\r\n` : "") + "\r\n";
    chunks.push(Buffer.from(head), Buffer.isBuffer(p.body) ? p.body : Buffer.from(p.body), Buffer.from("\r\n"));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return { boundary, body: Buffer.concat(chunks) };
}
const postsToken = () => jwt(USERS.plain, SID(20), "aal1");
const DATA = { name: "data", body: JSON.stringify({ networks: ["x"], scheduleMode: "now" }) };

test("Uploads: chunked body without Content-Length is capped while streaming", async () => {
  const big = Buffer.alloc(6 * 1024 * 1024, 1); // cap de test = 1 Mo (+2 Mo)
  const { boundary, body } = multipart([DATA, { name: "media", filename: "a.mp4", type: "video/mp4", body: big }]);
  const { request } = await import("node:http");
  const status = await new Promise((resolve, reject) => {
    const req = request(
      `${base}/api/posts`,
      { method: "POST", headers: { Authorization: `Bearer ${postsToken()}`, "Content-Type": `multipart/form-data; boundary=${boundary}`, "Transfer-Encoding": "chunked" } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); }
    );
    req.on("error", reject);
    for (let i = 0; i < body.length; i += 65536) req.write(body.subarray(i, i + 65536));
    req.end();
  });
  assert.equal(status, 413);
});

for (const [type, name, content] of [
  ["text/html", "x.html", "<html><script>alert(1)</script></html>"],
  ["image/svg+xml", "x.svg", "<svg xmlns='http://www.w3.org/2000/svg'></svg>"],
  ["image/png", "x.png", "<html><script>alert(1)</script></html>"],
]) {
  test(`Post media: rejects ${type} ${content.slice(0, 6)}`, async () => {
    const { boundary, body } = multipart([DATA, { name: "media", filename: name, type, body: content }]);
    const r = await call("/api/posts", postsToken(), { method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` }, body });
    assert.equal(r.status, 400);
    assert.equal(await codeOf(r), "UNSUPPORTED_MEDIA_TYPE");
  });
}

test("Post media: a real image passes validation", async () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64)]);
  const { boundary, body } = multipart([DATA, { name: "media", filename: "a.png", type: "image/png", body: png }]);
  const r = await call("/api/posts", postsToken(), { method: "POST", headers: { "Content-Type": `multipart/form-data; boundary=${boundary}` }, body });
  assert.notEqual(await codeOf(r), "UNSUPPORTED_MEDIA_TYPE");
});

test("Logs: query strings never reach the logs", async () => {
  await call("/api/health?access_token=SECRETVALUE123&code=ABC", null);
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(logs.includes("/api/health"));
  assert.ok(!logs.includes("SECRETVALUE123"));
});
