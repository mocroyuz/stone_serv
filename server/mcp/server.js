import http from "node:http";
import { createClient } from "@supabase/supabase-js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = Number(process.env.PORT || process.env.MCP_PORT || 3001);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error("MCP requires SUPABASE_URL and SUPABASE_ANON_KEY");
}

function supabaseForToken(token) { return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false }, global: { headers: { Authorization: "Bearer " + token } } }); }
const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const allowedTables = {
  accounts: ["instagram_accounts", "tiktok_accounts", "youtube_accounts", "pinterest_accounts", "threads_accounts"],
};

function json(res, status, data) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(data));
}
async function authenticate(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ") || header.length > 8192) return null;
  const token = header.slice(7).trim();
  if (!token) return null;
  const { data, error } = await authClient.auth.getUser(token);
  if (error || !data?.user?.id) return null;
  return { user: data.user, token };
}
const SECRET_FIELD = /token|secret|password|credential|key|authorization|cookie|session/i;
function sanitize(value) { if (Array.isArray(value)) return value.map(sanitize); if (!value || typeof value !== "object") return value; const out = {}; for (const [key, val] of Object.entries(value)) { if (SECRET_FIELD.test(key)) continue; out[key] = sanitize(val); } return out; }
function createMcp(userId, token) { const userSupabase = supabaseForToken(token);
  const server = new McpServer({ name: "Stone", version: "0.1.0" });
  server.registerTool("stone_list_posts", {
    description: "List the authenticated user's Stone posts. Supports filtering by status and date range.",
    inputSchema: {
      status: z.enum(["draft", "scheduled", "published", "failed"]).optional(),
      limit: z.number().int().min(1).max(100).default(25),
    },
  }, async ({ status, limit }) => {
    let q = userSupabase.from("scheduled_posts").select("*").eq("user_id", userId).order("created_at", { ascending: false }).limit(limit);
    if (status) q = q.eq("status", status);
    const { data, error } = await q;
    if (error) return { isError: true, content: [{ type: "text", text: "Stone could not retrieve posts. " + "Please verify your permissions and try again." }] };
    return { structuredContent: { posts: sanitize(data || []) }, content: [{ type: "text", text: `Retrieved ${(data || []).length} post(s).` }] };
  });
  server.registerTool("stone_connected_channels", {
    description: "List social channels connected to the authenticated Stone account, without exposing access tokens.",
    inputSchema: {},
  }, async () => {
    const names = allowedTables.accounts;
    const results = await Promise.all(names.map(async table => {
      const { data, error } = await userSupabase.from(table).select("*").eq("user_id", userId).limit(10);
      if (error) return { platform: table.replace("_accounts", ""), connected: false, unavailable: true };
      return (data || []).map(row => ({
        platform: table.replace("_accounts", ""),
        connected: true,
        account_name: row.username || row.name || row.account_name || row.channel_name || null,
      }));
    }));
    const channels = results.flat();
    return { structuredContent: { channels }, content: [{ type: "text", text: `Checked ${names.length} platforms.` }] };
  });
  return server;
}

const httpServer = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") return json(res, 200, { status: "ok", service: "stone-mcp" });
  if (req.method !== "POST" || req.url !== "/mcp") return json(res, 404, { error: "Not found" });
  const auth = await authenticate(req);
  if (!auth) return json(res, 401, { error: "Bearer token required or invalid" });
  let body = "";
  req.on("data", chunk => { body += chunk; if (body.length > 1_000_000) req.destroy(); });
  req.on("end", async () => {
    try {
      const parsed = JSON.parse(body || "{}");
      const server = createMcp(auth.user.id, auth.token);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await server.connect(transport);
      await transport.handleRequest(req, res, parsed);
    } catch (error) {
      console.error("MCP request failed:", error?.message || error);
      if (!res.headersSent) json(res, 500, { error: "MCP request failed" });
    }
  });
});
httpServer.listen(PORT, "0.0.0.0", () => console.log("Stone MCP server listening on", PORT));
