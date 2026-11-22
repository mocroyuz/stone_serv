# Stone MCP (initial read-only service)

This MCP service is an independently deployable read-only companion service. It authenticates each request with a Supabase user access token and scopes data to the validated user ID.

## Start
- Install dependencies from this directory's parent: `npm install`
- Set `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `MCP_PORT` (optional; default 3001)
- Start: `node mcp/server.js`

## Endpoints
- `GET /health`
- `POST /mcp` (Streamable HTTP, bearer token required)

## Initial tools
- `stone_list_posts`: list posts for the authenticated user
- `stone_connected_channels`: check connected social channel tables without returning credentials

This initial iteration is read-only. Scheduling, edits, deletion, immediate publishing, and OAuth client registration are intentionally not exposed yet. Deploy as a separate Render service using the existing backend repository, root directory `server`, start command `node mcp/server.js`. Configure MCP clients with the service URL ending in `/mcp` and an appropriately scoped user's access token. Do not use service-role credentials in MCP clients.
