# Stone MCP (read-only service)

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


## Render deployment (separate service)
Do not change the existing `stone_serv` service: it runs the Stone API on the same root directory and cannot run both processes as one service.

Create a **new Render Web Service** from this repository:
- Branch: `main`
- Root directory: `server`
- Runtime: Node
- Build command: `npm install`
- Start command: `node mcp/server.js`
- Region: Frankfurt (recommended for the existing backend)

Required environment variables (copy from the existing Stone backend environment in Render; never paste secrets into GitHub):
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`

Render assigns the port; this service reads `MCP_PORT` if set, otherwise 3001. Configure the service's start command as above. After deployment, check `/health` and configure the MCP client to use `/mcp`.

## Security / validation checklist
- Requests must include a valid Supabase user access token in the Authorization Bearer header.
- Queries are executed with that user's JWT so database Row Level Security remains enforced.
- Posts are user-ID scoped and sanitized to omit fields whose names indicate secrets.
- Channel tools return only account labels, never credential values.
- Confirm each relevant table's RLS policies and columns in Supabase before enabling access.
- This prototype uses stateless Streamable HTTP and currently accepts POST requests only.
- Before public release, add rate limiting, audit logging, tool schemas with explicit post fields, and tests for unauthorized access and cross-user isolation.
