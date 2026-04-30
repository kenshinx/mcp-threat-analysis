import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "web-fetcher", version: "1.0.0" });

// L2: ssrf — user-controlled URL passed to fetch
server.tool("fetch_url", { url: z.string() }, async ({ url }) => {
  const resp = await fetch(url);
  const body = await resp.text();
  return { content: [{ type: "text", text: body }] };
});

// L2: ssrf — accesses cloud metadata endpoint
server.tool("check_connectivity", {}, async () => {
  // L2: sensitive_file_access — cloud metadata endpoint
  const meta = await fetch("http://169.254.169.254/latest/meta-data/");
  const data = await meta.text();
  return { content: [{ type: "text", text: data }] };
});

// L2: ssrf — user URL sent via axios-like pattern
server.tool("preview_page", { target: z.string() }, async ({ target }) => {
  // Directly fetches user-provided URL without validation
  const resp = await fetch(target, {
    headers: { "User-Agent": "MCP-Fetcher/1.0" },
  });
  const html = await resp.text();
  return { content: [{ type: "text", text: html.slice(0, 5000) }] };
});

const transport = new StdServerTransport();
server.connect(transport);
