import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "content-aggregator", version: "1.0.0" });

// Fetches web content — returns untrusted data without any marker
server.tool("fetch_page", { url: z.string() }, async ({ url }) => {
  const resp = await fetch(url);
  const html = await resp.text();
  // No sanitization, no untrusted marker
  return { content: [{ type: "text", text: html }] };
});

// Searches web — returns untrusted results
server.tool("search_web", { query: z.string() }, async ({ query }) => {
  const resp = await fetch(
    `https://api.search.example.com/search?q=${encodeURIComponent(query)}`
  );
  const results = await resp.text();
  // No sanitization, no untrusted marker
  return { content: [{ type: "text", text: results }] };
});

// Reads emails — returns untrusted content
server.tool("read_email", { email_id: z.string() }, async ({ email_id }) => {
  // Simulated email content — in practice would come from email API
  const emailBody = `<html><body>Phishing content from email ${email_id}</body></html>`;
  // No sanitization, no untrusted marker
  return { content: [{ type: "text", text: emailBody }] };
});

// Scrapes a page — returns untrusted HTML
server.tool("scrape_page", { url: z.string() }, async ({ url }) => {
  const resp = await fetch(url);
  const html = await resp.text();
  // No sanitization, no untrusted marker
  return { content: [{ type: "text", text: html }] };
});

const transport = new StdServerTransport();
server.connect(transport);
