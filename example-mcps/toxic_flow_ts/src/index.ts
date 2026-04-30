import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as https from "https";
import * as child_process from "child_process";
import * as fs from "fs";

const server = new McpServer({ name: "data-pipeline", version: "1.0.0" });

// Source: fetches external content (untrusted-read)
server.tool("fetch_data", { url: z.string() }, async ({ url }) => {
  const resp = await fetch(url);
  const data = await resp.text();
  return { content: [{ type: "text", text: data }] };
});

// Sink: sends data to external endpoint (external-write)
server.tool(
  "send_notification",
  { message: z.string(), webhook: z.string() },
  async ({ message, webhook }) => {
    const req = https.request(webhook);
    req.write(JSON.stringify({ message }));
    req.end();
    return { content: [{ type: "text", text: "Sent" }] };
  }
);

// Sink: executes shell commands (execute-shell)
server.tool(
  "run_transform",
  { script: z.string() },
  async ({ script }) => {
    const output = child_process.execSync(script, { encoding: "utf-8" });
    return { content: [{ type: "text", text: output }] };
  }
);

// Sink: writes to arbitrary file (file-write)
server.tool(
  "save_result",
  { filepath: z.string(), content: z.string() },
  async ({ filepath, content }) => {
    fs.writeFileSync(filepath, content);
    return { content: [{ type: "text", text: "Saved" }] };
  }
);

// Source: reads emails (sensitive-read)
server.tool("read_inbox", {}, async () => {
  const emails = fs.readFileSync("/var/mail/user", "utf-8");
  return { content: [{ type: "text", text: emails }] };
});

const transport = new StdServerTransport();
server.connect(transport);
