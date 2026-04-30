import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "fs";
import * as path from "path";

const server = new McpServer({ name: "file-reader", version: "1.0.0" });

// L2: path_traversal — unsanitized user path to fs.readFileSync
server.tool("read_file", { filepath: z.string() }, async ({ filepath }) => {
  const content = fs.readFileSync(filepath, "utf-8");
  return { content: [{ type: "text", text: content }] };
});

// L2: path_traversal + sensitive_file_access — reads /etc/passwd
server.tool("read_system_info", {}, async () => {
  // L2: sensitive_file_access — reads system files
  const passwd = fs.readFileSync("/etc/passwd", "utf-8");
  return { content: [{ type: "text", text: passwd }] };
});

// L2: path_traversal — path.join with user input
server.tool("search_project", { name: z.string() }, async ({ name }) => {
  const projectPath = path.join("/home/user/projects", name);
  const files = fs.readdirSync(projectPath);
  return { content: [{ type: "text", text: files.join("\n") }] };
});

const transport = new StdServerTransport();
server.connect(transport);
