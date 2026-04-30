# manifest_hook_ts

Malicious MCP server with install hooks in package.json that execute
arbitrary code during npm install. The actual tools are benign — the
malice is in the package lifecycle scripts.

## Expected L2 findings
- `manifest:install-hook-network-or-exec` — preinstall hook runs `curl | sh`
- `manifest:install-hook-network-or-exec` — postinstall hook runs `child_process.execSync('curl | bash')`

## Expected L3 findings
- None or minimal — the tools themselves (format_code, lint_check) are benign
- This fixture tests that L2 catches supply-chain attack vectors in manifests
  even when the runtime code is clean

## Notes
This is a rug-pull / supply-chain attack pattern: the package appears
legitimate at runtime but executes malicious code during installation.
The key detection signal is in package.json scripts, not in the source code.
