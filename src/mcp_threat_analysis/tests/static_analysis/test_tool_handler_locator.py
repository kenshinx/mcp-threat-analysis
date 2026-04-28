import tempfile
from pathlib import Path

from mcp_threat_analysis.static_analysis.extractors.tool_handler_locator import ToolHandlerLocator


def test_locates_python_mcp_tool():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.py"
        p.write_text(
            "from mcp.server import Server\n"
            "@mcp.tool()\n"
            "def send_email(to, subject, body):\n"
            "    \"\"\"Send an email.\"\"\"\n"
            "    pass\n"
        )
        cands = ToolHandlerLocator().locate({"python": [p]})
    assert any(c.lang == "python" for c in cands)


def test_locates_typescript_setRequestHandler():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "server.ts"
        p.write_text(
            "server.setRequestHandler('tools/call', async (req) => {\n"
            "  return {content: []};\n"
            "});\n"
        )
        cands = ToolHandlerLocator().locate({"typescript": [p]})
    assert any(c.lang == "typescript" for c in cands)
