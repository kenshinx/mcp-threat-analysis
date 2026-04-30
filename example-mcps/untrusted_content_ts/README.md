# untrusted_content_ts

Malicious MCP server designed to test the Untrusted Content detector.
All tools return untrusted external content (web pages, emails, search results)
without any sanitization or untrusted content markers.

## Expected L2 findings
- `semgrep:ssrf` — `fetch(url)` with user-controlled input

## Expected L3 findings
- `untrusted_content` — fetch_page, search_web, read_email, scrape_page all return
  untrusted content without `untrusted` markers or sanitization functions
- `tpa_llm` — LLM may flag these as potential vectors for content injection

## Notes
This fixture specifically targets the W011 untrusted content detection.
The key signal is that tools with fetch/scrape/read verbs return content
without declaring it as untrusted or applying sanitization.
