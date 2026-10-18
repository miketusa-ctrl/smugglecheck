# SmuggleCheck

Find hidden prompt-injection text: ASCII smuggling, zero-width/emoji stego, bidi, homoglyphs. One layer, not a full defense: it does not judge prompt injection written in plain, visible words.

SmuggleCheck is not affiliated with, endorsed or sponsored by Meta, OpenAI, Anthropic, Google, Mistral AI, DeepSeek, Alibaba (Qwen), the Unicode Consortium or any other AI vendor, model vendor or MCP client maker.

## Live service

- Web app and API: https://smugglecheck.mike-tusa.workers.dev/
- Plans: Free, no paid plan (https://smugglecheck.mike-tusa.workers.dev/)
- Support: digitalpromohub.support@gmail.com

## Use it from an AI assistant (MCP)

SmuggleCheck is a remote MCP server (Streamable HTTP) at `https://smugglecheck.mike-tusa.workers.dev/mcp`. Tools: `scan_text`, `compare_strings`.

Cursor and Windsurf accept this config:

```json
{
  "mcpServers": {
    "smugglecheck": {
      "type": "http",
      "url": "https://smugglecheck.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Cline (MCP Servers > Remote Servers, or `cline_mcp_settings.json`) needs `"type": "streamableHttp"`:

```json
{
  "mcpServers": {
    "smugglecheck": {
      "type": "streamableHttp",
      "url": "https://smugglecheck.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Claude Desktop: open Settings > Connectors, choose "Add custom connector" and paste `https://smugglecheck.mike-tusa.workers.dev/mcp`. Or, for clients that only support local (stdio) servers, use the mcp-remote bridge: `npx mcp-remote https://smugglecheck.mike-tusa.workers.dev/mcp`.

VS Code uses a `servers` key instead of `mcpServers`.

The `server.json` file is the [MCP Registry](https://registry.modelcontextprotocol.io) manifest for this server.

## Run your own copy

Requires Node.js 22+ and a Cloudflare account.

```bash
npm install
npx wrangler@4 dev      # local dev server
```

`wrangler.toml` is a template: create your own KV namespaces / D1 databases / rate-limit namespaces and replace the `<PLACEHOLDER>` values before `npx wrangler@4 deploy`. Any secrets the Worker reads go in `wrangler secret put` (or `.dev.vars` locally), never in the repo.

Optional Worker secrets (leave unset if you do not need them): `GLAMA_CLAIM` (your glama.ai connector claim token, served at `/.well-known/glama.json`); `VISITOR_SALT` (a random salt for the privacy-friendly daily unique-visitor counter; while it is unset, no visitors are counted); `MCP_REGISTRY_AUTH` (your MCP Registry HTTP-domain proof, `v=MCPv1; k=ed25519; p=<public key>`, served at `/.well-known/mcp-registry-auth`; 404 while unset).

## Third-party data

The code in this repository is licensed under MIT. The homoglyph data file `src/lib/confusables-data.js` is NOT MIT: it is generated from Unicode confusables.txt (UTS #39 18.0.0), © Unicode, Inc., and is licensed under the Unicode License v3 (https://www.unicode.org/license.txt). See [NOTICE](NOTICE).

## License

Code: MIT (c) Digital Promo Hub, see [LICENSE](LICENSE). Homoglyph data file `src/lib/confusables-data.js`: Unicode License v3, © Unicode, Inc., see [NOTICE](NOTICE).
