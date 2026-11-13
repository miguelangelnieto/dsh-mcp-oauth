# dsh-mcp-oauth

Sign in to OAuth-protected MCP servers from [DeepSeek Harness](https://deepseek.com) — and keep them signed in.

The MCP client bridge speaks stdio and Streamable HTTP with static headers, but
has no interactive OAuth. This Host plugin fills that gap for servers that
accept only bearer tokens: it discovers the server's authorization server, runs
the browser authorization-code + PKCE flow, stores the grant in the harness
credential store, refreshes it before expiry, and registers the MCP server so
its tools appear. It is vendor-neutral: no endpoint, client id, or provider is
built in.

## Requirements

- DeepSeek Harness Web or Desktop profile — the plugin registers servers through
  the **MCP manager** service (`@deepseek-ai/dsh-mcp-manager`), which the Web and
  Desktop profiles mount. Without the manager, tokens are still published for a
  `dsh-mcp-client` row you configure yourself.
- The MCP server must expose OAuth metadata per RFC 9728 / RFC 8414 (most MCP
  providers do), or you must name the endpoints in configuration.
- Loopback port 53682 free while signing in.
- Node built-ins only: nothing is installed or downloaded at runtime.

## Install

Add this directory as a profile bundle: **Plugins → Add plugin** in the app, or
ask the agent to run the `plugin_manager` tool with `install_bundle` and this
directory's absolute path.

Either route installs the package and selects the bundle. Installing the package
alone with pnpm (`dsh plugin --profile <profile> add <dir>`) is not enough: the
bundle must also be listed under `dsh.profile.bundles` in the profile's
`package.json`, which is what the two routes above do.

The package deliberately keeps the local name `@local/dsh-mcp-oauth`; rename it before
publishing to a registry. It installs the row `dsh-mcp-oauth`, so the feature can be
disabled from Plugins without uninstalling the package.

## Configure

The bundle inserts the plugin row with no providers. Add providers in your
profile's `cordis.patch.yml`:

```yaml
- id: dsh-mcp-oauth
  config:
    providers:
      example:
        url: https://mcp.example.com/mcp
        scopes: mcp offline_access
      other:
        url: https://other.example.com/mcp
        # optional overrides below
```

Each provider key is a lowercase id. Its tools appear as
`mcp__<serverName>__<tool>`, with `serverName` defaulting to the key.

### Provider fields

| Field | Default | Meaning |
|---|---|---|
| `url` | required | MCP endpoint (Streamable HTTP) |
| `serverName` | provider key | Tool namespace, `[A-Za-z0-9_-]{1,32}` |
| `scopes` | discovered | Space-separated scopes to request (add `offline_access` for refresh tokens) |
| `resource` | discovered | RFC 8707 resource indicator sent to authorize/token |
| `issuer` | discovered | Authorization-server issuer |
| `authorizationEndpoint`, `tokenEndpoint`, `registrationEndpoint` | discovered | Explicit endpoints; skip discovery |
| `clientId`, `clientSecret` | — | Use a pre-registered client instead of dynamic registration |
| `tokenRef` | `<ID>_MCP_TOKEN` | Credential reference the access token is published to |
| `redirectPort` | `53682` | Loopback callback port (`http://127.0.0.1:<port>/callback`) |
| `clientName` | `DeepSeek Harness` | Name sent to dynamic registration |
| `register` | `true` | Register the server with the MCP manager |
| `headers` | `{}` | Extra request headers for the MCP connection |
| `toolCallTimeoutMs`, `startupTimeoutMs` | manager defaults | Per-server budgets |

## Use

One tool, `mcp_oauth`:

| Call | Effect |
|---|---|
| `{ provider, action: "status" }` | Whether a grant exists and when it expires |
| `{ provider, action: "sign_in" }` | Opens the browser sign-in; the server reconnects when the credential lands |
| `{ provider, action: "sign_out" }` | Deletes the grant and the credential |

## How authentication works

1. The plugin probes the MCP endpoint for a `WWW-Authenticate` challenge and
   reads the RFC 9728 protected-resource metadata it advertises; otherwise it
   tries `/.well-known/oauth-protected-resource` (path-scoped and origin-scoped).
2. It reads the authorization server's RFC 8414 or OIDC metadata for the
   authorize and token endpoints, then optionally registers a public client.
3. Sign-in uses PKCE (S256) with a state value and a loopback redirect.
4. The grant is stored as credential records (`dsh-mcp-oauth/<provider>-client`
   and `-tokens`) and the access token is published to `tokenRef`. The MCP row
   references it as `Bearer ${credential:<tokenRef>}`, so no secret is written
   into configuration.
5. A one-minute timer refreshes two minutes before expiry and republishes the
   token. A rejected grant is removed and the server waits for a new sign-in.

## Notes and limits

- Sign-in is interactive; there is no headless or device-code path.
- Refreshing only runs while the Host runs; a Host closed past the refresh
  token's lifetime needs a new sign-in.
- Servers without dynamic client registration need `clientId` (and
  `clientSecret` for confidential clients).
- No token value is logged, rendered, or written to plugin configuration.
- Changing `redirectPort` re-registers the client for that provider.

## License

MIT — see [LICENSE](LICENSE).
