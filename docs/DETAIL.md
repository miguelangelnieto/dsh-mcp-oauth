# MCP OAuth servers

Some MCP servers accept only OAuth bearer tokens. The MCP client bridge has no
interactive sign-in, so this plugin supplies one for every server you list in
its configuration.

## How it works

For each provider:

1. **Discovery** — it reads the endpoint's `WWW-Authenticate` challenge for
   RFC 9728 protected-resource metadata, falls back to the well-known
   `/.well-known/oauth-protected-resource` URLs, then reads the authorization
   server's RFC 8414 / OIDC metadata for the authorize, token, and (optional)
   registration endpoints. Explicit `authorizationEndpoint` / `tokenEndpoint` in
   configuration skip discovery.
2. **Client** — it uses a configured `clientId`, a stored dynamic registration,
   or registers a new public client (`token_endpoint_auth_method: none`) when the
   server advertises a registration endpoint.
3. **Sign-in** — the `mcp_oauth` tool opens the authorization page in the browser
   with PKCE (S256) and a loopback redirect on `127.0.0.1:<redirectPort>/callback`,
   exchanges the code, and stores the grant in the harness credential store.
4. **Server** — when the MCP manager is mounted, the plugin registers the server
   as `streamable-http` with `Authorization: Bearer ${credential:<tokenRef>}`; the
   bridge mounts a client for it and its tools appear as `mcp__<serverName>__<tool>`.
   Without the manager, the token is still published for a `dsh-mcp-client` row
   you configure yourself.
5. **Refresh** — a one-minute timer refreshes the grant two minutes before
   expiry and republishes the credential, so the connection rotates without a
   restart. A rejected grant is deleted and the server waits for a new sign-in.

## Storage

- Client registration: `<plugin>/<provider>-client`.
- Grant (access token, rotated refresh token, expiry):
  `<plugin>/<provider>-tokens`.
- Access token: the provider's `tokenRef` credential (default
  `<PROVIDER>_MCP_TOKEN`).

No token value appears in configuration, logs, or tool output. Tool results
carry only whether a grant exists and when it expires.

## Scope and resource parameters

The recommended scopes are the protected resource's `scopes_supported`, unless
`scopes` overrides them. Many authorization servers need `offline_access` for a
refresh token, so list it explicitly. The discovered resource URL is sent as the
RFC 8707 `resource` parameter; override it with `resource` when the server
publishes a different identifier.

## Limitations

- Sign-in is interactive: someone finishes the browser page. There is no
  headless or device-code path.
- Refreshing happens only while the Host runs.
- Servers without dynamic client registration need a `clientId` (and, for
  confidential clients, `clientSecret`) in configuration.
- `redirectPort` is pinned per provider; changing it re-registers that client.
