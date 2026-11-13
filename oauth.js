/**
 * Generic OAuth 2.1 client pieces for MCP servers: protected-resource and
 * authorization-server discovery, dynamic client registration, authorization
 * code + PKCE, the loopback redirect listener, and token exchange/refresh.
 *
 * Nothing here persists secrets or assumes a particular vendor.
 *
 * @module dsh-mcp-oauth/oauth
 */
import { createHash, randomBytes } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

const REQUEST_TIMEOUT_MS = 15_000

/**
 * @param {Buffer} buffer - Raw bytes.
 * @returns {string} base64url text without padding.
 */
function base64url(buffer) {
  return buffer.toString('base64url')
}

/**
 * Create a PKCE verifier and its S256 challenge.
 * @returns {{ verifier: string, challenge: string }} Verifier and challenge.
 */
export function createPkce() {
  const verifier = base64url(randomBytes(32))
  const challenge = base64url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge }
}

/**
 * Create an opaque anti-CSRF state value.
 * @returns {string} Random state.
 */
export function createState() {
  return base64url(randomBytes(16))
}

/**
 * Read a bounded response body without failing the caller.
 * @param {Response} response - Fetch response.
 * @returns {Promise<string>} Short response text.
 */
async function responseDetail(response) {
  try {
    return (await response.text()).trim().slice(0, 300)
  } catch {
    return ''
  }
}

/**
 * Fetch and parse a JSON document, returning undefined for any failure.
 * @param {string} url - Absolute URL.
 * @returns {Promise<Record<string, unknown> | undefined>} Parsed body.
 */
async function fetchJson(url) {
  try {
    const response = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!response.ok) return undefined
    const body = await response.json()
    return body !== null && typeof body === 'object' ? body : undefined
  } catch {
    return undefined
  }
}

/**
 * Derive the RFC 9728 well-known URLs that can describe an MCP endpoint.
 * @param {string} url - MCP endpoint URL.
 * @returns {string[]} Candidate metadata URLs, most specific first.
 */
export function protectedResourceMetadataUrls(url) {
  const endpoint = new URL(url)
  const path = endpoint.pathname.replace(/\/+$/, '')
  const candidates = []
  if (path.length > 0 && path !== '/') {
    candidates.push(`${endpoint.origin}/.well-known/oauth-protected-resource${path}`)
  }
  candidates.push(`${endpoint.origin}/.well-known/oauth-protected-resource`)
  return [...new Set(candidates)]
}

/**
 * Read the `resource_metadata` URL from a WWW-Authenticate challenge.
 * @param {string | null} header - WWW-Authenticate header value.
 * @returns {string | undefined} Metadata URL.
 */
export function resourceMetadataFromChallenge(header) {
  if (typeof header !== 'string') return undefined
  const match = /resource_metadata="([^"]+)"/.exec(header)
  return match === null ? undefined : match[1]
}

/**
 * Discover the OAuth protected-resource metadata for an MCP endpoint: first
 * from the endpoint's own authentication challenge, then from the well-known
 * URLs RFC 9728 defines.
 * @param {string} url - MCP endpoint URL.
 * @returns {Promise<{ resource?: string, authorizationServers: string[], scopesSupported?: string[] } | undefined>} Resource metadata.
 */
export async function discoverResource(url) {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'dsh-mcp-oauth', version: '1' },
        },
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    const advertised = resourceMetadataFromChallenge(response.headers.get('www-authenticate'))
    if (advertised !== undefined) {
      const metadata = await fetchJson(advertised)
      if (metadata !== undefined) return normalizeResourceMetadata(metadata)
    }
  } catch {
    // The endpoint may refuse the probe; the well-known documents still tell.
  }
  for (const candidate of protectedResourceMetadataUrls(url)) {
    const metadata = await fetchJson(candidate)
    if (metadata !== undefined) {
      const normalized = normalizeResourceMetadata(metadata)
      if (normalized !== undefined) return normalized
    }
  }
  return undefined
}

/**
 * @param {Record<string, unknown>} metadata - Raw metadata document.
 * @returns {object | undefined} Normalized metadata.
 */
function normalizeResourceMetadata(metadata) {
  const servers = Array.isArray(metadata.authorization_servers)
    ? metadata.authorization_servers.filter((entry) => typeof entry === 'string')
    : []
  if (servers.length === 0) return undefined
  return {
    ...(typeof metadata.resource === 'string' ? { resource: metadata.resource } : {}),
    authorizationServers: servers,
    ...(Array.isArray(metadata.scopes_supported)
      ? { scopesSupported: metadata.scopes_supported.filter((entry) => typeof entry === 'string') }
      : {}),
  }
}

/**
 * Derive authorization-server metadata URLs for an issuer. RFC 8414 inserts the
 * issuer path into `/.well-known/oauth-authorization-server`; OIDC 1.0 appends
 * `/.well-known/openid-configuration`; a few servers (including ones with a
 * path-based issuer) publish the document at the origin root, so all three
 * shapes are tried.
 * @param {string} issuer - Issuer URL.
 * @returns {string[]} Candidate metadata URLs.
 */
export function authorizationServerMetadataUrls(issuer) {
  const base = issuer.replace(/\/+$/, '')
  const endpoint = new URL(base)
  const path = endpoint.pathname.replace(/\/+$/, '')
  const candidates = [
    `${base}/.well-known/oauth-authorization-server`,
    `${endpoint.origin}/.well-known/oauth-authorization-server${path}`,
    `${endpoint.origin}/.well-known/oauth-authorization-server`,
    `${base}/.well-known/openid-configuration`,
    `${endpoint.origin}/.well-known/openid-configuration${path}`,
    `${endpoint.origin}/.well-known/openid-configuration`,
  ]
  return [...new Set(candidates)]
}

/**
 * Discover an authorization server's metadata: RFC 8414 first, OIDC discovery
 * as the fallback.
 * @param {string} issuer - Authorization server issuer URL.
 * @returns {Promise<{ issuer: string, authorizationEndpoint: string, tokenEndpoint: string, registrationEndpoint?: string, scopesSupported?: string[] }>} Server metadata.
 */
export async function discoverAuthorizationServer(issuer) {
  const base = issuer.replace(/\/+$/, '')
  for (const candidate of authorizationServerMetadataUrls(base)) {
    const metadata = await fetchJson(candidate)
    if (metadata === undefined) continue
    if (typeof metadata.authorization_endpoint !== 'string' || typeof metadata.token_endpoint !== 'string') continue
    return {
      issuer: typeof metadata.issuer === 'string' ? metadata.issuer : base,
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      ...(typeof metadata.registration_endpoint === 'string'
        ? { registrationEndpoint: metadata.registration_endpoint }
        : {}),
      ...(Array.isArray(metadata.scopes_supported)
        ? { scopesSupported: metadata.scopes_supported.filter((entry) => typeof entry === 'string') }
        : {}),
    }
  }
  throw new Error(`no authorization-server metadata at ${base}`)
}

/**
 * Register a public OAuth client for the loopback redirect URI.
 * @param {object} options - Registration inputs.
 * @param {string} options.registrationEndpoint - Dynamic registration URL.
 * @param {string} options.redirectUri - Pinned loopback redirect URI.
 * @param {string} [options.scopes] - Requested scopes.
 * @param {string} options.clientName - Human-readable client name.
 * @returns {Promise<{ clientId: string, clientSecret?: string }>} Registered client.
 */
export async function registerClient({ registrationEndpoint, redirectUri, scopes, clientName }) {
  const response = await fetch(registrationEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      client_name: clientName,
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      ...(scopes === undefined || scopes.length === 0 ? {} : { scope: scopes }),
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  if (!response.ok) {
    throw new Error(`client registration failed (${response.status}) ${await responseDetail(response)}`.trim())
  }
  const body = await response.json()
  if (typeof body?.client_id !== 'string' || body.client_id.length === 0) {
    throw new Error('client registration response carried no client_id')
  }
  return {
    clientId: body.client_id,
    ...(typeof body.client_secret === 'string' ? { clientSecret: body.client_secret } : {}),
  }
}

/**
 * Build the authorization request URL.
 * @param {object} options - Request inputs.
 * @param {string} options.authorizationEndpoint - Authorization URL.
 * @param {string} options.clientId - Registered client id.
 * @param {string} options.redirectUri - Pinned loopback redirect URI.
 * @param {string} [options.scopes] - Requested scopes.
 * @param {string} options.state - Anti-CSRF state.
 * @param {string} options.challenge - PKCE S256 challenge.
 * @param {string} [options.resource] - RFC 8707 resource indicator.
 * @returns {string} Authorization URL.
 */
export function buildAuthorizeUrl({ authorizationEndpoint, clientId, redirectUri, scopes, state, challenge, resource }) {
  const url = new URL(authorizationEndpoint)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  if (typeof scopes === 'string' && scopes.length > 0) url.searchParams.set('scope', scopes)
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', challenge)
  url.searchParams.set('code_challenge_method', 'S256')
  if (typeof resource === 'string' && resource.length > 0) url.searchParams.set('resource', resource)
  return url.toString()
}

/**
 * POST a form body to the token endpoint and normalise the grant.
 * @param {string} tokenEndpoint - Token URL.
 * @param {Record<string, string>} fields - Form fields.
 * @returns {Promise<{ access: string, refresh?: string, expiresIn: number, scope?: string, tokenType: string }>} Grant.
 */
async function tokenRequest(tokenEndpoint, fields) {
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams(fields),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  let body
  try {
    body = await response.json()
  } catch {
    body = undefined
  }
  if (!response.ok || typeof body?.access_token !== 'string') {
    const code = typeof body?.error === 'string' ? body.error : `HTTP ${response.status}`
    const description = typeof body?.error_description === 'string'
      ? body.error_description
      : await responseDetail(response)
    const error = new Error(`token request failed: ${code}${description ? ` — ${description}` : ''}`)
    error.code = typeof body?.error === 'string' ? body.error : undefined
    throw error
  }
  return {
    access: body.access_token,
    ...(typeof body.refresh_token === 'string' ? { refresh: body.refresh_token } : {}),
    expiresIn: Number.isFinite(body.expires_in) ? Number(body.expires_in) : 3600,
    ...(typeof body.scope === 'string' ? { scope: body.scope } : {}),
    tokenType: typeof body.token_type === 'string' ? body.token_type : 'Bearer',
  }
}

/**
 * Exchange an authorization code for a grant.
 * @param {object} options - Exchange inputs.
 * @param {string} options.tokenEndpoint - Token URL.
 * @param {string} options.clientId - Registered client id.
 * @param {string} [options.clientSecret] - Confidential-client secret, when issued.
 * @param {string} options.code - Authorization code.
 * @param {string} options.redirectUri - Pinned loopback redirect URI.
 * @param {string} options.verifier - PKCE verifier.
 * @param {string} [options.resource] - RFC 8707 resource indicator.
 * @returns {Promise<object>} Grant.
 */
export function exchangeCode({ tokenEndpoint, clientId, clientSecret, code, redirectUri, verifier, resource }) {
  const fields = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: verifier,
  }
  if (typeof resource === 'string' && resource.length > 0) fields.resource = resource
  if (typeof clientSecret === 'string' && clientSecret.length > 0) fields.client_secret = clientSecret
  return tokenRequest(tokenEndpoint, fields)
}

/**
 * Refresh a grant with its refresh token.
 * @param {object} options - Refresh inputs.
 * @param {string} options.tokenEndpoint - Token URL.
 * @param {string} options.clientId - Registered client id.
 * @param {string} [options.clientSecret] - Confidential-client secret, when issued.
 * @param {string} options.refresh - Refresh token.
 * @param {string} [options.resource] - RFC 8707 resource indicator.
 * @returns {Promise<object>} Grant.
 */
export function refreshAccessToken({ tokenEndpoint, clientId, clientSecret, refresh, resource }) {
  const fields = { grant_type: 'refresh_token', refresh_token: refresh, client_id: clientId }
  if (typeof resource === 'string' && resource.length > 0) fields.resource = resource
  if (typeof clientSecret === 'string' && clientSecret.length > 0) fields.client_secret = clientSecret
  return tokenRequest(tokenEndpoint, fields)
}

/**
 * Render the page the browser shows after the redirect.
 * @param {boolean} ok - Whether sign-in succeeded.
 * @param {string} [reason] - Failure reason.
 * @returns {string} HTML page.
 */
function resultPage(ok, reason) {
  const title = ok ? 'Signed in' : 'Sign-in failed'
  const detail = ok
    ? 'The harness stored the credential. You can close this tab and return to DeepSeek Harness.'
    : `The harness could not finish sign-in (${reason ?? 'unknown error'}). Close this tab and start sign-in again from the harness.`
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>`
    + '<style>body{font:15px/1.5 system-ui,-apple-system,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f5f7fa;color:#1f2933}'
    + 'main{background:#fff;border:1px solid #d7dee6;border-radius:14px;padding:28px 32px;max-width:460px}'
    + 'h1{font-size:19px;margin:0 0 8px}p{margin:0;color:#52606d}</style></head>'
    + `<body><main><h1>${title}</h1><p>${detail}</p></main></body></html>`
}

/**
 * Listen on the loopback redirect URI for the authorization response.
 * @param {object} options - Listener inputs.
 * @param {number} options.port - Loopback port.
 * @param {string} options.state - Expected state value.
 * @param {number} options.timeoutMs - Budget for the browser round trip.
 * @param {string} [options.pathname] - Redirect path.
 * @returns {Promise<{ result: Promise<{ code: string }>, close: () => Promise<void> }>} Listener.
 */
export async function listenForCallback({ port, state, timeoutMs, pathname = '/callback' }) {
  let succeed
  let fail
  const result = new Promise((resolve, reject) => {
    succeed = resolve
    fail = reject
  })
  // A rejection nobody awaits must not surface as an unhandled rejection.
  result.catch(() => {})

  const server = createServer((req, res) => {
    let url
    try {
      url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`)
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain' })
      res.end('Bad request')
      return
    }
    if (url.pathname !== pathname) {
      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('Not found')
      return
    }
    const error = url.searchParams.get('error')
    const description = url.searchParams.get('error_description')
    const code = url.searchParams.get('code')
    const returned = url.searchParams.get('state')
    const ok = error === null && typeof code === 'string' && returned === state
    res.writeHead(ok ? 200 : 400, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    })
    res.end(resultPage(ok, error ?? (returned !== state ? 'state mismatch' : undefined)))
    if (error !== null) {
      fail(new Error(`authorization failed: ${error}${description ? ` — ${description}` : ''}`))
    } else if (typeof code !== 'string') {
      fail(new Error('authorization response carried no code'))
    } else if (returned !== state) {
      fail(new Error('authorization state mismatch'))
    } else {
      succeed({ code })
    }
  })

  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', resolve)
  })

  const timer = setTimeout(() => fail(new Error('sign-in timed out waiting for the browser')), timeoutMs)
  timer.unref?.()
  result.finally(() => clearTimeout(timer)).catch(() => {})

  const close = () => new Promise((resolve) => {
    server.close(() => resolve())
    server.closeAllConnections?.()
  })
  return { result, close }
}

/**
 * Open a URL in the user's default browser.
 * @param {string} url - URL to open.
 * @returns {boolean} Whether a browser launcher was started.
 */
export function openBrowser(url) {
  const platform = process.platform
  const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open'
  const args = platform === 'win32' ? ['/c', 'start', '', url] : [url]
  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' })
    child.on('error', () => {})
    child.unref()
    return true
  } catch {
    return false
  }
}
