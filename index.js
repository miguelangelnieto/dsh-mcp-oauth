/**
 * OAuth-protected MCP servers for DeepSeek Harness.
 *
 * Point this plugin at any MCP endpoint that speaks OAuth 2.1 (RFC 9728
 * protected-resource metadata, optional dynamic client registration): it runs
 * the browser authorization-code + PKCE sign-in, stores the grant in the
 * harness credential store, publishes the access token as a credential
 * reference, refreshes it before expiry, and (when the MCP manager is
 * available) registers the server so its tools appear without any separate
 * mcp-client configuration.
 *
 * No endpoint, vendor, or client id is built in: everything comes from the
 * `providers` configuration.
 *
 * @module dsh-mcp-oauth
 */
import {
  buildAuthorizeUrl,
  createPkce,
  createState,
  discoverAuthorizationServer,
  discoverResource,
  exchangeCode,
  listenForCallback,
  openBrowser,
  refreshAccessToken,
  registerClient,
} from './oauth.js'

export const name = 'dsh-mcp-oauth'
export const inject = ['credentials', 'tools']

const REFRESH_INTERVAL_MS = 60_000
const REFRESH_LEEWAY_MS = 120_000
const SIGN_IN_TIMEOUT_MS = 180_000
const DISCOVERY_TTL_MS = 60 * 60_000
const PROVIDER_ID = /^[a-z][a-z0-9_-]{0,30}$/
const SERVER_NAME = /^[A-Za-z0-9_-]{1,32}$/
const TOOL_NAME = /^[a-z][a-z0-9_]{1,40}$/
const REF_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/

/**
 * Read a bounded error description without leaking grant values.
 * @param {unknown} error - Thrown value.
 * @returns {string} Short message.
 */
function messageOf(error) {
  if (error instanceof Error) return error.message.slice(0, 400)
  return String(error).slice(0, 400)
}

/**
 * Derive a credential reference name from a provider id.
 * @param {string} id - Provider id.
 * @returns {string} Uppercase reference name.
 */
function defaultTokenRef(id) {
  const name = id.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')
  return `${name}_MCP_TOKEN`
}

/**
 * Validate and fill one provider's configuration.
 * @param {string} id - Provider key.
 * @param {Record<string, unknown>} value - Provider config.
 * @returns {object} Resolved provider.
 */
function resolveProvider(id, value) {
  if (!PROVIDER_ID.test(id)) {
    throw new Error(`dsh-mcp-oauth providers.${id}: id must match [a-z][a-z0-9_-]{0,30}`)
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`dsh-mcp-oauth providers.${id} must be a mapping`)
  }
  const string = (key, fallback, { required = false } = {}) => {
    const candidate = value[key] ?? fallback
    if (candidate === undefined) {
      if (required) throw new Error(`dsh-mcp-oauth providers.${id}.${key} is required`)
      return undefined
    }
    if (typeof candidate !== 'string' || candidate.trim().length === 0) {
      throw new Error(`dsh-mcp-oauth providers.${id}.${key} must be a non-empty string`)
    }
    return candidate.trim()
  }
  const url = string('url', undefined, { required: true })
  let parsedUrl
  try {
    parsedUrl = new URL(url)
  } catch {
    throw new Error(`dsh-mcp-oauth providers.${id}.url must be an absolute http(s) URL`)
  }
  if (!/^https?:$/.test(parsedUrl.protocol)) {
    throw new Error(`dsh-mcp-oauth providers.${id}.url must be an absolute http(s) URL`)
  }
  const tokenRef = string('tokenRef', defaultTokenRef(id))
  if (!REF_NAME.test(tokenRef)) {
    throw new Error(`dsh-mcp-oauth providers.${id}.tokenRef must be a POSIX shell identifier`)
  }
  const serverName = string('serverName', id)
  if (!SERVER_NAME.test(serverName)) {
    throw new Error(`dsh-mcp-oauth providers.${id}.serverName must match [A-Za-z0-9_-]{1,32}`)
  }
  const redirectPort = value.redirectPort ?? 53682
  if (!Number.isInteger(redirectPort) || redirectPort < 1024 || redirectPort > 65_535) {
    throw new Error(`dsh-mcp-oauth providers.${id}.redirectPort must be an integer port from 1024 to 65535`)
  }
  const integer = (key, fallback, min, max) => {
    const candidate = value[key] ?? fallback
    if (candidate === undefined) return undefined
    if (!Number.isInteger(candidate) || candidate < min || candidate > max) {
      throw new Error(`dsh-mcp-oauth providers.${id}.${key} must be an integer from ${min} to ${max}`)
    }
    return candidate
  }
  const headers = value.headers ?? {}
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new Error(`dsh-mcp-oauth providers.${id}.headers must be a mapping of strings`)
  }
  for (const [header, headerValue] of Object.entries(headers)) {
    if (typeof headerValue !== 'string') {
      throw new Error(`dsh-mcp-oauth providers.${id}.headers.${header} must be a string`)
    }
  }
  const register = value.register ?? true
  if (typeof register !== 'boolean') {
    throw new Error(`dsh-mcp-oauth providers.${id}.register must be a boolean`)
  }
  return {
    id,
    url,
    serverName,
    tokenRef,
    redirectPort,
    redirectUri: `http://127.0.0.1:${redirectPort}/callback`,
    clientName: string('clientName', 'DeepSeek Harness'),
    headers,
    register,
    toolCallTimeoutMs: integer('toolCallTimeoutMs', undefined, 1000, 3_600_000),
    startupTimeoutMs: integer('startupTimeoutMs', undefined, 1000, 3_600_000),
    ...(string('scopes', undefined) === undefined ? {} : { scopes: string('scopes', undefined) }),
    ...(string('resource', undefined) === undefined ? {} : { resource: string('resource', undefined) }),
    ...(string('issuer', undefined) === undefined ? {} : { issuer: string('issuer', undefined) }),
    ...(string('authorizationEndpoint', undefined) === undefined
      ? {}
      : { authorizationEndpoint: string('authorizationEndpoint', undefined) }),
    ...(string('tokenEndpoint', undefined) === undefined ? {} : { tokenEndpoint: string('tokenEndpoint', undefined) }),
    ...(string('registrationEndpoint', undefined) === undefined
      ? {}
      : { registrationEndpoint: string('registrationEndpoint', undefined) }),
    ...(string('clientId', undefined) === undefined ? {} : { clientId: string('clientId', undefined) }),
    ...(string('clientSecret', undefined) === undefined ? {} : { clientSecret: string('clientSecret', undefined) }),
  }
}

/**
 * Resolve the `providers` map; an empty or absent map means "not configured".
 * @param {Record<string, unknown> | undefined} config - Row config.
 * @returns {object[]} Providers in configuration order.
 */
export function resolveProviders(config) {
  const configured = config?.providers
  if (configured === undefined || configured === null) return []
  if (typeof configured !== 'object' || Array.isArray(configured)) {
    throw new Error('dsh-mcp-oauth config.providers must be a mapping')
  }
  return Object.entries(configured).map(([id, value]) => resolveProvider(id, value))
}

/**
 * Build one provider's endpoints, storage, sign-in engine, and status.
 * @param {import('@deepseek-ai/cordis').Context} ctx - Plugin context.
 * @param {object} provider - Resolved provider.
 * @returns {object} Engine.
 */
function createEngine(ctx, provider) {
  const credentials = ctx.credentials
  const clientKey = `${name}/${provider.id}-client`
  const tokensKey = `${name}/${provider.id}-tokens`

  /** @type {{ state: 'starting' | 'signed-out' | 'authorized' | 'error', error?: string }} */
  let status = { state: 'starting' }
  /** @type {{ url: string } | undefined} */
  let activeFlow
  /** @type {{ at: number, endpoints: object } | undefined} */
  let discovery

  /**
   * @param {string} key - Record key.
   * @returns {Promise<Record<string, unknown> | undefined>} Stored payload.
   */
  async function readRecord(key) {
    const record = await credentials.readRecord(key)
    const payload = record?.payload
    return payload !== null && typeof payload === 'object' ? payload : undefined
  }

  /**
   * @param {string} key - Record key.
   * @param {Record<string, unknown>} payload - Payload to store.
   * @returns {Promise<void>} Resolves after the write.
   */
  async function writeRecord(key, payload) {
    await credentials.modifyRecord(key, async () => ({ kind: 'grant', payload }))
  }

  /**
   * Publish the access token the registered server's header resolves.
   * @param {string} access - Bearer value.
   * @returns {Promise<void>} Resolves after the write.
   */
  async function publish(access) {
    await credentials.set(provider.tokenRef, access)
  }

  /**
   * Publish a live token, comparing first so a periodic check does not rewrite
   * an unchanged credential and reconnect the MCP server for nothing.
   * @param {string} access - Bearer value.
   * @returns {Promise<void>} Resolves after the credential settles.
   */
  async function ensurePublished(access) {
    const current = await credentials.resolve(provider.tokenRef)
    if (current?.value !== access) await publish(access)
    status = { state: 'authorized' }
  }

  /**
   * Drop a grant the server no longer accepts.
   * @returns {Promise<void>} Resolves after the cleanup.
   */
  async function clearGrant() {
    await credentials.deleteRecord(tokensKey)
    await credentials.unset(provider.tokenRef)
  }

  /**
   * Resolve the authorization and token endpoints, discovering them from the
   * MCP endpoint's metadata unless the configuration names them.
   * @param {boolean} [force] - Ignore the cached discovery result.
   * @returns {Promise<object>} Endpoints and resource indicator.
   */
  async function resolveEndpoints(force = false) {
    if (!force && discovery !== undefined && Date.now() - discovery.at < DISCOVERY_TTL_MS) {
      return discovery.endpoints
    }
    if (provider.authorizationEndpoint !== undefined && provider.tokenEndpoint !== undefined) {
      const endpoints = {
        resource: provider.resource,
        authorizationEndpoint: provider.authorizationEndpoint,
        tokenEndpoint: provider.tokenEndpoint,
        registrationEndpoint: provider.registrationEndpoint,
        scopes: provider.scopes,
      }
      discovery = { at: Date.now(), endpoints }
      return endpoints
    }
    const resourceMetadata = await discoverResource(provider.url)
    const issuer = provider.issuer ?? resourceMetadata?.authorizationServers?.[0]
    if (issuer === undefined) {
      throw new Error(`no OAuth metadata found for ${provider.url}; set authorizationEndpoint/tokenEndpoint in config`)
    }
    const server = await discoverAuthorizationServer(issuer)
    const endpoints = {
      resource: provider.resource ?? resourceMetadata?.resource ?? provider.url,
      authorizationEndpoint: provider.authorizationEndpoint ?? server.authorizationEndpoint,
      tokenEndpoint: provider.tokenEndpoint ?? server.tokenEndpoint,
      registrationEndpoint: provider.registrationEndpoint ?? server.registrationEndpoint,
      scopes: provider.scopes
        ?? (resourceMetadata?.scopesSupported ?? server.scopesSupported)?.join(' '),
    }
    discovery = { at: Date.now(), endpoints }
    return endpoints
  }

  /**
   * Return a client for this loopback redirect: a configured one, a stored
   * registration, or a fresh dynamic registration.
   * @param {object} endpoints - Resolved endpoints.
   * @returns {Promise<object>} Client payload.
   */
  async function ensureClient(endpoints) {
    if (provider.clientId !== undefined) {
      return { clientId: provider.clientId, ...(provider.clientSecret === undefined ? {} : { clientSecret: provider.clientSecret }) }
    }
    const existing = await readRecord(clientKey)
    if (existing !== undefined
      && typeof existing.clientId === 'string'
      && existing.redirectUri === provider.redirectUri) {
      return existing
    }
    if (endpoints.registrationEndpoint === undefined) {
      throw new Error('the authorization server offers no dynamic client registration; set clientId in config')
    }
    const created = await registerClient({
      registrationEndpoint: endpoints.registrationEndpoint,
      redirectUri: provider.redirectUri,
      scopes: endpoints.scopes,
      clientName: provider.clientName,
    })
    const payload = {
      type: 'oauth-client',
      clientId: created.clientId,
      ...(created.clientSecret === undefined ? {} : { clientSecret: created.clientSecret }),
      redirectUri: provider.redirectUri,
      registrationEndpoint: endpoints.registrationEndpoint,
      createdAt: new Date().toISOString(),
    }
    await writeRecord(clientKey, payload)
    return payload
  }

  /**
   * Exchange the refresh token for a new access token when the stored one is
   * close to expiry (or when forced).
   * @param {boolean} [force] - Refresh regardless of the remaining lifetime.
   * @returns {Promise<void>} Resolves after the attempt settles.
   */
  async function rotate(force = false) {
    const tokens = await readRecord(tokensKey)
    if (tokens === undefined || typeof tokens.refresh !== 'string' || typeof tokens.access !== 'string') {
      status = { state: 'signed-out' }
      return
    }
    const expiresAt = Number(tokens.expiresAt)
    if (!force && Number.isFinite(expiresAt) && expiresAt - Date.now() > REFRESH_LEEWAY_MS) {
      await ensurePublished(tokens.access)
      return
    }
    const client = await readRecord(clientKey)
    const clientId = provider.clientId ?? client?.clientId
    if (typeof clientId !== 'string') {
      throw new Error('stored grant has no client registration; sign in again')
    }
    const clientSecret = provider.clientSecret ?? (typeof client?.clientSecret === 'string' ? client.clientSecret : undefined)
    const endpoints = await resolveEndpoints()
    try {
      const next = await refreshAccessToken({
        tokenEndpoint: endpoints.tokenEndpoint,
        clientId,
        clientSecret,
        refresh: tokens.refresh,
        resource: endpoints.resource,
      })
      const merged = {
        type: 'oauth-tokens',
        access: next.access,
        refresh: next.refresh ?? tokens.refresh,
        expiresAt: Date.now() + next.expiresIn * 1000,
        ...(next.scope === undefined ? {} : { scope: next.scope }),
        tokenType: next.tokenType,
        obtainedAt: new Date().toISOString(),
      }
      await writeRecord(tokensKey, merged)
      await publish(merged.access)
      status = { state: 'authorized' }
      ctx.logger.info(`dsh-mcp-oauth(${provider.id}): access token refreshed`)
    } catch (error) {
      if (error?.code === 'invalid_grant' || error?.code === 'invalid_token' || error?.code === 'unauthorized_client') {
        await clearGrant()
        status = { state: 'signed-out', error: `refresh rejected: ${messageOf(error)}` }
        ctx.logger.warn(`dsh-mcp-oauth(${provider.id}): ${status.error}; sign in again with the mcp_oauth tool`)
        return
      }
      status = { state: 'error', error: messageOf(error) }
      ctx.logger.warn(`dsh-mcp-oauth(${provider.id}): refresh failed: ${status.error}`)
    }
  }

  /**
   * Reuse a stored grant at startup: publish a live token, or refresh one that
   * is about to expire.
   * @returns {Promise<void>} Resolves after the attempt settles.
   */
  async function bootstrap() {
    const tokens = await readRecord(tokensKey)
    if (tokens === undefined || typeof tokens.access !== 'string') {
      status = { state: 'signed-out' }
      return
    }
    const expiresAt = Number(tokens.expiresAt)
    if (Number.isFinite(expiresAt) && expiresAt - Date.now() > REFRESH_LEEWAY_MS) {
      await ensurePublished(tokens.access)
      return
    }
    await rotate(true)
  }

  /**
   * Start (or join) the browser sign-in flow. The tool returns immediately; the
   * loopback listener finishes the exchange in the background.
   * @returns {Promise<{ url: string }>} Authorization URL.
   */
  async function startSignIn() {
    if (activeFlow !== undefined) return { url: activeFlow.url }
    const endpoints = await resolveEndpoints()
    const client = await ensureClient(endpoints)
    const { verifier, challenge } = createPkce()
    const state = createState()
    const listener = await listenForCallback({
      port: provider.redirectPort,
      state,
      timeoutMs: SIGN_IN_TIMEOUT_MS,
    })
    const url = buildAuthorizeUrl({
      authorizationEndpoint: endpoints.authorizationEndpoint,
      clientId: String(client.clientId),
      redirectUri: provider.redirectUri,
      scopes: endpoints.scopes,
      state,
      challenge,
      resource: endpoints.resource,
    })
    activeFlow = { url }
    openBrowser(url)
    void (async () => {
      try {
        const { code } = await listener.result
        const grant = await exchangeCode({
          tokenEndpoint: endpoints.tokenEndpoint,
          clientId: String(client.clientId),
          clientSecret: typeof client.clientSecret === 'string' ? client.clientSecret : undefined,
          code,
          redirectUri: provider.redirectUri,
          verifier,
          resource: endpoints.resource,
        })
        const stored = {
          type: 'oauth-tokens',
          access: grant.access,
          ...(grant.refresh === undefined ? {} : { refresh: grant.refresh }),
          expiresAt: Date.now() + grant.expiresIn * 1000,
          ...(grant.scope === undefined ? {} : { scope: grant.scope }),
          tokenType: grant.tokenType,
          obtainedAt: new Date().toISOString(),
        }
        await writeRecord(tokensKey, stored)
        await publish(stored.access)
        status = { state: 'authorized' }
        ctx.logger.info(`dsh-mcp-oauth(${provider.id}): signed in; the MCP server will reconnect`)
      } catch (error) {
        status = { state: 'signed-out', error: messageOf(error) }
        ctx.logger.warn(`dsh-mcp-oauth(${provider.id}): sign-in failed: ${status.error}`)
      } finally {
        activeFlow = undefined
        await listener.close()
      }
    })()
    return { url }
  }

  /**
   * Describe the current authorization without exposing the token.
   * @param {string} action - Invoked action.
   * @returns {Promise<Record<string, unknown>>} Tool result fields.
   */
  async function describeState(action) {
    const tokens = await readRecord(tokensKey)
    const info = await credentials.describe(provider.tokenRef)
    const expiresAt = Number(tokens?.expiresAt)
    const signedIn = typeof tokens?.access === 'string' && info.configured
    return {
      action,
      provider: provider.id,
      serverName: provider.serverName,
      tokenRef: provider.tokenRef,
      signedIn,
      credentialConfigured: info.configured,
      expiresAt: Number.isFinite(expiresAt) ? new Date(expiresAt).toISOString() : null,
      remainingSeconds: Number.isFinite(expiresAt)
        ? Math.max(0, Math.round((expiresAt - Date.now()) / 1000))
        : null,
      authorizeUrl: activeFlow?.url ?? null,
      error: signedIn ? null : (status.error ?? null),
    }
  }

  return {
    provider,
    bootstrap,
    probeEndpoints: resolveEndpoints,
    describe: describeState,
    startSignIn,
    clearGrant,
    async tick() {
      await rotate(false)
    },
  }
}

/**
 * Register the MCP servers the plugin manages, when the MCP manager is mounted.
 * @param {import('@deepseek-ai/cordis').Context} ctx - Plugin context.
 * @param {object[]} providers - Resolved providers.
 * @returns {void}
 */
function registerServers(ctx, providers) {
  ctx.inject(['mcpManager'], (managerCtx) => {
    managerCtx.effect(() => {
      const disposers = []
      for (const provider of providers) {
        if (!provider.register) continue
        const headers = { ...provider.headers }
        if (Object.keys(headers).every((header) => header.toLowerCase() !== 'authorization')) {
          headers.Authorization = `Bearer \${credential:${provider.tokenRef}}`
        }
        try {
          disposers.push(managerCtx.mcpManager.register(provider.serverName, {
            transport: 'streamable-http',
            url: provider.url,
            headers,
            ...(provider.toolCallTimeoutMs === undefined ? {} : { toolCallTimeoutMs: provider.toolCallTimeoutMs }),
            ...(provider.startupTimeoutMs === undefined ? {} : { startupTimeoutMs: provider.startupTimeoutMs }),
          }))
        } catch (error) {
          ctx.logger.warn(`dsh-mcp-oauth(${provider.id}): could not register MCP server: ${messageOf(error)}`)
        }
      }
      return () => {
        for (const dispose of disposers.reverse()) dispose()
      }
    }, 'dsh-mcp-oauth: server registration')
  })
}

/**
 * Register the sign-in tool and start each provider's refresh loop.
 * @param {import('@deepseek-ai/cordis').Context} ctx - Plugin context.
 * @param {Record<string, unknown> | undefined} config - Plugin row config.
 * @returns {void}
 */
export function apply(ctx, config) {
  const providers = resolveProviders(config)
  if (providers.length === 0) {
    ctx.logger.info('dsh-mcp-oauth: no providers configured; set config.providers to connect an MCP server')
    return
  }
  const engines = providers.map((provider) => createEngine(ctx, provider))
  const byId = new Map(engines.map((engine) => [engine.provider.id, engine]))
  const ids = engines.map((engine) => engine.provider.id)

  const tool = {
    name: 'mcp_oauth',
    description:
      'Report or start the OAuth sign-in for a configured MCP server. MCP servers that accept only a bearer '
      + `token need one; configured providers: ${ids.join(', ')}. Reports whether a managed grant exists, opens `
      + 'the sign-in page in the browser when asked to sign in, and signs out on request. Never prints the token.',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        provider: {
          type: 'string',
          enum: ids,
          description: ids.length === 1 ? `Configured provider (${ids[0]}).` : 'Configured provider.',
        },
        action: {
          type: 'string',
          enum: ['status', 'sign_in', 'sign_out'],
          description: 'status reports the grant; sign_in opens the browser sign-in; sign_out removes the stored grant.',
        },
      },
    },
    output: {
      schema: { type: 'object' },
      render(_args, value) {
        if (value.action === 'sign_in' && value.authorizeUrl !== null) {
          return [{
            type: 'text',
            text: `Sign-in to ${value.provider} started. Finish it in the browser page that opened (${value.authorizeUrl}) and the MCP server will come up on its own.`,
          }]
        }
        if (value.action === 'sign_out') {
          return [{ type: 'text', text: `Signed out of ${value.provider}; the stored grant and bearer token were removed.` }]
        }
        const lifetime = value.remainingSeconds === null
          ? 'no managed grant'
          : `token valid for about ${Math.round(value.remainingSeconds / 60)} more minutes`
        return [{
          type: 'text',
          text: value.signedIn
            ? `${value.provider}: signed in; ${lifetime}.`
            : `${value.provider}: not signed in (${value.error ?? 'no stored grant'}). `
              + `Call mcp_oauth with provider "${value.provider}" and action "sign_in".`,
        }]
      },
    },
    async execute(args) {
      const requested = typeof args?.provider === 'string' ? args.provider : ids[0]
      const engine = byId.get(requested)
      if (engine === undefined) throw new Error(`unknown MCP OAuth provider "${requested}"; configured: ${ids.join(', ')}`)
      const action = typeof args?.action === 'string' ? args.action : 'status'
      if (action === 'sign_in') {
        const { url } = await engine.startSignIn()
        const described = await engine.describe('sign_in')
        return { ...described, authorizeUrl: url, signedIn: false }
      }
      if (action === 'sign_out') {
        await engine.clearGrant()
        return { ...(await engine.describe('sign_out')), signedIn: false, credentialConfigured: false }
      }
      return engine.describe('status')
    },
  }

  ctx.effect(() => {
    let stopped = false
    const disposers = [ctx.tools.register(tool)]
    const timer = setInterval(() => {
      if (stopped) return
      for (const engine of engines) {
        void engine.tick().catch((error) => {
          ctx.logger.warn(`dsh-mcp-oauth: scheduled refresh failed: ${messageOf(error)}`)
        })
      }
    }, REFRESH_INTERVAL_MS)
    timer.unref?.()
    disposers.push(() => clearInterval(timer))
    for (const engine of engines) {
      void engine.bootstrap().catch((error) => {
        if (stopped) return
        ctx.logger.warn(`dsh-mcp-oauth(${engine.provider.id}): startup check failed: ${messageOf(error)}`)
      })
    }
    return () => {
      stopped = true
      for (const dispose of disposers.reverse()) dispose()
    }
  })

  registerServers(ctx, providers)
}
