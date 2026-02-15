import { Envelope, GatewayPublicKey, openJson, sealJson } from './crypto.js';
import { GatewayError, HttpError, ProtocolError } from './errors.js';
import { ChatCompletionsRequest, ChatCompletionsResponse } from './openaiTypes.js';
import { TicketSource, ZkTicket } from './tickets.js';
import { maxOutputTokensHint, TokenClass } from './tokenClass.js';

export interface GatewayClientConfig {
  /** Path for the encrypted infer endpoint. */
  inferPath?: string;
  /** Optional bearer token (enterprise / account mode). */
  authBearer?: string;
  /** Additional headers. */
  headers?: Record<string, string>;
  /** Timeout in milliseconds. */
  timeoutMs?: number;
  /** Fetch implementation (defaults to global fetch). */
  fetchImpl?: typeof fetch;
}

function joinUrl(base: string, path: string): string {
  const b = base.endsWith('/') ? base : `${base}/`;
  const p = path.startsWith('/') ? path.slice(1) : path;
  return new URL(p, b).toString();
}

export class GatewayClient {
  readonly inferUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(
    public readonly endpoint: string,
    public readonly gatewayPk: GatewayPublicKey,
    public readonly tickets: TicketSource,
    public readonly config: GatewayClientConfig = {},
  ) {
    this.inferUrl = joinUrl(endpoint, config.inferPath ?? '/v1/infer');
    this.fetchImpl = config.fetchImpl ?? fetch;
    if (!this.fetchImpl) {
      throw new Error('No fetch implementation available. Use Node 18+ or pass config.fetchImpl.');
    }
  }

  async inferJson(tokenClass: TokenClass, upstream: unknown): Promise<unknown> {
    const ticket = await this.tickets.nextTicket(tokenClass);
    return this.inferJsonWithTicket(tokenClass, ticket, upstream);
  }

  async inferJsonWithTicket(tokenClass: TokenClass, ticket: ZkTicket, upstream: unknown): Promise<unknown> {
    const payload = {
      token_class: tokenClass,
      ticket,
      upstream,
    };

    const { envelope, state } = sealJson(this.gatewayPk, tokenClass, payload);

    const headers: Record<string, string> = {
      accept: 'application/json',
      'content-type': 'application/json',
      ...(this.config.headers ?? {}),
    };

    if (this.config.authBearer) {
      headers['authorization'] = `Bearer ${this.config.authBearer}`;
    }

    const ctrl = new AbortController();
    const timeoutMs = this.config.timeoutMs ?? 60_000;
    const to = setTimeout(() => ctrl.abort(), timeoutMs);

    let resp: Response;
    try {
      resp = await this.fetchImpl(this.inferUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(envelope),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(to);
    }

    const status = resp.status;

    let respJson: unknown;
    try {
      respJson = await resp.json();
    } catch {
      const snippet = (await resp.text().catch(() => ''))?.slice(0, 500) ?? '';
      throw new ProtocolError(`failed to parse envelope (HTTP ${status}): ${snippet}`);
    }

    const respEnv = respJson as Envelope;
    const decrypted = openJson(respEnv, state);

    if (decrypted && typeof decrypted === 'object' && 'error' in (decrypted as any)) {
      const err = (decrypted as any).error ?? {};
      const code = String(err.code ?? 'gateway_error');
      const msg = String(err.message ?? 'unknown error');
      throw new GatewayError(code, msg);
    }

    if (status < 200 || status >= 300) {
      throw new HttpError(status, `gateway returned HTTP ${status}`);
    }

    if (!decrypted || typeof decrypted !== 'object' || !('upstream' in (decrypted as any))) {
      throw new ProtocolError("missing 'upstream' field in decrypted gateway response");
    }

    return (decrypted as any).upstream;
  }

  async chatCompletions(tokenClass: TokenClass, req: ChatCompletionsRequest): Promise<ChatCompletionsResponse> {
    if (req.max_tokens === undefined || req.max_tokens === null) {
      req.max_tokens = maxOutputTokensHint(tokenClass);
    }

    const upstream = {
      path: '/v1/chat/completions',
      method: 'POST',
      body: req,
    };

    const respJson = await this.inferJson(tokenClass, upstream);

    const body =
      respJson && typeof respJson === 'object' && 'body' in (respJson as any) ? (respJson as any).body : respJson;

    if (!body || typeof body !== 'object') {
      throw new ProtocolError('unexpected upstream response type');
    }

    return body as ChatCompletionsResponse;
  }
}
