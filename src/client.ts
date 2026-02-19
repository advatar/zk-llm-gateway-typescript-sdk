import * as crypto from 'node:crypto';

import { Envelope, GatewayPublicKey, normalizeEnvelope, openJson, sealJson } from './crypto.js';
import { GatewayError, HttpError, ProtocolError } from './errors.js';
import { ChatCompletionsRequest, ChatCompletionsResponse, ChatMessage } from './openaiTypes.js';
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

interface InferenceRequest {
  request_id: string;
  model: string;
  messages: ChatMessage[];
  max_tokens?: number;
  temperature?: number;
  token_class: TokenClass;
  ticket: ZkTicket;
}

interface InferenceResponse {
  request_id: string;
  model: string;
  output: string;
  billed_token_class: TokenClass;
}

interface ErrorResponse {
  code: string;
  message: string;
}

type GatewayEnvelopePayload =
  | { kind: 'ok'; response: InferenceResponse }
  | { kind: 'err'; error: ErrorResponse };

function joinUrl(base: string, path: string): string {
  const b = base.endsWith('/') ? base : `${base}/`;
  const p = path.startsWith('/') ? path.slice(1) : path;
  return new URL(p, b).toString();
}

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function parseChatRequest(input: unknown): ChatCompletionsRequest {
  if (isObject(input) && typeof input.model === 'string' && Array.isArray(input.messages)) {
    return input as ChatCompletionsRequest;
  }

  if (isObject(input) && input.path === '/v1/chat/completions' && isObject(input.body)) {
    return parseChatRequest(input.body);
  }

  throw new ProtocolError(
    "unsupported inferJson payload; expected chat request body or {path:'/v1/chat/completions', body:{...}}",
  );
}

function buildInferenceRequest(tokenClass: TokenClass, ticket: ZkTicket, req: ChatCompletionsRequest): InferenceRequest {
  return {
    request_id: crypto.randomUUID(),
    model: req.model,
    messages: req.messages,
    max_tokens: req.max_tokens,
    temperature: req.temperature,
    token_class: tokenClass,
    ticket,
  };
}

function parseGatewayPayload(decrypted: unknown): GatewayEnvelopePayload | undefined {
  if (!isObject(decrypted)) return undefined;
  if (decrypted.kind !== 'ok' && decrypted.kind !== 'err') return undefined;
  if (decrypted.kind === 'ok' && isObject(decrypted.response)) {
    return { kind: 'ok', response: decrypted.response as unknown as InferenceResponse };
  }
  if (decrypted.kind === 'err' && isObject(decrypted.error)) {
    return { kind: 'err', error: decrypted.error as unknown as ErrorResponse };
  }
  return undefined;
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
    if (ticket.token_class !== tokenClass) {
      throw new ProtocolError('ticket token_class must match requested token_class');
    }

    const chatReq = parseChatRequest(upstream);
    const payload = buildInferenceRequest(tokenClass, ticket, chatReq);

    const { envelope, state } = sealJson(this.gatewayPk, tokenClass, payload);

    const headers: Record<string, string> = {
      accept: 'application/json',
      'content-type': 'application/json',
      ...(this.config.headers ?? {}),
    };

    if (this.config.authBearer) {
      headers.authorization = `Bearer ${this.config.authBearer}`;
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

    let respEnv: Envelope;
    try {
      respEnv = normalizeEnvelope(respJson as any);
    } catch (e) {
      throw new ProtocolError(`invalid encrypted envelope: ${(e as Error).message}`);
    }

    const decrypted = openJson(respEnv, state);

    const payloadOut = parseGatewayPayload(decrypted);
    if (payloadOut?.kind === 'ok') {
      return payloadOut.response;
    }
    if (payloadOut?.kind === 'err') {
      throw new GatewayError(payloadOut.error.code ?? 'gateway_error', payloadOut.error.message ?? 'unknown error');
    }

    // Legacy SDK payload fallback.
    if (isObject(decrypted) && isObject(decrypted.error)) {
      const code = String((decrypted.error as any).code ?? 'gateway_error');
      const msg = String((decrypted.error as any).message ?? 'unknown error');
      throw new GatewayError(code, msg);
    }

    if (status < 200 || status >= 300) {
      throw new HttpError(status, `gateway returned HTTP ${status}`);
    }

    if (isObject(decrypted) && 'upstream' in decrypted) {
      return (decrypted as any).upstream;
    }

    throw new ProtocolError('missing response payload in decrypted gateway response');
  }

  async chatCompletions(tokenClass: TokenClass, req: ChatCompletionsRequest): Promise<ChatCompletionsResponse> {
    if (req.max_tokens === undefined || req.max_tokens === null) {
      req.max_tokens = maxOutputTokensHint(tokenClass);
    }

    const respJson = await this.inferJson(tokenClass, req);

    if (isObject(respJson) && typeof respJson.output === 'string' && typeof respJson.request_id === 'string') {
      const ir = respJson as unknown as InferenceResponse;
      return {
        id: ir.request_id,
        model: ir.model,
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: ir.output,
            },
            finish_reason: 'stop',
          },
        ],
        billed_token_class: ir.billed_token_class,
      } as ChatCompletionsResponse;
    }

    // Backward-compatible parsing for SDK-proxy responses.
    const body = isObject(respJson) && 'body' in respJson ? (respJson as any).body : respJson;
    if (!isObject(body)) {
      throw new ProtocolError('unexpected upstream response type');
    }

    return body as ChatCompletionsResponse;
  }
}
