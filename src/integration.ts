import { GatewayClient, GatewayClientConfig } from './client.js';
import { GatewayPublicKey } from './crypto.js';
import { ProtocolError } from './errors.js';
import { ChatCompletionsResponse, ChatMessage } from './openaiTypes.js';
import { DummyTicketSource, FileTicketSource, TicketSource } from './tickets.js';
import { parseTokenClass, TokenClass } from './tokenClass.js';

export const GATEWAY_INFER_PATH = '/v1/infer';
export const RELAY_INFER_PATH = '/relay';

export class TicketSourceConfig {
  private constructor(
    public readonly kind: 'dummy' | 'file',
    public readonly path?: string,
  ) {}

  static dummy(): TicketSourceConfig {
    return new TicketSourceConfig('dummy');
  }

  static file(path: string): TicketSourceConfig {
    return new TicketSourceConfig('file', path);
  }

  async load(): Promise<TicketSource> {
    if (this.kind === 'dummy') return new DummyTicketSource();
    if (this.kind === 'file' && this.path) return FileTicketSource.fromPath(this.path);
    throw new ProtocolError('ticket source config must be dummy or file(path)');
  }
}

type EnvMap = Record<string, string | undefined>;

export class AppGatewayConfig {
  constructor(
    public readonly endpoint: string,
    public readonly gatewayPk: GatewayPublicKey,
    public readonly tickets: TicketSourceConfig,
    public readonly model: string,
    public readonly tokenClass: TokenClass,
    public readonly inferPath: string = GATEWAY_INFER_PATH,
    public readonly authBearer?: string,
    public readonly temperature?: number,
    public readonly timeoutMs: number = 60_000,
  ) {}

  static fromEnv(env: EnvMap = process.env): AppGatewayConfig {
    const endpoint = requiredEnv(env, 'GATEWAY_BASE_URL', 'GATEWAY_URL');
    const pkB64 = requiredEnv(env, 'GATEWAY_PUBLIC_KEY_B64');
    const gatewayPk = GatewayPublicKey.fromBase64(pkB64);

    const useRelay = env.GATEWAY_USE_RELAY ? parseBool(env.GATEWAY_USE_RELAY, 'GATEWAY_USE_RELAY') : false;
    const inferPath = env.GATEWAY_INFER_PATH ?? (useRelay ? RELAY_INFER_PATH : GATEWAY_INFER_PATH);

    let tickets: TicketSourceConfig;
    if (env.GATEWAY_TICKETS_JSON || env.TICKETS_JSON) {
      tickets = TicketSourceConfig.file((env.GATEWAY_TICKETS_JSON ?? env.TICKETS_JSON)!);
    } else if (env.GATEWAY_USE_DUMMY_TICKETS) {
      if (parseBool(env.GATEWAY_USE_DUMMY_TICKETS, 'GATEWAY_USE_DUMMY_TICKETS')) {
        tickets = TicketSourceConfig.dummy();
      } else {
        throw new ProtocolError('set GATEWAY_TICKETS_JSON or GATEWAY_USE_DUMMY_TICKETS=true');
      }
    } else {
      throw new ProtocolError('set GATEWAY_TICKETS_JSON or GATEWAY_USE_DUMMY_TICKETS=true');
    }

    const model = env.GATEWAY_MODEL ?? env.MODEL ?? 'gpt-4o-mini';
    const tokenClass = env.GATEWAY_TOKEN_CLASS || env.TOKEN_CLASS
      ? parseTokenClass(env.GATEWAY_TOKEN_CLASS ?? env.TOKEN_CLASS ?? '')
      : TokenClass.C2048;
    const temperature = env.GATEWAY_TEMPERATURE ? parseNumber(env.GATEWAY_TEMPERATURE, 'GATEWAY_TEMPERATURE') : undefined;
    const timeoutMs = env.GATEWAY_TIMEOUT_SECS
      ? parseNumber(env.GATEWAY_TIMEOUT_SECS, 'GATEWAY_TIMEOUT_SECS') * 1000
      : 60_000;

    return new AppGatewayConfig(
      endpoint,
      gatewayPk,
      tickets,
      model,
      tokenClass,
      inferPath,
      env.GATEWAY_AUTH_BEARER,
      temperature,
      timeoutMs,
    );
  }

  useGatewayPath(): AppGatewayConfig {
    return new AppGatewayConfig(
      this.endpoint,
      this.gatewayPk,
      this.tickets,
      this.model,
      this.tokenClass,
      GATEWAY_INFER_PATH,
      this.authBearer,
      this.temperature,
      this.timeoutMs,
    );
  }

  useRelayPath(): AppGatewayConfig {
    return new AppGatewayConfig(
      this.endpoint,
      this.gatewayPk,
      this.tickets,
      this.model,
      this.tokenClass,
      RELAY_INFER_PATH,
      this.authBearer,
      this.temperature,
      this.timeoutMs,
    );
  }

  withAuthBearer(authBearer: string): AppGatewayConfig {
    return new AppGatewayConfig(
      this.endpoint,
      this.gatewayPk,
      this.tickets,
      this.model,
      this.tokenClass,
      this.inferPath,
      authBearer,
      this.temperature,
      this.timeoutMs,
    );
  }

  withTemperature(temperature: number): AppGatewayConfig {
    return new AppGatewayConfig(
      this.endpoint,
      this.gatewayPk,
      this.tickets,
      this.model,
      this.tokenClass,
      this.inferPath,
      this.authBearer,
      temperature,
      this.timeoutMs,
    );
  }

  withTimeoutMs(timeoutMs: number): AppGatewayConfig {
    return new AppGatewayConfig(
      this.endpoint,
      this.gatewayPk,
      this.tickets,
      this.model,
      this.tokenClass,
      this.inferPath,
      this.authBearer,
      this.temperature,
      timeoutMs,
    );
  }

  async build(): Promise<AppGateway> {
    const clientConfig: GatewayClientConfig = {
      inferPath: this.inferPath,
      authBearer: this.authBearer,
      timeoutMs: this.timeoutMs,
    };

    const client = new GatewayClient(
      this.endpoint,
      this.gatewayPk,
      await this.tickets.load(),
      clientConfig,
    );

    return new AppGateway(client, this.model, this.tokenClass, this.temperature);
  }
}

export class AppChatRequest {
  constructor(
    public readonly messages: ChatMessage[],
    public readonly systemPrompt?: string,
    public readonly model?: string,
    public readonly tokenClass?: TokenClass,
    public readonly temperature?: number,
  ) {}

  static fromUserPrompt(userPrompt: string): AppChatRequest {
    return new AppChatRequest([ChatMessage.user(userPrompt)]);
  }

  withSystemPrompt(systemPrompt: string): AppChatRequest {
    return new AppChatRequest(this.messages, systemPrompt, this.model, this.tokenClass, this.temperature);
  }

  withModel(model: string): AppChatRequest {
    return new AppChatRequest(this.messages, this.systemPrompt, model, this.tokenClass, this.temperature);
  }

  withTokenClass(tokenClass: TokenClass): AppChatRequest {
    return new AppChatRequest(this.messages, this.systemPrompt, this.model, tokenClass, this.temperature);
  }

  withTemperature(temperature: number): AppChatRequest {
    return new AppChatRequest(this.messages, this.systemPrompt, this.model, this.tokenClass, temperature);
  }
}

export class AppGateway {
  constructor(
    public readonly client: GatewayClient,
    public readonly defaultModel: string,
    public readonly defaultTokenClass: TokenClass,
    public readonly defaultTemperature?: number,
  ) {}

  async ask(userPrompt: string): Promise<string> {
    const response = await this.chat(AppChatRequest.fromUserPrompt(userPrompt));
    return response.choices?.[0]?.message?.content ?? '';
  }

  async askWithSystem(systemPrompt: string, userPrompt: string): Promise<string> {
    const response = await this.chat(AppChatRequest.fromUserPrompt(userPrompt).withSystemPrompt(systemPrompt));
    return response.choices?.[0]?.message?.content ?? '';
  }

  async chat(request: AppChatRequest): Promise<ChatCompletionsResponse> {
    if (!request.messages.length) {
      throw new ProtocolError('chat request must include at least one message');
    }

    const messages = request.systemPrompt
      ? [ChatMessage.system(request.systemPrompt), ...request.messages]
      : [...request.messages];

    return this.client.chatCompletions(request.tokenClass ?? this.defaultTokenClass, {
      model: request.model ?? this.defaultModel,
      messages,
      temperature: request.temperature ?? this.defaultTemperature,
      stream: false,
    });
  }
}

function requiredEnv(env: EnvMap, ...keys: string[]): string {
  for (const key of keys) {
    const value = env[key];
    if (value && value.trim()) return value;
  }
  throw new ProtocolError(`missing environment variable; set one of ${keys.join(', ')}`);
}

function parseBool(raw: string, key: string): boolean {
  const value = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(value)) return true;
  if (['0', 'false', 'no', 'off'].includes(value)) return false;
  throw new ProtocolError(`${key} must be one of true/false/1/0/yes/no/on/off`);
}

function parseNumber(raw: string, key: string): number {
  const value = Number(raw.trim());
  if (!Number.isFinite(value)) {
    throw new ProtocolError(`${key} must be numeric`);
  }
  return value;
}
