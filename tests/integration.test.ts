import { describe, expect, it } from 'vitest';

import { AppChatRequest, AppGateway, AppGatewayConfig, ChatMessage, RELAY_INFER_PATH, TicketSourceConfig, TokenClass } from '../src/index.js';

describe('integration helpers', () => {
  it('parses env into app gateway config', () => {
    const config = AppGatewayConfig.fromEnv({
      GATEWAY_URL: 'https://proxy.example.com',
      GATEWAY_PUBLIC_KEY_B64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      GATEWAY_USE_DUMMY_TICKETS: 'true',
      GATEWAY_USE_RELAY: 'true',
      MODEL: 'gpt-4o-mini',
      TOKEN_CLASS: 'c1024',
      GATEWAY_TEMPERATURE: '0.2',
      GATEWAY_TIMEOUT_SECS: '30',
    });

    expect(config.endpoint).toBe('https://proxy.example.com');
    expect(config.inferPath).toBe(RELAY_INFER_PATH);
    expect(config.model).toBe('gpt-4o-mini');
    expect(config.tokenClass).toBe(TokenClass.C1024);
    expect(config.temperature).toBe(0.2);
    expect(config.timeoutMs).toBe(30_000);
    expect(config.tickets).toEqual(TicketSourceConfig.dummy());
  });

  it('builds app chat requests', () => {
    const request = AppChatRequest.fromUserPrompt('hello')
      .withSystemPrompt('system')
      .withModel('gpt-4o-mini')
      .withTokenClass(TokenClass.C512)
      .withTemperature(0.1);

    expect(request.messages).toHaveLength(1);
    expect(request.messages[0]?.role).toBe('user');
    expect(request.systemPrompt).toBe('system');
    expect(request.model).toBe('gpt-4o-mini');
    expect(request.tokenClass).toBe(TokenClass.C512);
    expect(request.temperature).toBe(0.1);
  });

  it('applies defaults and system prompts when chatting', async () => {
    const captured: Record<string, unknown> = {};

    const gateway = new AppGateway(
      {
        chatCompletions: async (tokenClass: TokenClass, request: any) => {
          captured.tokenClass = tokenClass;
          captured.request = request;
          return {
            id: 'resp-1',
            model: request.model,
            choices: [
              {
                index: 0,
                message: ChatMessage.assistant('hello from stub'),
                finish_reason: 'stop',
              },
            ],
          };
        },
      } as any,
      'gpt-4o-mini',
      TokenClass.C2048,
      0.2,
    );

    const answer = await gateway.askWithSystem('system', 'hello');

    expect(answer).toBe('hello from stub');
    expect(captured.tokenClass).toBe(TokenClass.C2048);
    expect(captured.request).toEqual({
      model: 'gpt-4o-mini',
      messages: [
        ChatMessage.system('system'),
        ChatMessage.user('hello'),
      ],
      temperature: 0.2,
      stream: false,
    });
  });
});
