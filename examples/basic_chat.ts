import { GatewayClient, GatewayPublicKey, TokenClass, DummyTicketSource, ChatMessage } from '../src/index.js';

async function main() {
  const endpoint = process.env.GATEWAY_URL ?? 'https://api.gateway.example.com';
  const pkB64 = process.env.GATEWAY_PUBLIC_KEY_B64 ?? '';
  if (!pkB64) throw new Error('missing GATEWAY_PUBLIC_KEY_B64');

  const gatewayPk = GatewayPublicKey.fromBase64(pkB64);
  const tickets = new DummyTicketSource();
  const client = new GatewayClient(endpoint, gatewayPk, tickets);

  const resp = await client.chatCompletions(TokenClass.C2048, {
    model: process.env.MODEL ?? 'gpt-4o-mini',
    messages: [
      ChatMessage.system('You are a helpful assistant.'),
      ChatMessage.user('Write a haiku about privacy-preserving payments.'),
    ],
    temperature: 0.2,
  });

  console.log(resp.choices?.[0]?.message?.content ?? '');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
