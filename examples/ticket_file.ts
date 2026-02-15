import { GatewayClient, GatewayPublicKey, TokenClass, FileTicketSource, ChatMessage } from '../src/index.js';

async function main() {
  const endpoint = process.env.GATEWAY_URL ?? 'https://api.gateway.example.com';
  const pkB64 = process.env.GATEWAY_PUBLIC_KEY_B64 ?? '';
  if (!pkB64) throw new Error('missing GATEWAY_PUBLIC_KEY_B64');

  const tickets = await FileTicketSource.fromPath('./examples/tickets.sample.json');

  const client = new GatewayClient(endpoint, GatewayPublicKey.fromBase64(pkB64), tickets);

  const resp = await client.chatCompletions(TokenClass.C1024, {
    model: process.env.MODEL ?? 'gpt-4o-mini',
    messages: [
      ChatMessage.system('You are a helpful assistant.'),
      ChatMessage.user('Give me a one-sentence summary of what this SDK does.'),
    ],
  });

  console.log(resp.choices?.[0]?.message?.content ?? '');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
