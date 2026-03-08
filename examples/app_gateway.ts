import { AppGatewayConfig } from '../src/index.js';

async function main() {
  const prompt = process.argv[2] ?? process.env.PROMPT ?? 'Explain how token classes reduce size leakage.';
  const systemPrompt = process.env.SYSTEM_PROMPT ?? 'You are a helpful assistant.';

  const gateway = await AppGatewayConfig.fromEnv().build();
  const answer = await gateway.askWithSystem(systemPrompt, prompt);

  console.log(answer);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
