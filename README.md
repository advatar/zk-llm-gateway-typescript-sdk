# ZK LLM Gateway SDK (TypeScript)

TypeScript/Node SDK for the **ZK LLM Gateway**: **end-to-end encrypted envelopes**, **token-class padding**, and **ZK-ready usage tickets** for metered LLM inference.

This SDK is designed for calling a **hosted commercial gateway** (or a self-hosted gateway that implements the same wire format).
It helps you avoid identity-linked per-user API keys by supporting **unlinkable “ticket” spends** (nullifier-based anti-replay),
while also reducing metadata leakage via fixed-size padding.

> ⚠️ Privacy note (important):
> - This SDK protects prompts/responses from **relays/intermediaries** (ciphertext only) and reduces size fingerprinting.
> - It **does not** magically prevent the upstream LLM provider from correlating requests via the **content you send** or timing.
> - For long personal-agent chats, keep long-term memory local and send minimized context.

## Features

- **Envelope encryption**: X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (client → gateway)
- **Token classes**: coarse buckets (`c256`, `c512`, `c1024`, `c2048`, `c4096`) that map to fixed padded byte sizes
- **ZK-ready tickets**: pluggable ticket source (`DummyTicketSource`, `FileTicketSource`, or your own)
- **OpenAI Chat Completions helper**: convenience method that forwards OpenAI-compatible requests through `/v1/infer`
- **Optional redaction utilities**: redact obvious identifiers (emails, phone numbers, ETH addresses, API keys) before sending prompts

## Requirements

- Node.js **18+**

This SDK uses Node’s `crypto` implementation for X25519 and ChaCha20-Poly1305.

## Install

From GitHub (replace org/repo):

```bash
npm install zk-llm-gateway-sdk
# or
npm install "zk-llm-gateway-sdk@github:your-org/zk-llm-gateway-typescript-sdk"
```

## Quickstart (Chat Completions)

Set environment variables:

- `GATEWAY_URL` – e.g. `https://api.gateway.example.com`
- `GATEWAY_PUBLIC_KEY_B64` – base64 X25519 public key for the gateway
- *(optional)* `MODEL` – e.g. `gpt-4o-mini`

```ts
import { GatewayClient, GatewayPublicKey, TokenClass, DummyTicketSource, ChatMessage } from 'zk-llm-gateway-sdk';

const endpoint = process.env.GATEWAY_URL ?? 'https://api.gateway.example.com';
const pkB64 = process.env.GATEWAY_PUBLIC_KEY_B64!;

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
```

## Ticket sources

### Dummy tickets (dev only)

```ts
const tickets = new DummyTicketSource();
```

### Ticket pack file (JSON array)

```ts
import { FileTicketSource } from 'zk-llm-gateway-sdk';

const tickets = await FileTicketSource.fromPath('./tickets.json');
```

File format:

```json
[
  {
    "commitment_root": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "nullifier": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    "token_class": "c2048",
    "proof": ""
  }
]
```

## Wire format (high level)

The SDK sends:

1. A plaintext JSON payload:
   ```json
   {
     "request_id": "6f0f8bc0-87de-4a8c-bad2-5f4f08c6c3d9",
     "model": "gpt-4o-mini",
     "messages": [{ "role": "user", "content": "hello" }],
     "max_tokens": 256,
     "temperature": 0.2,
     "token_class": "c2048",
     "ticket": {
       "commitment_root": "...",
       "nullifier": "...",
       "token_class": "c2048",
       "proof": "..."
     }
   }
   ```

2. Pads it to a fixed size for the chosen token class.

3. Encrypts it into an **Envelope**:
   ```json
   {
     "v": 1,
     "token_class": "c2048",
     "eph_pubkey_b64": "...",
     "nonce_b64": "...",
     "ciphertext_b64": "..."
   }
   ```

The gateway returns an encrypted envelope response (and typically echoes the same `eph_pubkey_b64`).

## Redaction helpers

Redaction is optional but useful to prevent accidental leakage of obvious identifiers.

```ts
import { Redactor, RedactionMode } from 'zk-llm-gateway-sdk';

const redactor = new Redactor(RedactionMode.StablePerValue);
const res = redactor.redactText('Email me at alice@example.com (sk-verysecret...)');
console.log(res.redacted);
const restored = redactor.rehydrateText(res.redacted, res.map);
```

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## License

Apache-2.0
