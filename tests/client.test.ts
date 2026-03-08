import * as crypto from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { Envelope, GatewayPublicKey, normalizeEnvelope } from '../src/crypto.js';
import { GatewayClient } from '../src/client.js';
import { padPayload, unpadPayload } from '../src/padding.js';
import { randomDummyTicket } from '../src/tickets.js';
import { responsePaddedLen, tokenClassId, TokenClass } from '../src/tokenClass.js';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function x25519SpkiFromRaw(raw32: Uint8Array): Buffer {
  return Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw32)]);
}

function hkdfSha256(ikm: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  const prk = crypto.createHmac('sha256', Buffer.alloc(32, 0)).update(Buffer.from(ikm)).digest();
  const blocks: Buffer[] = [];
  let prev = Buffer.alloc(0);
  let counter = 1;

  while (Buffer.concat(blocks).length < len) {
    const h = crypto.createHmac('sha256', prk);
    h.update(prev);
    h.update(Buffer.from(info));
    h.update(Buffer.from([counter]));
    prev = h.digest();
    blocks.push(prev);
    counter += 1;
  }

  return Buffer.concat(blocks).subarray(0, len);
}

function deriveKey(sharedSecret: Uint8Array, tokenClass: TokenClass, direction: 1 | 2): Uint8Array {
  const prefix = Buffer.from('zk-llm-gateway-envelope-v1', 'ascii');
  const dir = direction === 1 ? Buffer.from('/req', 'ascii') : Buffer.from('/resp', 'ascii');
  return hkdfSha256(sharedSecret, Buffer.concat([prefix, dir, Buffer.from([tokenClassId(tokenClass)])]), 32);
}

function decryptRequestPayload(privateKey: crypto.KeyObject, input: Envelope): any {
  const envelope = normalizeEnvelope(input);
  const ephRaw = Buffer.from(envelope.eph_pubkey_b64, 'base64');
  const ephKey = crypto.createPublicKey({ key: x25519SpkiFromRaw(ephRaw), format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey, publicKey: ephKey });
  const reqKey = deriveKey(shared, envelope.token_class, 1);

  const nonce = Buffer.from(envelope.nonce_b64, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext_b64, 'base64');
  const aad = Buffer.from([envelope.v, tokenClassId(envelope.token_class), 1]);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', reqKey, nonce, { authTagLength: 16 });
  const ct = ciphertext.subarray(0, ciphertext.length - 16);
  const tag = ciphertext.subarray(ciphertext.length - 16);
  decipher.setAAD(aad, { plaintextLength: ct.length });
  decipher.setAuthTag(tag);
  const padded = Buffer.concat([decipher.update(ct), decipher.final()]);

  return JSON.parse(Buffer.from(unpadPayload(padded)).toString('utf8'));
}

function encryptResponsePayload(
  privateKey: crypto.KeyObject,
  requestEnvelope: Envelope,
  payload: unknown,
): Envelope {
  const ephRaw = Buffer.from(requestEnvelope.eph_pubkey_b64, 'base64');
  const ephKey = crypto.createPublicKey({ key: x25519SpkiFromRaw(ephRaw), format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({ privateKey, publicKey: ephKey });
  const respKey = deriveKey(shared, requestEnvelope.token_class, 2);

  const raw = Buffer.from(JSON.stringify(payload), 'utf8');
  const padded = padPayload(raw, responsePaddedLen(requestEnvelope.token_class));
  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from([requestEnvelope.v, tokenClassId(requestEnvelope.token_class), 2]);

  const cipher = crypto.createCipheriv('chacha20-poly1305', respKey, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: padded.length });
  const ct = Buffer.concat([cipher.update(padded), cipher.final(), cipher.getAuthTag()]);

  return {
    v: requestEnvelope.v,
    token_class: requestEnvelope.token_class,
    eph_pubkey_b64: requestEnvelope.eph_pubkey_b64,
    nonce_b64: nonce.toString('base64'),
    ciphertext_b64: ct.toString('base64'),
  };
}

describe('GatewayClient', () => {
  it('forwards passthrough request fields and reconstructs canonical upstream responses', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const gwRaw = spki.subarray(spki.length - 32);
    const gatewayPk = GatewayPublicKey.fromBase64(gwRaw.toString('base64'));
    const ticket = randomDummyTicket(TokenClass.C2048);

    const fetchImpl: typeof fetch = vi.fn(async (_input, init) => {
      const requestEnvelope = JSON.parse(String(init?.body)) as Envelope;
      const payload = decryptRequestPayload(privateKey, requestEnvelope);

      expect(payload.stream).toBe(false);
      expect(payload.top_p).toBe(0.1);
      expect(payload.response_format).toEqual({ type: 'json_object' });
      expect(payload.tools[0].function.name).toBe('lookup_weather');
      expect(payload.token_class).toBe('c2048');
      expect(payload.ticket.nullifier).toBe(ticket.nullifier);

      const responseEnvelope = encryptResponsePayload(privateKey, requestEnvelope, {
        kind: 'ok',
        response: {
          request_id: payload.request_id,
          model: payload.model,
          output: '',
          billed_token_class: payload.token_class,
          upstream: {
            id: 'chatcmpl-123',
            model: payload.model,
            choices: [
              {
                index: 0,
                message: {
                  role: 'assistant',
                  content: null,
                  tool_calls: [
                    {
                      id: 'call_1',
                      type: 'function',
                      function: {
                        name: 'lookup_weather',
                        arguments: '{"city":"Stockholm"}',
                      },
                    },
                  ],
                },
                finish_reason: 'tool_calls',
              },
            ],
          },
        },
      });

      return new Response(JSON.stringify(responseEnvelope), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    const client = new GatewayClient('https://gateway.example.com', gatewayPk, {
      nextTicket: async () => ticket,
    }, { fetchImpl });

    const response = await client.chatCompletions(TokenClass.C2048, {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'hello' }],
      stream: false,
      top_p: 0.1,
      response_format: { type: 'json_object' },
      tools: [{ type: 'function', function: { name: 'lookup_weather' } }],
    });

    expect(response.id).toBe('chatcmpl-123');
    expect(response.billed_token_class).toBe(TokenClass.C2048);
    expect((response.choices[0].message as any).tool_calls[0].function.name).toBe('lookup_weather');
  });

  it('rejects stream=true on the canonical infer path', async () => {
    const { publicKey } = crypto.generateKeyPairSync('x25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const gwRaw = spki.subarray(spki.length - 32);
    const gatewayPk = GatewayPublicKey.fromBase64(gwRaw.toString('base64'));
    const fetchImpl = vi.fn();

    const client = new GatewayClient('https://gateway.example.com', gatewayPk, {
      nextTicket: async (tokenClass) => randomDummyTicket(tokenClass),
    }, { fetchImpl: fetchImpl as typeof fetch });

    await expect(
      client.inferJson(TokenClass.C512, {
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'hello' }],
        stream: true,
      }),
    ).rejects.toThrow(/stream=true is not supported/);

    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
