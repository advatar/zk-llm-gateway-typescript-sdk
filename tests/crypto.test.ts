import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';

import { GatewayPublicKey, openJson, sealJson } from '../src/crypto.js';
import { padPayload } from '../src/padding.js';
import { responsePaddedLen, tokenClassId, TokenClass } from '../src/tokenClass.js';

function encryptResponse(
  key: Uint8Array,
  tokenClass: TokenClass,
  payload: unknown,
): { nonceB64: string; ciphertextB64: string } {
  const raw = Buffer.from(JSON.stringify(payload), 'utf8');
  const padded = padPayload(raw, responsePaddedLen(tokenClass));

  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from([1, tokenClassId(tokenClass), 2]);

  const cipher = crypto.createCipheriv('chacha20-poly1305', Buffer.from(key), nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(aad, { plaintextLength: padded.length });

  const ct = Buffer.concat([cipher.update(padded), cipher.final()]);
  const tag = cipher.getAuthTag();
  const full = Buffer.concat([ct, tag]);

  return {
    nonceB64: nonce.toString('base64'),
    ciphertextB64: full.toString('base64'),
  };
}

describe('crypto', () => {
  it('seal/open roundtrip with gateway-style response envelope', () => {
    const { publicKey } = crypto.generateKeyPairSync('x25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const gwRaw = spki.subarray(spki.length - 32);
    const gwPk = GatewayPublicKey.fromBase64(gwRaw.toString('base64'));

    const payload = { hello: 'world', n: 123 };
    const { envelope: reqEnv, state } = sealJson(gwPk, TokenClass.C1024, payload);

    const respPayload = { upstream: { ok: true } };
    const enc = encryptResponse(state.respKey, TokenClass.C1024, respPayload);

    const respEnv = {
      v: reqEnv.v,
      token_class: reqEnv.token_class,
      eph_pubkey_b64: reqEnv.eph_pubkey_b64,
      nonce_b64: enc.nonceB64,
      ciphertext_b64: enc.ciphertextB64,
    };

    const opened = openJson(respEnv, state) as any;
    expect(opened).toEqual(respPayload);
  });
});
