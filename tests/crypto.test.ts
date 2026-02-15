import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';

import { GatewayPublicKey, openJson, sealJson } from '../src/crypto.js';
import { TokenClass } from '../src/tokenClass.js';

describe('crypto', () => {
  it('seal/open roundtrip', () => {
    // Generate a random gateway keypair and export public key as raw 32 bytes.
    const { publicKey } = crypto.generateKeyPairSync('x25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;

    // X25519 SPKI prefix is fixed; raw key is last 32 bytes.
    const gwRaw = spki.subarray(spki.length - 32);
    const gwPk = GatewayPublicKey.fromBase64(gwRaw.toString('base64'));

    const payload = { hello: 'world', n: 123 };
    const { envelope, state } = sealJson(gwPk, TokenClass.C1024, payload);

    const opened = openJson(envelope, state) as any;
    expect(opened).toEqual(payload);
  });
});
