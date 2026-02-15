import { describe, expect, it } from 'vitest';

import { padPayload, unpadPayload } from '../src/padding.js';

describe('padding', () => {
  it('pads and unpads roundtrip', () => {
    const payload = Buffer.from('hello world', 'utf8');
    const padded = padPayload(payload, 1024);
    expect(padded.length).toBe(1024);
    const raw = unpadPayload(padded);
    expect(Buffer.from(raw).toString('utf8')).toBe('hello world');
  });
});
