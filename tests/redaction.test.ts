import { describe, expect, it } from 'vitest';

import { RedactionMode, Redactor } from '../src/redaction.js';

describe('redaction', () => {
  it('redacts and rehydrates', () => {
    const r = new Redactor(RedactionMode.StablePerValue);
    const input = 'Contact alice@example.com and use sk-abcdef0123456789 for auth.';
    const res = r.redactText(input);
    expect(res.redacted).not.toContain('alice@example.com');
    expect(res.redacted).not.toContain('sk-abcdef0123456789');

    const restored = r.rehydrateText(res.redacted, res.map);
    expect(restored).toBe(input);
  });
});
