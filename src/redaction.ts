import * as crypto from 'node:crypto';

export enum RedactionMode {
  StablePerValue = 'stable_per_value',
  Ephemeral = 'ephemeral',
}

export interface RedactionResult {
  redacted: string;
  /** placeholder -> original */
  map: Record<string, string>;
}

type RedactionKind = 'EMAIL' | 'PHONE' | 'ETH' | 'APIKEY' | 'PRIVKEY' | 'TERM';

/**
 * Regex-based redaction helpers.
 *
 * These utilities can reduce accidental leakage of obvious identifiers (emails, phones, ETH addresses,
 * API keys, private key blocks) before sending prompts to a remote model.
 */
export class Redactor {
  private readonly salt: Buffer;
  private readonly customTerms: string[] = [];

  private readonly patterns: Array<{ kind: RedactionKind; rx: RegExp }>;

  constructor(public readonly mode: RedactionMode = RedactionMode.StablePerValue) {
    this.salt = crypto.randomBytes(16);

    // Pragmatic patterns. Tune for your product.
    const email = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
    const phone = /\b\+?[0-9][0-9() \-]{7,}[0-9]\b/g;
    const eth = /\b0x[a-fA-F0-9]{40}\b/g;
    const apikey = /\b(sk-[A-Za-z0-9]{16,})\b/g;
    const privkey = /-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----/g;

    this.patterns = [
      { kind: 'PRIVKEY', rx: privkey },
      { kind: 'APIKEY', rx: apikey },
      { kind: 'ETH', rx: eth },
      { kind: 'EMAIL', rx: email },
      { kind: 'PHONE', rx: phone },
    ];
  }

  addCustomTerm(term: string): void {
    const t = term.trim();
    if (t) this.customTerms.push(t);
  }

  redactText(input: string): RedactionResult {
    let out = input;
    const mapping: Record<string, string> = {};
    let counter = 0;

    // Custom terms first (exact match).
    for (const term of this.customTerms) {
      if (term && out.includes(term)) {
        const ph = this.placeholder('TERM', term, counter);
        out = out.split(term).join(ph);
        mapping[ph] = term;
        counter += 1;
      }
    }

    // Regex replacements (iterative).
    for (const { kind, rx } of this.patterns) {
      // reset lastIndex for global regex
      rx.lastIndex = 0;
      while (true) {
        const m = rx.exec(out);
        if (!m) break;
        const s = m[0];
        const ph = this.placeholder(kind, s, counter);
        out = out.slice(0, m.index) + ph + out.slice(m.index + s.length);
        mapping[ph] = s;
        counter += 1;

        // Reset to allow overlapping rescans after modifying the string.
        rx.lastIndex = 0;
      }
    }

    return { redacted: out, map: mapping };
  }

  redactJson(value: unknown): { redacted: unknown; map: Record<string, string> } {
    const map: Record<string, string> = {};
    const redacted = this.redactJsonInner(value, map);
    return { redacted, map };
  }

  private redactJsonInner(value: unknown, map: Record<string, string>): unknown {
    if (typeof value === 'string') {
      const res = this.redactText(value);
      Object.assign(map, res.map);
      return res.redacted;
    }
    if (Array.isArray(value)) {
      return value.map((v) => this.redactJsonInner(v, map));
    }
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = this.redactJsonInner(v, map);
      }
      return out;
    }
    return value;
  }

  rehydrateText(input: string, map: Record<string, string>): string {
    let out = input;
    const keys = Object.keys(map).sort((a, b) => b.length - a.length);
    for (const k of keys) {
      out = out.split(k).join(map[k]!);
    }
    return out;
  }

  rehydrateJson(value: unknown, map: Record<string, string>): unknown {
    if (typeof value === 'string') return this.rehydrateText(value, map);
    if (Array.isArray(value)) return value.map((v) => this.rehydrateJson(v, map));
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = this.rehydrateJson(v, map);
      }
      return out;
    }
    return value;
  }

  private placeholder(kind: RedactionKind, original: string, counter: number): string {
    const h = crypto.createHash('sha256');
    h.update(this.salt);
    h.update(Buffer.from(kind, 'utf8'));

    if (this.mode === RedactionMode.StablePerValue) {
      h.update(Buffer.from(original, 'utf8'));
    } else {
      const c = Buffer.alloc(8);
      c.writeBigUInt64LE(BigInt(counter));
      h.update(c);
      h.update(Buffer.from(original, 'utf8'));
    }

    const digest = h.digest();
    const short = digest.subarray(0, 6).toString('hex');
    return `<${kind}_${short}>`;
  }
}
