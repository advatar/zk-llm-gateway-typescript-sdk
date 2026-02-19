import { InvalidTokenClass } from './errors.js';

/**
 * Coarse bucket for request/response size shaping.
 *
 * Values and sizing intentionally match the gateway's canonical protocol
 * (`zk-llm-gateway/common/src/token.rs`).
 */
export enum TokenClass {
  C256 = 'c256',
  C512 = 'c512',
  C1024 = 'c1024',
  C2048 = 'c2048',
  C4096 = 'c4096',
}

export function parseTokenClass(value: string): TokenClass {
  const v = value.trim().toLowerCase();
  if (v === 'c256' || v === '256') return TokenClass.C256;
  if (v === 'c512' || v === '512') return TokenClass.C512;
  if (v === 'c1024' || v === '1024') return TokenClass.C1024;
  if (v === 'c2048' || v === '2048') return TokenClass.C2048;
  if (v === 'c4096' || v === '4096') return TokenClass.C4096;
  throw new InvalidTokenClass(`invalid token class: ${value}`);
}

export function tokenClassId(tc: TokenClass): number {
  switch (tc) {
    case TokenClass.C256:
      return 1;
    case TokenClass.C512:
      return 2;
    case TokenClass.C1024:
      return 3;
    case TokenClass.C2048:
      return 4;
    case TokenClass.C4096:
      return 5;
    default:
      throw new InvalidTokenClass(`invalid token class: ${String(tc)}`);
  }
}

export function maxPromptBytes(tc: TokenClass): number {
  switch (tc) {
    case TokenClass.C256:
      return 2 * 1024;
    case TokenClass.C512:
      return 4 * 1024;
    case TokenClass.C1024:
      return 8 * 1024;
    case TokenClass.C2048:
      return 16 * 1024;
    case TokenClass.C4096:
      return 32 * 1024;
    default:
      throw new InvalidTokenClass(`invalid token class: ${String(tc)}`);
  }
}

export function requestPaddedLen(tc: TokenClass): number {
  switch (tc) {
    case TokenClass.C256:
      return 8 * 1024;
    case TokenClass.C512:
      return 12 * 1024;
    case TokenClass.C1024:
      return 20 * 1024;
    case TokenClass.C2048:
      return 36 * 1024;
    case TokenClass.C4096:
      return 68 * 1024;
    default:
      throw new InvalidTokenClass(`invalid token class: ${String(tc)}`);
  }
}

export function responsePaddedLen(tc: TokenClass): number {
  switch (tc) {
    case TokenClass.C256:
      return 8 * 1024;
    case TokenClass.C512:
      return 16 * 1024;
    case TokenClass.C1024:
      return 32 * 1024;
    case TokenClass.C2048:
      return 64 * 1024;
    case TokenClass.C4096:
      return 128 * 1024;
    default:
      throw new InvalidTokenClass(`invalid token class: ${String(tc)}`);
  }
}

export function maxOutputTokensHint(tc: TokenClass): number {
  switch (tc) {
    case TokenClass.C256:
      return 256;
    case TokenClass.C512:
      return 512;
    case TokenClass.C1024:
      return 1024;
    case TokenClass.C2048:
      return 2048;
    case TokenClass.C4096:
      return 4096;
    default:
      throw new InvalidTokenClass(`invalid token class: ${String(tc)}`);
  }
}
