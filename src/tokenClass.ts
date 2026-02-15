import { InvalidTokenClass } from './errors.js';

/**
 * Coarse bucket for request/response size shaping.
 *
 * Token classes map to fixed padded byte lengths for plaintext request/response.
 * This reduces metadata leakage from variable request sizes.
 *
 * Note: these are pragmatic byte limits, not exact token counts.
 */
export enum TokenClass {
  C512 = 'c512',
  C1024 = 'c1024',
  C2048 = 'c2048',
  C4096 = 'c4096',
}

export function parseTokenClass(value: string): TokenClass {
  const v = value.trim().toLowerCase();
  if (v === 'c512' || v === '512') return TokenClass.C512;
  if (v === 'c1024' || v === '1024') return TokenClass.C1024;
  if (v === 'c2048' || v === '2048') return TokenClass.C2048;
  if (v === 'c4096' || v === '4096') return TokenClass.C4096;
  throw new InvalidTokenClass(`invalid token class: ${value}`);
}

export function requestPaddedLen(tc: TokenClass): number {
  switch (tc) {
    case TokenClass.C512:
      return 8 * 1024;
    case TokenClass.C1024:
      return 16 * 1024;
    case TokenClass.C2048:
      return 32 * 1024;
    case TokenClass.C4096:
      return 64 * 1024;
    default:
      // Exhaustiveness
      throw new InvalidTokenClass(`invalid token class: ${String(tc)}`);
  }
}

export function responsePaddedLen(tc: TokenClass): number {
  // In this SDK the response padded size matches the request padded size.
  return requestPaddedLen(tc);
}

export function maxOutputTokensHint(tc: TokenClass): number {
  switch (tc) {
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
