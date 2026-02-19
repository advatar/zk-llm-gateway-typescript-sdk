import * as crypto from 'node:crypto';
import { TicketExhausted } from './errors.js';
import { parseTokenClass, TokenClass } from './tokenClass.js';

/** Canonical gateway ticket payload. */
export interface ZkTicket {
  commitment_root: string;
  nullifier: string;
  token_class: TokenClass;
  proof: string;
}

type RawTicket = Partial<
  ZkTicket & {
    commitment_root_b64: string;
    nullifier_b64: string;
    proof_b64: string;
  }
>;

function b64Zeros(size: number): string {
  return Buffer.alloc(size, 0).toString('base64');
}

function normalizeTicket(raw: RawTicket, fallbackTokenClass: TokenClass): ZkTicket {
  const commitment_root = typeof raw.commitment_root === 'string'
    ? raw.commitment_root
    : typeof raw.commitment_root_b64 === 'string'
      ? raw.commitment_root_b64
      : b64Zeros(32);

  const nullifier = typeof raw.nullifier === 'string'
    ? raw.nullifier
    : typeof raw.nullifier_b64 === 'string'
      ? raw.nullifier_b64
      : '';

  if (!nullifier) {
    throw new Error('ticket missing nullifier/nullifier_b64');
  }

  const proof = typeof raw.proof === 'string'
    ? raw.proof
    : typeof raw.proof_b64 === 'string'
      ? raw.proof_b64
      : '';

  const token_class = raw.token_class ? parseTokenClass(String(raw.token_class)) : fallbackTokenClass;

  return {
    commitment_root,
    nullifier,
    token_class,
    proof,
  };
}

export function randomDummyTicket(tokenClass: TokenClass): ZkTicket {
  return {
    commitment_root: crypto.randomBytes(32).toString('base64'),
    nullifier: crypto.randomBytes(32).toString('base64'),
    token_class: tokenClass,
    proof: crypto.randomBytes(64).toString('base64'),
  };
}

/**
 * Ticket source interface.
 *
 * For long-running agents, prefer a source that can refresh/replenish tickets.
 */
export interface TicketSource {
  nextTicket(tokenClass: TokenClass): Promise<ZkTicket>;
}

/** Development-only ticket source. */
export class DummyTicketSource implements TicketSource {
  async nextTicket(tokenClass: TokenClass): Promise<ZkTicket> {
    return randomDummyTicket(tokenClass);
  }
}

/**
 * Ticket pool loaded from a JSON file (array of ticket objects).
 *
 * Node-only.
 */
export class FileTicketSource implements TicketSource {
  private constructor(private readonly tickets: RawTicket[]) {}

  static async fromPath(path: string): Promise<FileTicketSource> {
    const fs = await import('node:fs/promises');
    const txt = await fs.readFile(path, 'utf8');
    const data = JSON.parse(txt);
    const tickets: RawTicket[] = Array.isArray(data) ? (data as any[]).filter((v) => v && typeof v === 'object') as RawTicket[] : [];
    return new FileTicketSource(tickets);
  }

  remaining(): number {
    return this.tickets.length;
  }

  async nextTicket(tokenClass: TokenClass): Promise<ZkTicket> {
    const exactIndex = this.tickets.findIndex((t) => {
      if (!t.token_class) return false;
      try {
        return parseTokenClass(String(t.token_class)) === tokenClass;
      } catch {
        return false;
      }
    });

    const fallbackIndex = this.tickets.findIndex((t) => !t.token_class);
    const idx = exactIndex >= 0 ? exactIndex : fallbackIndex;

    if (idx < 0) throw new TicketExhausted('ticket pool exhausted');

    const [raw] = this.tickets.splice(idx, 1);
    try {
      const ticket = normalizeTicket(raw, tokenClass);
      if (ticket.token_class !== tokenClass) {
        throw new Error('ticket token_class mismatch');
      }
      return ticket;
    } catch (e) {
      throw new TicketExhausted(`invalid ticket entry: ${(e as Error).message}`);
    }
  }
}
