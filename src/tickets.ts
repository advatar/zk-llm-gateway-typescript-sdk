import * as crypto from 'node:crypto';
import { TicketExhausted } from './errors.js';
import { TokenClass } from './tokenClass.js';

/** ZK-ready ticket payload. Fields are intentionally generic and opaque. */
export interface ZkTicket {
  nullifier_b64: string;
  proof_b64: string;
  commitment_root_b64?: string | null;
  extra?: unknown;
  ticket_id?: string | null;
}

export function randomDummyTicket(): ZkTicket {
  const n = crypto.randomBytes(32);
  return {
    nullifier_b64: n.toString('base64'),
    proof_b64: Buffer.from([]).toString('base64'),
    commitment_root_b64: null,
    extra: null,
    ticket_id: null,
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
  async nextTicket(_tokenClass: TokenClass): Promise<ZkTicket> {
    return randomDummyTicket();
  }
}

/**
 * Ticket pool loaded from a JSON file (array of ZkTicket objects).
 *
 * Node-only.
 */
export class FileTicketSource implements TicketSource {
  private constructor(private readonly tickets: ZkTicket[]) {}

  static async fromPath(path: string): Promise<FileTicketSource> {
    const fs = await import('node:fs/promises');
    const txt = await fs.readFile(path, 'utf8');
    const data = JSON.parse(txt);
    const tickets: ZkTicket[] = Array.isArray(data) ? (data as any[]).filter(Boolean) as ZkTicket[] : [];
    return new FileTicketSource(tickets);
  }

  remaining(): number {
    return this.tickets.length;
  }

  async nextTicket(_tokenClass: TokenClass): Promise<ZkTicket> {
    const t = this.tickets.shift();
    if (!t) throw new TicketExhausted('ticket pool exhausted');
    return t;
  }
}
