/**
 * What the 0.6 hosts need from the account: the member engine, the ticket call, an exchange pass, and the member key
 * for one raw signature. `accountOf` provides it from a `ColophonSession`; anything else may implement it.
 */
import type { ColophonSession } from '../session/session.js';
import { SessionError } from '../session/errors.js';
import type { HomeTransport } from '../session/transport.js';
import type { glue } from '../session/wasm.js';

export interface HostAccount {
  /** The account (64 hex). */
  readonly account: string;
  /** This device's member ID. */
  readonly member: string;
  /**
   * The member engine as it is now. Stream and endpoint calls take it; it is read again for every call, so a locked or
   * reopened engine is seen at once (a locked one throws `Locked`; a reopened one is another engine to an endpoint).
   */
  engine(): glue.AccountEngine;
  /** The `colophon.home.stream` call for `home`, signed and judged by the core, as the envelope's bytes. */
  streamCall(home: string, signal?: AbortSignal): Promise<Uint8Array>;
  /** One ordinary exchange pass with the homes (the stream's `Wake`). */
  exchange(signal?: AbortSignal): Promise<void>;
  /** A raw P-256 signature (`r || s`) by this member's key over `body` (a session delegation, sessions §S2). */
  signRaw(body: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

/**
 * The host account of a restored `ColophonSession`. The session keeps owning the engine, its lock and its exchange;
 * this only reaches them. `exchange` is the session's own `syncNow`, so passes never overlap with its poll loop.
 */
export function accountOf(session: ColophonSession): HostAccount {
  const account = session.libraryId; const member = session.memberId;
  if (account === undefined || member === undefined) throw new SessionError('notReady');
  const worker = session.worker;
  return {
    account, member,
    engine: () => worker.requireEngine().run(e => e),
    streamCall: (home, signal) => worker.streamCall(home, signal),
    exchange: async signal => { await session.syncNow(signal); },
    signRaw: (body, signal) => worker.configuration.keys.sign(body, signal),
  };
}

/** The transport `session` was configured with for `home` (its ticket requests go there), if any. */
export function transportOf(session: ColophonSession, home: string): HomeTransport | undefined {
  return session.worker.transportOf(home);
}
