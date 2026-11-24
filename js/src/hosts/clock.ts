/**
 * The clocks and timers a 0.6 host drives the core with. Both state machines take time as an argument and keep no
 * timer of their own, so the host owns these; tests inject a manual clock and step it.
 */

/** A host's clocks, in milliseconds. */
export interface HostClock {
  /** Monotonic milliseconds: never goes back while the process runs (every stream and session timer). */
  monoMs(): number;
  /** Wall-clock milliseconds since the Unix epoch (delegation windows, member expiry, account views). */
  wallMs(): number;
  /** Runs `run` once, `ms` from now on the monotonic clock. Returns the function that cancels it. */
  setTimer(run: () => void, ms: number): () => void;
}

/**
 * The runtime's clocks: `performance.now()` (monotonic, from process start) and `Date.now()`, with the global
 * `setTimeout`. The same in browsers, Bun and Node.
 */
export const systemClock: HostClock = {
  monoMs: () => Math.floor(performance.now()),
  wallMs: () => Date.now(),
  setTimer: (run, ms) => {
    const timer = setTimeout(run, Math.max(0, Math.min(ms, 2_147_483_647)));
    return () => clearTimeout(timer);
  },
};

/**
 * One timer that is always set to the latest deadline it was given: `at` replaces whatever was scheduled before, and
 * `clear` cancels it. Used for `HomeStream`'s `Sleep { until }` and `SessionEndpoint.next_deadline`.
 */
export class Deadline {
  private cancel: (() => void) | undefined;
  private due: number | undefined;
  constructor(private readonly clock: HostClock, private readonly run: () => void) {}
  /** Fires `run` at monotonic `due` (at once if it has passed); none clears it. */
  at(due: number | undefined): void {
    if (due === this.due && this.cancel) return;
    this.clear();
    if (due === undefined) return;
    this.due = due;
    this.cancel = this.clock.setTimer(() => { this.cancel = undefined; this.due = undefined; this.run(); }, Math.max(0, due - this.clock.monoMs()));
  }
  clear(): void { this.cancel?.(); this.cancel = undefined; this.due = undefined; }
  /** When it fires next, if set. */
  get when(): number | undefined { return this.due; }
}
