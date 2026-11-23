// Colophon 0.6 draft: a home's two-way stream (docs/colophon-0.6-stream.md). I/O only.
//
// One HomeStream per home slot (one account). It mints single-use stream tickets after the home
// module verified a `colophon.home.stream` call, accepts WebSocket connections that present one,
// pushes what the home commits (`change`, `head`, `notice`, `route`), and carries sealed session
// frames between the account's connected members (0.6 sessions §S9). Every decision about who may
// stream, subscribe or send a frame is the home module's (`stream_standing`, `subscription`,
// `session_frame`); this file holds connections, timers, caps and an in-memory retained-frame
// table. Nothing about a session frame is ever written to disk or logged, and neither is a ticket.
import { createHash, randomBytes } from 'node:crypto';

export const STREAM_PROTOCOL = 'colophon/home-stream/6';

/** Defaults; `createRelay({ stream })` overrides any of them. */
export const STREAM_DEFAULTS = Object.freeze({
  ticketMs: 30_000, // a ticket's life on the home's clock
  ticketsPerPrincipal: 8, // outstanding unredeemed tickets
  ticketsPerSlot: 256,
  streamsPerPrincipal: 4, // open connections of one controller, or one member with its links
  streamsPerAccount: 64, // open connections of one account (slot)
  messageBytes: 20_480, // largest WebSocket message; larger closes 1009
  subscriptions: 64, // per connection
  framesPerSecond: 50, // inbound token bucket, per connection
  frameBurst: 100,
  bytesPerSecond: 262_144,
  byteBurst: 524_288,
  // Session frames the whole account may send, all connections together. Each one is copied to
  // every other subscriber, so this is what bounds the home's outbound work for an account.
  sessionFramesPerSecond: 100,
  sessionFrameBurst: 200,
  sessionBytesPerSecond: 524_288,
  sessionByteBurst: 1_048_576,
  bufferedBytes: 1_048_576, // a connection whose unsent bytes exceed this is cut off (4013)
  resumeEntries: 1024, // most missed changes replayed on connect; more answers `resync`
  retainMs: 60_000, // retained-frame life (at most 60 s, §S9)
  retainedPerSlot: 1024,
  pingMs: 20_000,
  idleMs: 60_000, // no pong or message for this long closes 4008
  sweepMs: 5_000, // standing re-check, expiry and retained sweep while streams are open (1 to MAX_SWEEP_MS)
});

/** The longest interval between standing sweeps. The sweep cannot be turned off: while any
 * stream is open, time-driven changes (an expiry, a removal falling due, a stop) must evict
 * within this bound even when nothing else commits. */
export const MAX_SWEEP_MS = 5_000;

/** Check `stream` settings (config file `stream`, createRelay's `stream`): known keys only, each a
 * positive integer; `sweepMs` at most MAX_SWEEP_MS. */
export function streamOptions(options) {
  if (options === undefined || options === null) return {};
  if (typeof options !== 'object' || Array.isArray(options)) throw new Error('stream must be an object of settings');
  for (const [key, value] of Object.entries(options)) {
    if (!(key in STREAM_DEFAULTS)) throw new Error(`stream.${key} is not a stream setting`);
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`stream.${key} must be a positive integer`);
    if (key === 'sweepMs' && value > MAX_SWEEP_MS) throw new Error(`stream.sweepMs must be at most ${MAX_SWEEP_MS}`);
  }
  return { ...options };
}

export const CLOSE = Object.freeze({
  normal: 1000,
  goingAway: 1001, // the slot was released: do not resume here
  policy: 1008, // stream authorization ended
  tooBig: 1009,
  internal: 1011,
  restart: 1012, // the home is shutting down: resume after `retryMs`
  idle: 4008,
  slow: 4013,
});

const sha = (text) => createHash('sha256').update(text).digest('hex');

/** A token bucket on real time. */
class Bucket {
  constructor(rate, burst) { this.rate = rate; this.burst = burst; this.tokens = burst; this.at = Date.now(); }
  take(n) {
    const now = Date.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.at) / 1000) * this.rate);
    this.at = now;
    if (this.tokens < n) return false;
    this.tokens -= n;
    return true;
  }
}

export class HomeStream {
  /** @param {import('./home.js').HomeSlot} home @param {object} options STREAM_DEFAULTS overrides */
  constructor(home, options = {}) {
    this.home = home;
    this.o = { ...STREAM_DEFAULTS, ...options };
    this.o.retainMs = Math.min(this.o.retainMs, 60_000);
    this.tickets = new Map(); // sha256(ticket) -> grant
    this.conns = new Set();
    this.retained = new Map(); // namespace \0 cell \0 from -> { frame, from, namespace, cell, at }
    this.counters = { forwarded: 0, dropped: 0, limited: 0, refused: 0, slow: 0, idle: 0 };
    this.session = {
      frames: new Bucket(this.o.sessionFramesPerSecond, this.o.sessionFrameBurst),
      bytes: new Bucket(this.o.sessionBytesPerSecond, this.o.sessionByteBurst),
    };
    // Retained frames replayed to new subscribers, at the same rates. Kept apart from the budget
    // for live frames so that subscribing over and over cannot starve them.
    this.replay = {
      frames: new Bucket(this.o.sessionFramesPerSecond, this.o.sessionFrameBurst),
      bytes: new Bucket(this.o.sessionBytesPerSecond, this.o.sessionByteBurst),
    };
    this.timers = null;
  }

  get clock() { return this.home.clock; }

  // -------------------------------------------------------------------------------------------
  // Tickets.

  /** Mint a ticket for a verified `colophon.home.stream` call (`allowed.stream` from `access`). */
  mint(allowed) {
    const { HttpError } = this.home.deps;
    const now = this.clock();
    for (const [key, t] of this.tickets) if (now > t.until) this.tickets.delete(key);
    const grant = allowed.stream;
    const mine = [...this.tickets.values()].filter((t) => t.principalId === grant.principalId).length;
    if (mine >= this.o.ticketsPerPrincipal || this.tickets.size >= this.o.ticketsPerSlot) {
      throw new HttpError(429, 'Too many stream tickets', { 'retry-after': String(Math.ceil(this.o.ticketMs / 1000)) }, { result: 'refused:window' });
    }
    const ticket = randomBytes(32).toString('base64url');
    const until = now + this.o.ticketMs;
    this.tickets.set(sha(ticket), { ...grant, until });
    return { ticket, expires: new Date(until).toISOString(), path: '/stream' };
  }

  /** Redeem a ticket: single use whatever the outcome. Null when unknown or expired. */
  redeem(ticket) {
    if (typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(ticket)) return null;
    const key = sha(ticket);
    const grant = this.tickets.get(key);
    this.tickets.delete(key);
    if (!grant || this.clock() > grant.until) return null;
    return grant;
  }

  // -------------------------------------------------------------------------------------------
  // Connections.

  /** Burn every ticket the upgrade presents, before anything else can refuse it: a ticket that
   * reached a URL (and so perhaps a log) is never usable afterwards. The grant of the first
   * valid one, or null; `present` says whether any ticket parameter was there at all. */
  take(url) {
    const tickets = url.searchParams.getAll('ticket');
    let grant = null;
    for (const t of tickets) {
      const g = this.redeem(t);
      grant ??= g;
    }
    return { grant, present: tickets.length > 0, count: tickets.length };
  }

  /** The upgrade, after `take`: check the query, the ticket, standing and caps, then hand the
   * socket to `connect`. */
  async connect(url, taken, connect) {
    const { HttpError } = this.home.deps;
    if (!taken.present) throw new HttpError(401, 'A stream ticket is required', {}, { result: 'refused:ticket' });
    const after = url.searchParams.get('after');
    for (const name of url.searchParams.keys()) {
      if (name !== 'ticket' && name !== 'after') throw new HttpError(400, 'Unknown stream parameter');
    }
    if (taken.count !== 1 || url.searchParams.getAll('after').length > 1) throw new HttpError(400, 'One ticket and at most one cursor');
    const { grant } = taken;
    if (!grant) throw new HttpError(403, 'Forbidden', {}, { result: 'refused:ticket' });
    await this.home.lock(async () => {
      const { slot } = this.home;
      if (slot.closing || slot.releasing || slot.released) throw new HttpError(503, 'Home unavailable');
      // Standing may have changed since the ticket was minted: judge it at the committed state.
      const [standing] = this.standing([grant]);
      if (!standing) throw new HttpError(403, 'Forbidden', {}, { result: 'refused:revoked' });
      const open = [...this.conns];
      if (open.length >= this.o.streamsPerAccount
          || open.filter((c) => c.principalId === grant.principalId).length >= this.o.streamsPerPrincipal) {
        throw new HttpError(429, 'Too many streams', { 'retry-after': '30' }, { result: 'refused:window' });
      }
      const conn = {
        principalId: grant.principalId,
        member: grant.principalId.startsWith('member:') ? grant.principalId.slice('member:'.length) : null,
        sessionNonce: grant.sessionNonce,
        expiresAt: minExpiry(grant.expiresAt, standing.expiresAt),
        namespaces: standing.namespaces ?? [],
        ws: null, n: 0, subs: new Set(), lastSeen: Date.now(), live: false,
        frames: new Bucket(this.o.framesPerSecond, this.o.frameBurst),
        bytes: new Bucket(this.o.bytesPerSecond, this.o.byteBurst),
        dropped: 0, refused: 0, warnedAt: 0, timer: null,
      };
      // Counted against the caps from now; dropped if the handshake never completes.
      this.conns.add(conn);
      conn.timer = setTimeout(() => { if (!conn.ws) this.conns.delete(conn); }, 10_000);
      conn.timer.unref?.();
      connect((ws) => this.open(conn, ws, after));
    });
  }

  open(conn, ws, after) {
    clearTimeout(conn.timer);
    if (!this.conns.has(conn)) { ws.terminate(); return; }
    conn.ws = ws;
    ws.on('message', (data, isBinary) => this.receive(conn, data, isBinary));
    ws.on('pong', () => { conn.lastSeen = Date.now(); });
    ws.on('close', () => this.drop(conn));
    ws.on('error', () => ws.terminate());
    // Hello, the replay of missed changes, then live frames: all before anything else can run,
    // so no change is lost or repeated between the replay and the first live frame.
    const { slot, key } = this.home;
    this.send(conn, {
      type: 'hello', protocol: STREAM_PROTOCOL, account: this.home.account, home: key.memberId,
      instance: slot.instance, cursor: `${slot.instance}.${slot.entries.length}`,
      head: this.home.lastHead ?? null, notice: this.home.noticeSeq ?? 0,
      principal: conn.principalId, expiresAt: conn.expiresAt, namespaces: conn.namespaces,
      limits: {
        frameBytes: 16_384, messageBytes: this.o.messageBytes, subscriptions: this.o.subscriptions,
        framesPerSecond: this.o.framesPerSecond, bytesPerSecond: this.o.bytesPerSecond,
        sessionFramesPerSecond: this.o.sessionFramesPerSecond, sessionBytesPerSecond: this.o.sessionBytesPerSecond,
        retainMs: this.o.retainMs, pingMs: this.o.pingMs, idleMs: this.o.idleMs,
        resumeEntries: this.o.resumeEntries,
      },
    });
    this.resume(conn, after);
    conn.live = true;
    this.armExpiry(conn);
    this.startTimers();
  }

  /** Missed `change` frames after `after` (a `/changes` cursor), or `resync`. */
  resume(conn, after) {
    if (after === null || after === undefined) return;
    const { slot } = this.home;
    const dot = after.lastIndexOf('.');
    const seq = Number(after.slice(dot + 1));
    if (dot < 1 || after.slice(0, dot) !== slot.instance || !/^\d+$/.test(after.slice(dot + 1))
        || !Number.isSafeInteger(seq) || seq > slot.entries.length) {
      // As `/changes` answers 410: the cursor cannot be continued; list from the beginning.
      this.send(conn, { type: 'resync', reason: 'gone', after });
      return;
    }
    if (slot.entries.length - seq > this.o.resumeEntries) {
      this.send(conn, { type: 'resync', reason: 'tooFar', after });
      return;
    }
    for (let i = seq; i < slot.entries.length; i++) {
      if (!this.send(conn, changeFrame(slot, i))) return;
    }
  }

  drop(conn) {
    clearTimeout(conn.timer);
    this.conns.delete(conn);
    if (!this.conns.size) this.stopTimers();
  }

  close(conn, code, reason) {
    this.drop(conn);
    const { ws } = conn;
    if (!ws) return;
    try { ws.close(code, reason); } catch { ws.terminate(); }
    // A peer that never answers the close is cut off.
    const t = setTimeout(() => ws.terminate(), 1000);
    t.unref?.();
  }

  /** Send one frame with the connection's next `n`. False when the frame was not sent; a
   * connection that cannot keep up is closed rather than sent less (no gap in `n`). */
  send(conn, frame) {
    const { ws } = conn;
    if (!ws || ws.readyState !== ws.OPEN) return false;
    if (ws.bufferedAmount > this.o.bufferedBytes) {
      this.counters.slow += 1;
      this.close(conn, CLOSE.slow, 'Slow consumer');
      return false;
    }
    conn.n += 1;
    const { type, ...rest } = frame;
    try { ws.send(JSON.stringify({ type, n: conn.n, ...rest })); } catch { ws.terminate(); return false; }
    return true;
  }

  /** A frame to every live connection, filtered by `want` (default all). */
  broadcast(frame, want = () => true) {
    const now = this.clock();
    for (const conn of [...this.conns]) {
      if (!conn.live) continue;
      // Past its grant (a clock that moved before the expiry timer fired): closed, not sent to.
      if (conn.expiresAt !== null && conn.expiresAt !== undefined && now > conn.expiresAt) {
        if (conn.member) this.forget(conn.member);
        this.close(conn, CLOSE.policy, 'Stream authorization ended');
        continue;
      }
      if (want(conn)) this.send(conn, frame);
    }
  }

  // -------------------------------------------------------------------------------------------
  // What the home commits.

  change(index) {
    if (this.conns.size) this.broadcast(changeFrame(this.home.slot, index));
  }

  head(seq, digest) {
    this.broadcast({ type: 'head', home: this.home.key.memberId, seq, digest });
  }

  notice({ seq, object, kind, deadline }) {
    this.broadcast({ type: 'notice', notice: seq, object, kind, deadline });
  }

  route(id, change, route) {
    this.broadcast({ type: 'route', id, change, ...(route ? { kind: route.kind, reaches: route.reaches, by: route.by } : {}) });
  }

  // -------------------------------------------------------------------------------------------
  // What clients send.

  error(conn, code, ref, extra = {}) {
    this.send(conn, { type: 'error', code, ...(ref !== undefined ? { ref } : {}), ...extra });
  }

  /** Count a frame dropped for a rate cap, and tell its sender at most once a second. */
  limited(conn) {
    conn.dropped += 1;
    this.counters.dropped += 1;
    const now = Date.now();
    if (now - conn.warnedAt >= 1000) {
      conn.warnedAt = now;
      this.error(conn, 'rateLimited', undefined, { dropped: conn.dropped });
    }
  }

  receive(conn, data, isBinary) {
    conn.lastSeen = Date.now();
    if (!conn.live) return;
    const size = data.length ?? data.byteLength ?? 0;
    // Over the rate: dropped and counted, never queued. The sender hears of it at most once a
    // second, with its running total.
    if (!conn.frames.take(1) || !conn.bytes.take(size)) { this.limited(conn); return; }
    if (isBinary) { this.error(conn, 'binary'); return; }
    let msg;
    try { msg = JSON.parse(Buffer.from(data).toString('utf8')); } catch { msg = null; }
    if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.type !== 'string') {
      this.error(conn, 'badFrame');
      return;
    }
    const ref = typeof msg.id === 'string' && msg.id.length <= 64 ? msg.id : undefined;
    switch (msg.type) {
      case 'ping':
        this.send(conn, { type: 'pong', ...(Number.isFinite(msg.t) ? { t: msg.t } : {}), ...(ref !== undefined ? { ref } : {}) });
        return;
      case 'subscribe': this.subscribe(conn, msg, ref); return;
      case 'unsubscribe': {
        const key = `${msg.namespace}\0${msg.cell}`;
        conn.subs.delete(key);
        this.send(conn, { type: 'unsubscribed', namespace: msg.namespace, cell: msg.cell, ...(ref !== undefined ? { ref } : {}) });
        return;
      }
      case 'session': this.forward(conn, msg, ref); return;
      default: this.error(conn, 'unknownType', ref);
    }
  }

  subscribe(conn, msg, ref) {
    const { namespace, cell } = msg;
    if (!conn.member) { this.error(conn, 'notEntitled', ref); return; }
    if (typeof namespace !== 'string' || typeof cell !== 'string') { this.error(conn, 'badFrame', ref); return; }
    const r = this.home.wasm.call({ op: 'subscription', namespace, cell, entitled: conn.namespaces });
    if (!r.allowed) { this.error(conn, r.code, ref); return; }
    const key = `${namespace}\0${cell}`;
    const already = conn.subs.has(key);
    if (!already && conn.subs.size >= this.o.subscriptions) { this.error(conn, 'tooMany', ref); return; }
    conn.subs.add(key);
    this.send(conn, { type: 'subscribed', namespace, cell, ...(ref !== undefined ? { ref } : {}) });
    // Subscribing again to a cell replays nothing: the connection has had those frames.
    if (already) return;
    // The latest retained frame of every other member in the cell (§S9), still in its time,
    // whatever its `to` says: receivers ignore frames not addressed to them (§S3).
    const now = Date.now();
    for (const [k, r2] of this.retained) {
      if (now - r2.at > this.o.retainMs) { this.retained.delete(k); continue; }
      if (r2.namespace === namespace && r2.cell === cell && r2.from !== conn.member) {
        // Replay is best effort and bounded for the account: over the budget the rest is left
        // out, and the subscriber gets each member's state with that member's next frame.
        if (!this.replay.frames.take(1) || !this.replay.bytes.take(r2.size)) { this.counters.limited += 1; return; }
        if (!this.send(conn, { type: 'session', retained: true, frame: r2.frame })) return;
      }
    }
  }

  forward(conn, msg, ref) {
    if (!conn.member) { conn.refused += 1; this.counters.refused += 1; this.error(conn, 'notEntitled', ref); return; }
    const { frame } = msg;
    if (!frame || typeof frame !== 'object' || Array.isArray(frame)) { this.error(conn, 'badFrame', ref); return; }
    // The frame is the session codec's: one canonical JSON object (sessions §S3). The module
    // checks this serialisation and refuses it unless it is canonical. A codec frame holds only
    // strings, `true`, integers up to 2^53 − 1 and objects of those (the delegation), which
    // JSON.parse and JSON.stringify carry without loss and, for keys already in byte order and
    // none of them integer-like, in the same order: so `encoded` is the sender's exact bytes.
    // The object is never changed after this, and `send` serialises it with the same function,
    // so every receiver, live or by retained replay, gets `encoded` byte for byte.
    const encoded = JSON.stringify(frame);
    const r = this.home.wasm.call({ op: 'session_frame', frame: encoded, account: this.home.account, member: conn.member, entitled: conn.namespaces });
    if (!r.allowed) {
      conn.refused += 1;
      this.counters.refused += 1;
      this.error(conn, r.code, ref);
      return;
    }
    // The account's budget for session frames, charged for every valid frame whoever is
    // listening: the answer cannot depend on how many members are connected or subscribed. Over
    // it the frame is dropped like one over the connection's own rate, and never retained.
    if (!this.session.frames.take(1) || !this.session.bytes.take(encoded.length)) {
      this.counters.limited += 1;
      this.limited(conn);
      return;
    }
    const out = { type: 'session', frame };
    if (r.retain) {
      const key = `${r.namespace}\0${r.cell}\0${r.from}`;
      if (this.retained.has(key) || this.retained.size < this.o.retainedPerSlot) {
        this.retained.set(key, { frame, size: encoded.length, from: r.from, namespace: r.namespace, cell: r.cell, at: Date.now() });
      }
    }
    // `to` is advice to receivers, not a route (§S3, §S9): a member reachable only through
    // another member must still get addressed frames, so every other subscribed, entitled member
    // receives the frame. The sender hears nothing either way, so it cannot learn from the home
    // whether the member `to` names is connected.
    const sub = `${r.namespace}\0${r.cell}`;
    this.counters.forwarded += 1;
    this.broadcast(out, (c) => c !== conn && c.member && c.member !== r.from && c.subs.has(sub)
      && c.namespaces.includes(r.namespace));
  }

  // -------------------------------------------------------------------------------------------
  // Standing, expiry and timers.

  /** The module's standing for each grant-like `{principalId, sessionNonce}`: null when it may no
   * longer stream, else `{expiresAt, namespaces}`. A module failure counts as no standing. */
  standing(subscribers) {
    try {
      return this.home.wasm.call({
        op: 'stream_standing', state: this.home.state, base: this.home.base, now: this.clock(),
        subscribers: subscribers.map(({ principalId, sessionNonce }) => ({ principalId, sessionNonce })),
      }).standing;
    } catch (error) {
      this.home.note('streams', `stream standing could not be checked: ${error.message}`);
      return subscribers.map(() => null);
    }
  }

  /** Re-check every connection at the committed state: called on every commit and sweep. A
   * connection whose access ended is closed (1008); one whose namespaces narrowed loses those
   * subscriptions. Retained frames of a member whose access ended or narrowed are dropped (G8);
   * those of a sender with no open connection lapse within retainMs. */
  revalidate() {
    const now = this.clock();
    const conns = [...this.conns].filter((c) => c.ws);
    if (conns.length) {
      const standing = this.standing(conns);
      for (const [i, conn] of conns.entries()) {
        const s = standing[i];
        if (!s || (conn.expiresAt !== null && now > conn.expiresAt)) {
          if (conn.member) this.forget(conn.member);
          this.close(conn, CLOSE.policy, 'Stream authorization ended');
          continue;
        }
        const expiresAt = minExpiry(conn.expiresAt, s.expiresAt);
        if (expiresAt !== conn.expiresAt) { conn.expiresAt = expiresAt; this.armExpiry(conn); }
        conn.namespaces = s.namespaces ?? [];
        for (const key of [...conn.subs]) if (!conn.namespaces.includes(key.split('\0')[0])) conn.subs.delete(key);
        if (conn.member) {
          for (const [key, r] of this.retained) {
            if (r.from === conn.member && !conn.namespaces.includes(r.namespace)) this.retained.delete(key);
          }
        }
      }
    }
  }

  /** Drop every retained frame of `member` (its access ended). */
  forget(member) {
    for (const [key, r] of this.retained) if (r.from === member) this.retained.delete(key);
  }

  armExpiry(conn) {
    clearTimeout(conn.expiry);
    if (conn.expiresAt === null || conn.expiresAt === undefined) return;
    // The grant is valid through its expiry instant. Long delays must fit the timer range.
    const delay = conn.expiresAt - this.clock() + 1;
    if (delay <= 0) {
      if (conn.member) this.forget(conn.member);
      this.close(conn, CLOSE.policy, 'Stream authorization ended');
      return;
    }
    conn.expiry = setTimeout(() => this.armExpiry(conn), Math.min(delay, 2 ** 31 - 1));
    conn.expiry.unref?.();
  }

  startTimers() {
    if (this.timers) return;
    const ping = setInterval(() => this.pingAll(), this.o.pingMs);
    ping.unref?.();
    const every = Math.min(Math.max(1, this.o.sweepMs), MAX_SWEEP_MS);
    const sweep = setInterval(() => { this.sweep().catch((error) => this.home.note('streams', `stream sweep failed: ${error.message}`)); }, every);
    sweep.unref?.();
    this.timers = { ping, sweep };
  }

  stopTimers() {
    if (!this.timers) return;
    clearInterval(this.timers.ping);
    clearInterval(this.timers.sweep);
    this.timers = null;
  }

  pingAll() {
    const now = Date.now();
    for (const conn of [...this.conns]) {
      if (!conn.ws) continue;
      if (now - conn.lastSeen > this.o.idleMs) {
        this.counters.idle += 1;
        this.close(conn, CLOSE.idle, 'Idle timeout');
        continue;
      }
      try { conn.ws.ping(); } catch { conn.ws.terminate(); }
    }
  }

  /** While streams are open: expired retained frames and tickets go, standing is re-checked at
   * the clock (an expiry, a session ended), and, when the relay runs no scheduler, the home is
   * settled so a removal that falls due is recorded and evicts without waiting for a request. */
  async sweep() {
    const now = Date.now();
    for (const [key, r] of this.retained) if (now - r.at > this.o.retainMs) this.retained.delete(key);
    const clock = this.clock();
    for (const [key, t] of this.tickets) if (clock > t.until) this.tickets.delete(key);
    if (!this.conns.size) return;
    // Standing is re-checked whatever settling does: a failure there must not keep a stream open.
    try { if (!this.home.scheduled) await this.home.lock(() => this.home.settleForRead()); }
    finally { this.revalidate(); }
  }

  /** Close every connection: `restart` (shutdown: clients resume elsewhere or later) or
   * `released` (the slot is gone: do not resume here). */
  closeAll(reason = 'restart') {
    const restart = reason === 'restart';
    for (const conn of [...this.conns]) {
      if (conn.ws && conn.live) this.send(conn, { type: 'bye', reason, resume: restart, ...(restart ? { retryMs: 1000 } : {}) });
      if (conn.ws) this.close(conn, restart ? CLOSE.restart : CLOSE.goingAway, restart ? 'Service restart' : 'Slot released');
      else this.drop(conn);
    }
    this.tickets.clear();
    this.retained.clear();
    this.stopTimers();
  }
}

function minExpiry(a, b) {
  if (a === null || a === undefined) return b ?? null;
  if (b === null || b === undefined) return a;
  return Math.min(a, b);
}

/** A `change` frame for the slot's change-log entry at `index`: the same entry and cursor
 * `GET {base}/changes` gives for it. */
function changeFrame(slot, index) {
  return { type: 'change', cursor: `${slot.instance}.${index + 1}`, entry: slot.entries[index] };
}
