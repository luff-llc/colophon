/**
 * What a library screen shows for each phase, and when to lock: the web twin of the Swift `GateModel`, with no
 * framework. An app renders `gateContent(session.state, session.hasUsableContent)` and wires `attachPageLifecycle`.
 */
import type { ColophonSession } from './session.js';
import { failureMessage, type SessionPhase, type SessionState } from './types.js';

export type GateAction = 'create' | 'join' | 'rejoin' | 'retry' | 'checkAgain' | 'cancelPairing' | 'unlock';
export type GateContent =
  /** Show the library, with an optional status line above it (stale content during a refresh or a retry). */
  | { kind: 'content'; status?: string; actions: GateAction[] }
  /** Show a full screen instead of the library. */
  | { kind: 'screen'; id: string; title: string; message: string; busy: boolean; actions: GateAction[] };

/** The words for a stopped account (the `stopped` phase): a verified state of the account, shown as what it is. No error, no
 *  retry: this app must be updated to continue, and what this device holds stays readable. */
export const StoppedWords = {
  title: 'Update to continue',
  message: 'This account was moved to a newer format. Update the app to continue. What this device already holds stays readable here; nothing is changed or lost.',
  status: 'This account was moved to a newer format; update the app to continue. You can still read what this device holds.',
} as const;

const screen = (id: string, title: string, message: string, actions: GateAction[] = [], busy = false): GateContent => ({ kind: 'screen', id, title, message, busy, actions });

/** The engine's phase as a screen. Content is shown only while the session says it is usable. */
export function gateContent(state: Pick<SessionState, 'phase'>, usable: boolean): GateContent {
  const phase: SessionPhase = state.phase;
  if (usable) {
    if (phase.kind === 'ready' || phase.kind === 'refreshing') return { kind: 'content', actions: [] };
    if (phase.kind === 'retry') return { kind: 'content', status: 'Refresh failed', actions: ['retry'] };
    if (phase.kind === 'waitingForDownload') return { kind: 'content', status: 'Updating your library…', actions: ['retry'] };
    if (phase.kind === 'stopped') return { kind: 'content', status: StoppedWords.status, actions: [] };
  }
  switch (phase.kind) {
    case 'ready': case 'refreshing': case 'opening': return screen('library.opening', 'Opening your library', '', [], true);
    case 'noLibrary': return screen('library.none', 'No library yet', 'Create a library on this device, or join the one you already have.', ['create', 'join']);
    case 'creating': return screen('library.creating', 'Creating your library', '', [], true);
    case 'locked': return screen('library.locked', 'Locked', 'Your library is locked.', ['unlock']);
    case 'waitingForDownload': return screen('library.downloading', 'Updating your library', '', ['retry'], true);
    case 'retry': return screen('library.retry', "Couldn't open your library", 'Retry to try again.', ['retry']);
    case 'stopped': return screen('library.stopped', StoppedWords.title, StoppedWords.message);
    case 'updateRequired': return screen('library.updateRequired', 'Update required', 'Your library was written by a newer version. Nothing is lost and nothing was changed. Update this app to open it.');
    case 'waitingForApproval': return screen('library.waiting', 'Waiting for approval', 'On a device you already use, scan this device\'s request, or pair with the six-digit code. Approve only when both devices show the same code.', ['checkAgain', 'cancelPairing']);
    case 'denied': return screen('library.denied', 'Access ended', 'This device no longer has access to the library.', ['rejoin']);
    case 'unavailable': return screen('library.unavailable', 'Library unavailable', phase.reason, ['retry']);
    case 'failed': return screen('library.failed', "Couldn't open your library", failureMessage(phase.failure), ['retry']);
  }
}

/** Runs a gate action on the session. `join` and `rejoin` are the app's (they need a screen and new keys). */
export async function performGateAction(session: ColophonSession, action: GateAction): Promise<void> {
  switch (action) {
    case 'create': return session.create();
    case 'retry': return session.retry();
    case 'checkAgain': await session.syncNow(); return session.refresh();
    case 'cancelPairing': return session.leave();
    case 'unlock': return session.unlock();
    case 'join': case 'rejoin': return;
  }
}

export interface PageLifecycleOptions {
  /** Lock this long after the page is hidden (default 0: at once). `'never'` leaves locking to the app. */
  lockAfterMs?: number | 'never';
  document?: Pick<Document, 'visibilityState' | 'addEventListener' | 'removeEventListener'>;
}
/**
 * Locks the session when the page is hidden and unlocks (or refreshes) it when it is shown again, so no secret stays
 * in a tab nobody is looking at. Unlocking a device member key is silent. Returns the function that detaches.
 */
export function attachPageLifecycle(session: ColophonSession, options: PageLifecycleOptions = {}): () => void {
  const doc = options.document ?? globalThis.document;
  if (!doc) return () => {};
  const after = options.lockAfterMs ?? 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const onChange = (): void => {
    clearTimeout(timer); timer = undefined;
    if (doc.visibilityState === 'hidden') {
      if (after === 'never' || session.phase.kind === 'locked') return;
      if (after === 0) session.lock(); else timer = setTimeout(() => session.lock(), after);
    } else if (session.phase.kind === 'locked') void session.unlock();
    else void session.refresh();
  };
  doc.addEventListener('visibilitychange', onChange);
  return () => { clearTimeout(timer); doc.removeEventListener('visibilitychange', onChange); };
}
