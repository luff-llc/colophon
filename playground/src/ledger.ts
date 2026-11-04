/* Ledger grouping for the colophon page: writes by the same actor in the same
 * namespace fold into one expandable line ("Ada saved 3 links").
 *
 * Pure logic, no DOM: the app renders these rows, and the Node walkthrough
 * checks them against the real core. The core is adding `namespace`, `kind`
 * and `origin` to LedgerEntry; use them when present and fall back to parsing
 * the current write sentences ("<label> wrote <kind> in <namespace>") when
 * absent, so grouping works before and after the core change lands. Nothing
 * here matches grant/revoke/rekey text, which the core is rewording.
 *
 * Grouping spans the whole ledger rather than just consecutive runs: the core
 * clocks each namespace separately and sorts by (clock, author, id), so one
 * actor's namespaces interleave and even the agent's three notes are not
 * adjacent. Each group sits at its first entry; the app scrolls fresh groups
 * into view, so new writes still surface.
 */

export interface LedgerEntryLike {
  sequence: number;
  at: string;
  actor: string;
  actorLabel: string;
  event: string;
  subject?: string;
  text: string;
  /** New core fields; absent until the ledger change lands. */
  namespace?: string;
  kind?: string;
  origin?: string;
}

export interface MemberLike {
  id: string;
  kind: string;
}

export interface WriteGroup {
  actor: string;
  actorLabel: string;
  namespace: string;
  /** Short display name for the namespace ("listening", "notes", "reading"). */
  display: string;
  entries: LedgerEntryLike[];
  /** Distinct operation kinds in the group, in first-seen order. */
  kinds: string[];
  /** True when the writer is (or wrote as) an AI agent. */
  ai: boolean;
  firstSeq: number;
  lastSeq: number;
  /** Time of the newest entry, for the group line. */
  at: string;
}

export type LedgerRow = { type: 'entry'; entry: LedgerEntryLike } | { type: 'writes'; group: WriteGroup };

/** Current core write sentences; only used when namespace/kind are absent. */
const WROTE_RE = /^(.+?)\s+wrote\s+(.+?)\s+in\s+(.+?)\s*$/;

interface KindWords {
  verb: string;
  singular: string;
  plural: string;
}

const KIND_WORDS: Record<string, KindWords> = {
  capture: { verb: 'saved', singular: 'link', plural: 'links' },
  addNote: { verb: 'added', singular: 'note', plural: 'notes' },
  editNote: { verb: 'edited', singular: 'note', plural: 'notes' },
  createNotebook: { verb: 'created', singular: 'notebook', plural: 'notebooks' },
  follow: { verb: 'followed', singular: 'show', plural: 'shows' },
  unfollow: { verb: 'unfollowed', singular: 'show', plural: 'shows' },
  episode: { verb: 'saved', singular: 'episode', plural: 'episodes' },
};

function fallbackKind(entry: LedgerEntryLike): string {
  if (entry.kind) return entry.kind;
  const m = WROTE_RE.exec(entry.text);
  return m?.[2] ?? '';
}

function fallbackNamespace(entry: LedgerEntryLike): string {
  if (entry.namespace) return entry.namespace;
  const m = WROTE_RE.exec(entry.text);
  return m?.[3] ?? '';
}

function isAI(entry: LedgerEntryLike, members: ReadonlyMap<string, MemberLike>): boolean {
  if (entry.origin === 'ai') return true;
  if (entry.origin === 'person') return false;
  return members.get(entry.actor)?.kind === 'agent';
}

/**
 * Fold `wrote` entries by the same actor in the same namespace into
 * WriteGroups. Every other event passes through untouched, and writes whose
 * namespace cannot be determined stay single so they are never merged
 * wrongly. Groups stay open across intervening rows (see the note above) and
 * sit at their first entry, in first-seen order.
 */
export function groupLedger(
  entries: LedgerEntryLike[],
  members: ReadonlyMap<string, MemberLike>,
  displayName: (namespace: string) => string,
): LedgerRow[] {
  const rows: LedgerRow[] = [];
  const open = new Map<string, WriteGroup>();
  for (const entry of entries) {
    if (entry.event !== 'wrote') {
      rows.push({ type: 'entry', entry });
      continue;
    }
    const namespace = fallbackNamespace(entry);
    if (!namespace) {
      rows.push({ type: 'entry', entry });
      continue;
    }
    const key = `${entry.actor} ${namespace}`;
    let group = open.get(key);
    if (!group) {
      group = {
        actor: entry.actor,
        actorLabel: entry.actorLabel,
        namespace,
        display: displayName(namespace),
        entries: [],
        kinds: [],
        ai: isAI(entry, members),
        firstSeq: entry.sequence,
        lastSeq: entry.sequence,
        at: entry.at,
      };
      open.set(key, group);
      rows.push({ type: 'writes', group });
    }
    group.entries.push(entry);
    group.lastSeq = entry.sequence;
    group.at = entry.at;
    if (!group.ai && isAI(entry, members)) group.ai = true;
    const kind = fallbackKind(entry);
    if (kind && !group.kinds.includes(kind)) group.kinds.push(kind);
  }
  return rows;
}

/**
 * One plain line for a write group. Single-kind groups name what was written
 * ("Ada saved 3 links"); mixed or unknown kinds fall back to the namespace
 * ("Ada added 6 to listening"). A lone unknown write keeps its own sentence.
 */
export function summarizeWrites(group: WriteGroup): string {
  const n = group.entries.length;
  const single = group.kinds.length === 1 ? (group.kinds[0] as string) : '';
  const words = single ? KIND_WORDS[single] : undefined;
  if (words) return `${group.actorLabel} ${words.verb} ${n} ${n === 1 ? words.singular : words.plural}`;
  if (n === 1) return group.entries[0]?.text ?? `${group.actorLabel} wrote in ${group.display}`;
  return `${group.actorLabel} added ${n} to ${group.display}`;
}

/**
 * Sequence gutter: a range when the group's entries sit together in the
 * ledger ("03–08"), otherwise the sequence of its first entry, where the line
 * sits. Ledger sequences are dense, so the span test means adjacency.
 */
export function groupSeq(group: WriteGroup): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  const adjacent = group.lastSeq - group.firstSeq + 1 === group.entries.length;
  return adjacent && group.firstSeq !== group.lastSeq
    ? `${pad(group.firstSeq)}–${pad(group.lastSeq)}`
    : pad(group.firstSeq);
}
