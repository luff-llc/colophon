/* The agent: Muse when the server proxy has a key, otherwise a scripted
 * stand-in that performs the same tool calls. Both paths act only through
 * Library.tools() and Library.call(), and the agent holds its own keys.
 *
 * The API key is never in the browser: the Vite dev/preview servers proxy
 * /api/muse/* to the Meta API and add Authorization from MUSE_API_KEY.
 * All wire-format details stay in this file.
 */

import type { Library, NamespaceView, Outcome } from './core';

export const DEFAULT_MODEL = 'muse-spark-1.3';

/** Same-origin proxy path (see vite.config.ts). Never carries a key. */
export const MUSE_PROXY_PATH = '/api/muse';

export const AGENT_LABEL = 'Muse on MacBook';

declare const __MUSE_AVAILABLE__: boolean | undefined;

/** True when the server was started with MUSE_API_KEY (baked at serve/build time). */
export function museAvailable(): boolean {
  try {
    return typeof __MUSE_AVAILABLE__ !== 'undefined' && __MUSE_AVAILABLE__ === true;
  } catch {
    return false;
  }
}

export interface AgentSettings {
  model: string;
}

export type AgentEvent =
  | { type: 'message'; text: string }
  | { type: 'tool_call'; name: string; input: unknown }
  | { type: 'tool_result'; name: string; outcome: Outcome<unknown> }
  | { type: 'notice'; text: string }
  | { type: 'done' };

export type Emit = (e: AgentEvent) => void | Promise<void>;

const LS_MODEL = 'colophon.playground.model';

export function loadSettings(): AgentSettings {
  let model = DEFAULT_MODEL;
  try {
    model = localStorage.getItem(LS_MODEL) || DEFAULT_MODEL;
    // Drop pre-integration settings; the key was never persisted to disk.
    localStorage.removeItem('colophon.playground.baseURL');
    sessionStorage.removeItem('colophon.playground.apiKey');
  } catch {
    // Storage unavailable (private mode): run scripted with defaults.
  }
  return { model };
}

export function saveSettings(s: AgentSettings): void {
  try {
    localStorage.setItem(LS_MODEL, s.model);
  } catch {
    // Ignore; the settings still apply for this tab.
  }
}

/** Run the Act turn: answer the question from listening, then write 3 notes. */
export async function runActTurn(
  agentLibrary: Library,
  settings: AgentSettings,
  question: string,
  emit: Emit,
): Promise<void> {
  if (museAvailable()) {
    try {
      await runLive(agentLibrary, settings, question, emit);
      return;
    } catch (err) {
      await emit({
        type: 'notice',
        text: `The Muse call failed (${err instanceof Error ? err.message : 'network error'}). The scripted stand-in takes over so the demo continues.`,
      });
    }
  } else {
    await emit({
      type: 'notice',
      text: 'Scripted agent (no MUSE_API_KEY) — performing the same tool calls Muse would.',
    });
  }
  await runScripted(agentLibrary, question, emit);
}

/* ------------------------- scripted stand-in ------------------------- */

interface PodcastEpisode {
  id: string;
  show?: string;
  title?: string;
  transcriptExcerpt?: string;
}

async function runScripted(library: Library, question: string, emit: Emit): Promise<void> {
  await emit({ type: 'message', text: `On it — “${question}” I'll search your listening for the answer.` });

  await emit({ type: 'tool_call', name: 'listening.podcasts__read', input: {} });
  const list = await library.call('listening.podcasts__read', {});
  await emit({ type: 'tool_result', name: 'listening.podcasts__read', outcome: list });
  if (!list.ok) {
    await emit({ type: 'message', text: 'I could not read your listening, so there is nothing to answer from.' });
    await emit({ type: 'done' });
    return;
  }
  const view = list.value as NamespaceView<{
    shows?: { id: string; title?: string }[];
    episodes?: PodcastEpisode[];
  }>;
  const episodes = view.state?.episodes ?? [];
  const hit = episodes.find((e) => /foghorn/i.test(e.title ?? '')) ?? episodes[0];
  if (!hit) {
    await emit({ type: 'message', text: 'Your listening is empty, so there is nothing to answer from.' });
    await emit({ type: 'done' });
    return;
  }
  const showTitle = view.state?.shows?.find((s) => s.id === hit.show)?.title ?? 'your listening';
  const citation = `${showTitle}, “${hit.title ?? hit.id}”`;

  let answer =
    'Keeper Ilsa Brandt logged the weather in the margins — “Sleet, gulls quiet” — though the regulation only asked for sounding times. Nobody required it; she gave the fog a diary anyway, and decades later the acoustics lab uses those margins to calibrate its models. The unofficial record became the useful one.';
  const m = /“[^”]+”/.exec(hit.transcriptExcerpt ?? '');
  if (m) {
    answer =
      `Keeper Ilsa Brandt logged the weather in the margins — ${m[0]} — though the regulation only asked for sounding times. ` +
      'Nobody required it; she gave the fog a diary anyway, and decades later the acoustics lab uses those margins to calibrate its models. The unofficial record became the useful one.';
  }
  await emit({ type: 'message', text: `${answer}\n\nSource: ${citation}.` });

  await emit({ type: 'tool_call', name: 'notes__read', input: {} });
  const shelf = await library.call('notes__read', {});
  await emit({ type: 'tool_result', name: 'notes__read', outcome: shelf });
  let notebook = 'nb-field';
  if (shelf.ok) {
    const notebooks = (shelf.value as NamespaceView<{ notebooks?: { id: string }[] }>).state?.notebooks ?? [];
    if (notebooks[0]?.id) notebook = notebooks[0].id;
  }

  const stamp = Date.now().toString(36);
  const notes = [
    {
      title: 'The margin beats the form',
      text: 'The Harbour Tape, “The Foghorn Ledger”: keeper Ilsa Brandt logged weather (“Sleet, gulls quiet”) the regulation never asked for. Twenty years of unofficial margins now calibrate the acoustics lab’s models.',
    },
    {
      title: 'Nobody asked her',
      text: 'Brandt’s diary of the fog was voluntary record-keeping. Lesson: the records people keep for love outlast the records the rules demand.',
    },
    {
      title: 'Unofficial becomes load-bearing',
      text: 'The lab depends on margins that were never part of the spec. If we keep our own notes this way — small, regular, in the margins — someone (maybe us) will thank us in twenty years.',
    },
  ];
  for (const [i, n] of notes.entries()) {
    const input = { id: `muse-note-${stamp}-${i + 1}`, notebook, title: n.title, text: n.text };
    await emit({ type: 'tool_call', name: 'notes__addNote', input });
    const r = await library.call('notes__addNote', input);
    await emit({ type: 'tool_result', name: 'notes__addNote', outcome: r });
  }
  await emit({
    type: 'message',
    text: 'I saved three notes to your notebook, each signed as written by me. I never opened your reading — I was never granted it.',
  });
  await emit({ type: 'done' });
}

/* ------------------------- live model path ------------------------- */

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: { id: string; type: 'function'; function: { name: string; arguments: string } }[];
  tool_call_id?: string;
  name?: string;
}

function toChatTools(library: Library): unknown[] {
  return library.tools().map((t) => ({
    type: 'function',
    function: { name: t.name, description: t.description, parameters: t.inputSchema },
  }));
}

function outcomeToText(o: Outcome<unknown>): string {
  if (o.ok) return JSON.stringify(o.value);
  return `ERROR (${o.reason}): ${o.detail}`;
}

async function runLive(
  library: Library,
  settings: AgentSettings,
  question: string,
  emit: Emit,
): Promise<void> {
  const messages: ChatMessage[] = [
    {
      role: 'system',
      content:
        'You are Muse, an AI agent invited into the person’s personal library. ' +
        'You can read their listening (podcasts) and write notes. You were never granted their reading (saved links): ' +
        'never call reading tools, and say plainly that you cannot see reading. ' +
        'First read listening.podcasts to find the episode that answers the question, using its transcriptExcerpt. ' +
        'Answer with a spoken citation (show, episode). ' +
        'Then read notes to find the first notebook id, and write exactly three short attributed notes via notes__addNote, ' +
        'each with a unique id like muse-note-<random>-<n>, the notebook id, a short title, and the note text. ' +
        'Keep every message short — two or three sentences.',
    },
    { role: 'user', content: question },
  ];
  const tools = toChatTools(library);
  for (let round = 0; round < 10; round++) {
    // Same-origin; the server proxy adds Authorization from MUSE_API_KEY.
    const res = await fetch(`${MUSE_PROXY_PATH}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: settings.model.trim(), messages, tools, tool_choice: 'auto' }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}${text ? `: ${text.slice(0, 160)}` : ''}`);
    }
    const data = (await res.json()) as {
      choices?: { message?: { content?: string | null; tool_calls?: ChatMessage['tool_calls'] } }[];
      error?: { message?: string };
    };
    if (data.error?.message) throw new Error(data.error.message);
    const msg = data.choices?.[0]?.message;
    if (!msg) throw new Error('empty response');
    if (msg.content) {
      messages.push({ role: 'assistant', content: msg.content });
      await emit({ type: 'message', text: msg.content });
    }
    const calls = msg.tool_calls ?? [];
    if (calls.length === 0) break;
    messages.push({ role: 'assistant', content: msg.content ?? null, tool_calls: calls });
    for (const c of calls) {
      let input: unknown = {};
      try {
        input = JSON.parse(c.function.arguments || '{}') as unknown;
      } catch {
        input = {};
      }
      await emit({ type: 'tool_call', name: c.function.name, input });
      const outcome = await library.call(c.function.name, input);
      await emit({ type: 'tool_result', name: c.function.name, outcome });
      messages.push({ role: 'tool', tool_call_id: c.id, content: outcomeToText(outcome) });
    }
  }
  await emit({ type: 'done' });
}
