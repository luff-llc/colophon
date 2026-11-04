/* The agent: a real model when a key is configured, otherwise a scripted
 * stand-in that performs the same tool calls. Both paths act only through
 * Library.tools() and Library.call(), and the agent holds its own keys.
 */

import type { Library, Outcome } from './core';

export const DEFAULT_BASE_URL = 'https://api.llama.com/compat/v1';
export const DEFAULT_MODEL = 'Llama-4-Maverick-17B-128E-Instruct-FP8';

export const AGENT_LABEL = 'Llama on MacBook';

export interface AgentSettings {
  baseURL: string;
  model: string;
  apiKey: string; // sessionStorage only, never committed, never persisted to disk
}

export type AgentEvent =
  | { type: 'message'; text: string }
  | { type: 'tool_call'; name: string; input: unknown }
  | { type: 'tool_result'; name: string; outcome: Outcome<unknown> }
  | { type: 'notice'; text: string }
  | { type: 'done' };

export type Emit = (e: AgentEvent) => void | Promise<void>;

const LS_BASE = 'colophon.playground.baseURL';
const LS_MODEL = 'colophon.playground.model';
const SS_KEY = 'colophon.playground.apiKey';

export function loadSettings(): AgentSettings {
  let baseURL = DEFAULT_BASE_URL;
  let model = DEFAULT_MODEL;
  let apiKey = '';
  try {
    baseURL = localStorage.getItem(LS_BASE) || DEFAULT_BASE_URL;
    model = localStorage.getItem(LS_MODEL) || DEFAULT_MODEL;
    apiKey = sessionStorage.getItem(SS_KEY) || '';
  } catch {
    // Storage unavailable (private mode): run scripted with defaults.
  }
  return { baseURL, model, apiKey };
}

export function saveSettings(s: AgentSettings): void {
  try {
    localStorage.setItem(LS_BASE, s.baseURL);
    localStorage.setItem(LS_MODEL, s.model);
    if (s.apiKey) sessionStorage.setItem(SS_KEY, s.apiKey);
    else sessionStorage.removeItem(SS_KEY);
  } catch {
    // Ignore; the settings still apply for this tab.
  }
}

/**
 * Where to POST chat completions. The default Llama base URL goes through the
 * Vite dev proxy (see vite.config.ts) when served from localhost, so the demo
 * never fights CORS. Custom base URLs (Ollama, another gateway) are used as-is.
 */
export function endpointForBaseURL(baseURL: string): string {
  const trimmed = baseURL.trim().replace(/\/+$/, '');
  const host = typeof location !== 'undefined' ? location.hostname : '';
  const local = host === 'localhost' || host === '127.0.0.1' || host === '';
  if (local && (trimmed === DEFAULT_BASE_URL || trimmed.startsWith('https://api.llama.com'))) {
    return '/llama-api';
  }
  return trimmed;
}

/** Run the Act turn: answer the question from listening, then write 3 notes. */
export async function runActTurn(
  agentLibrary: Library,
  settings: AgentSettings,
  question: string,
  emit: Emit,
): Promise<void> {
  if (settings.apiKey.trim()) {
    try {
      await runLive(agentLibrary, settings, question, emit);
      return;
    } catch (err) {
      await emit({
        type: 'notice',
        text: `The live model call failed (${err instanceof Error ? err.message : 'network error'}). The scripted stand-in takes over so the demo continues.`,
      });
    }
  } else {
    await emit({
      type: 'notice',
      text: 'No key configured — the scripted stand-in performs the same tool calls a model would.',
    });
  }
  await runScripted(agentLibrary, question, emit);
}

/* ------------------------- scripted stand-in ------------------------- */

async function runScripted(library: Library, question: string, emit: Emit): Promise<void> {
  await emit({ type: 'message', text: `On it — “${question}” I'll search your listening for the answer.` });

  await emit({ type: 'tool_call', name: 'listening_list_episodes', input: {} });
  const list = await library.call('listening_list_episodes', {});
  await emit({ type: 'tool_result', name: 'listening_list_episodes', outcome: list });

  let episodeId = '';
  let citation = 'your listening';
  if (list.ok) {
    const eps = (list.value as { episodes?: { id: string; title: string }[] }).episodes ?? [];
    const hit = eps.find((e) => /foghorn/i.test(e.title)) ?? eps[0];
    if (hit) episodeId = hit.id;
  }
  if (!episodeId) {
    await emit({ type: 'message', text: 'Your listening is empty, so there is nothing to answer from.' });
    await emit({ type: 'done' });
    return;
  }

  const tInput = { episode: episodeId };
  await emit({ type: 'tool_call', name: 'listening_get_transcript', input: tInput });
  const t = await library.call('listening_get_transcript', tInput);
  await emit({ type: 'tool_result', name: 'listening_get_transcript', outcome: t });

  let answer =
    'Keeper Ilsa Brandt logged the weather in the margins — “Sleet, gulls quiet” — though the regulation only asked for sounding times. Nobody required it; she gave the fog a diary anyway, and decades later the acoustics lab uses those margins to calibrate its models. The unofficial record became the useful one.';
  if (t.ok) {
    const v = t.value as { citation?: string; text?: string };
    if (v.citation) citation = v.citation;
    const m = /“[^”]+”/.exec(v.text ?? '');
    if (m) {
      answer =
        `Keeper Ilsa Brandt logged the weather in the margins — ${m[0]} — though the regulation only asked for sounding times. ` +
        'Nobody required it; she gave the fog a diary anyway, and decades later the acoustics lab uses those margins to calibrate its models. The unofficial record became the useful one.';
    }
  }
  await emit({ type: 'message', text: `${answer}\n\nSource: ${citation}.` });

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
  for (const n of notes) {
    const input = { title: n.title, text: n.text };
    await emit({ type: 'tool_call', name: 'notes_write', input });
    const r = await library.call('notes_write', input);
    await emit({ type: 'tool_result', name: 'notes_write', outcome: r });
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

function toOpenAITools(library: Library): unknown[] {
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
  const endpoint = endpointForBaseURL(settings.baseURL);
  const messages: ChatMessage[] = [
    {
      role: 'system',
      content:
        'You are Llama, an AI agent invited into the person’s personal library. ' +
        'You can read their listening (podcasts) and write notes. You were never granted their reading (saved links): ' +
        'never call reading tools, and say plainly that you cannot see reading. ' +
        'Answer the person’s question using the tools, with a spoken citation (show, episode, date). ' +
        'Then write exactly three short notes capturing what you learned, via notes_write. ' +
        'Keep every message short — two or three sentences.',
    },
    { role: 'user', content: question },
  ];
  const tools = toOpenAITools(library);
  for (let round = 0; round < 8; round++) {
    const res = await fetch(`${endpoint}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${settings.apiKey.trim()}` },
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
