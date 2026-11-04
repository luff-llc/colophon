/* The playground page: colophon surface, content tabs, agent device, intro.
 * Every core call in this file goes to './core' (the mock until the swap).
 */

import * as core from './core';
import {
  AGENT_LABEL,
  loadSettings,
  runActTurn,
  saveSettings,
  type AgentSettings,
} from './agent';
import { DEMO_QUESTION, seedLibrary } from './seed';
import { loadRecords, saveRecords } from './storage';

const IS_MOCK = (core as unknown as { IS_MOCK_CORE?: unknown }).IS_MOCK_CORE === true;
const NAMESPACES = ['listening', 'notes', 'reading'];
const OWNER_LABEL = 'Ada';

const REDUCED = () =>
  typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ------------------------- state ------------------------- */

type Tab = 'listening' | 'notes' | 'reading';

interface State {
  ownerKeys: core.KeyProvider | null;
  library: core.Library | null;
  agentKeys: core.KeyProvider | null;
  agentLibrary: core.Library | null;
  agentMemberID: string | null;
  pending: core.AccessRequest | null;
  consentOpen: boolean;
  verbsDone: { knock: boolean; grant: boolean; act: boolean; end: boolean; recover: boolean };
  busy: string | null;
  tab: Tab;
  showRecordFor: string | null;
  agentPhase: 'idle' | 'knocked' | 'granted' | 'working' | 'ended';
  agentModel: 'scripted' | 'live';
  readingProof: core.Outcome<unknown> | null;
  probeAfterEnd: core.Outcome<unknown> | null;
  recoveredNote: string | null;
  statusMsg: string | null;
  statusErr: string | null;
  activeSheet: 'colophon' | 'library' | 'agent';
  introDone: boolean;
}

const demoMode = () => new URLSearchParams(location.search).has('demo');

/* ------------------------- dom helpers ------------------------- */

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(d);
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ------------------------- app ------------------------- */

export async function boot(root: HTMLElement | null): Promise<void> {
  if (!root) throw new Error('missing #app');
  await core.init();

  const settings: AgentSettings = loadSettings();
  const state: State = {
    ownerKeys: null,
    library: null,
    agentKeys: null,
    agentLibrary: null,
    agentMemberID: null,
    pending: null,
    consentOpen: false,
    verbsDone: { knock: false, grant: false, act: false, end: false, recover: false },
    busy: null,
    tab: 'listening',
    showRecordFor: null,
    agentPhase: 'idle',
    agentModel: settings.apiKey.trim() ? 'live' : 'scripted',
    readingProof: null,
    probeAfterEnd: null,
    recoveredNote: null,
    statusMsg: null,
    statusErr: null,
    activeSheet: 'colophon',
    introDone: false,
  };
  const seenLedger = new Set<string>();
  const recordCache = new Map<string, RecordInspection | null>();
  let lastToolCard: HTMLElement | null = null;

  /* ----- shell ----- */

  const live = el('div', { id: 'live', class: 'sr-only', 'aria-live': 'polite' });
  const announce = (msg: string) => {
    live.textContent = '';
    requestAnimationFrame(() => {
      live.textContent = msg;
    });
  };

  root.append(
    el('a', { class: 'skip', href: '#colophon' }, ['Skip to colophon page']),
    headerEl(),
    demoBarEl(),
    sheetsNavEl(),
    layoutEl(),
    footerEl(),
    settingsDialogEl(),
    introEl(),
    live,
  );

  const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
    const n = document.getElementById(id);
    if (!n) throw new Error(`missing #${id}`);
    return n as T;
  };

  function headerEl(): HTMLElement {
    const themeName = () => (document.documentElement.dataset['theme'] === 'lamplight' ? 'Lamplight' : 'Paper');
    const header = el('header', { class: 'topbar' });
    const h1 = el('h1', { class: 'brand' }, ['Colophon', el('span', { class: 'sub' }, ['playground'])]);
    const badge = el('span', { class: IS_MOCK ? 'badge mock' : 'badge' }, [
      IS_MOCK ? 'preview core' : 'WebAssembly core',
    ]);
    badge.title = IS_MOCK
      ? 'Running the preview core (mock-core.ts) until @colophon/core lands'
      : 'Running the real @colophon/core';
    const spacer = el('span', { class: 'spacer' });
    const themeBtn = el('button', { class: 'icon-button', id: 'btn-theme', type: 'button' }, [`Theme: ${themeName()}`]);
    themeBtn.addEventListener('click', () => {
      const html = document.documentElement;
      const next = html.dataset['theme'] === 'lamplight' ? 'paper' : 'lamplight';
      html.dataset['theme'] = next;
      try {
        localStorage.setItem('colophon.playground.theme', next);
      } catch {
        /* private mode */
      }
      themeBtn.textContent = `Theme: ${next === 'lamplight' ? 'Lamplight' : 'Paper'}`;
    });
    const settingsBtn = el('button', { class: 'icon-button', id: 'btn-settings', type: 'button' }, ['Agent settings']);
    settingsBtn.addEventListener('click', () => {
      syncSettingsForm();
      ($('dlg-settings') as HTMLDialogElement).showModal();
    });
    header.append(h1, badge, spacer, themeBtn, settingsBtn);
    return header;
  }

  function demoBarEl(): HTMLElement {
    const bar = el('div', { class: 'demo-bar', id: 'demo-bar', hidden: demoMode() ? '' : 'x' });
    if (!demoMode()) bar.setAttribute('hidden', '');
    else bar.removeAttribute('hidden');
    bar.append(
      el('span', { class: 'count', id: 'demo-count' }, ['']),
      el('span', { class: 'step', id: 'demo-step' }, ['']),
      el('button', { class: 'next', id: 'demo-next', type: 'button' }, ['Next']),
    );
    bar.querySelector('#demo-next')?.addEventListener('click', () => void demoNext());
    return bar;
  }

  function sheetsNavEl(): HTMLElement {
    const nav = el('nav', { class: 'sheets-nav', id: 'sheets-nav', 'aria-label': 'Panels' });
    const defs: [State['activeSheet'], string][] = [
      ['colophon', 'Colophon'],
      ['library', 'Library'],
      ['agent', 'Agent'],
    ];
    for (const [id, label] of defs) {
      const b = el('button', { type: 'button', role: 'tab', 'data-sheet': id, 'aria-selected': 'false' }, [label]);
      b.addEventListener('click', () => {
        state.activeSheet = id;
        renderSheets();
      });
      nav.append(b);
    }
    return nav;
  }

  function layoutEl(): HTMLElement {
    const main = el('main', { class: 'layout', id: 'main' });
    const library = el('section', { class: 'panel library', id: 'panel-library', 'aria-label': 'Your library' });
    library.append(el('div', { class: 'library-card' }, [el('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Library content', id: 'tabs' }), el('div', { class: 'tab-body', id: 'tab-body', role: 'tabpanel' })]));
    const colophon = el('article', { class: 'panel colophon-page', id: 'colophon', 'aria-label': 'Colophon page', tabindex: '-1' });
    const agent = el('section', { class: 'panel', id: 'panel-agent', 'aria-label': 'Agent device' });
    agent.append(
      el('div', { class: 'agent-device' }, [
        el('div', { class: 'agent-screen' }, [
          el('div', { class: 'agent-bar' }, [
            el('div', { class: 'device-name' }, ['MacBook · Llama']),
            el('div', { class: 'agent-status', id: 'agent-status' }, []),
          ]),
          el('div', { id: 'agent-code-wrap' }),
          el('div', { class: 'agent-log', id: 'agent-log', 'aria-label': 'Agent conversation', 'aria-live': 'off' }),
          el('div', { id: 'agent-proof' }),
          el('div', { id: 'agent-banner' }),
        ]),
      ]),
    );
    main.append(library, colophon, agent);
    return main;
  }

  function footerEl(): HTMLElement {
    return el('footer', { class: 'footer' }, [
      el('p', { id: 'footer-line' }, ['']),
      el('p', {}, ['Keys never leave this tab. Records live in memory and IndexedDB.']),
    ]);
  }

  function settingsDialogEl(): HTMLElement {
    const dlg = document.createElement('dialog');
    dlg.className = 'settings';
    dlg.id = 'dlg-settings';
    dlg.setAttribute('aria-label', 'Agent settings');
    dlg.append(
      el('h2', {}, ['Agent settings']),
      el('p', { class: 'lede' }, [
        'With a key, a real model answers through your library’s tools. Without one, a scripted stand-in performs the same tool calls.',
      ]),
      el('form', { class: 'settings-form', id: 'settings-form', method: 'dialog' }, [
        el('label', { for: 'set-base' }, [
          'Base URL (OpenAI-compatible)',
          el('input', { type: 'text', id: 'set-base', name: 'base', value: '', autocomplete: 'off', spellcheck: 'false' }),
        ]),
        el('label', { for: 'set-model' }, [
          'Model',
          el('input', { type: 'text', id: 'set-model', name: 'model', value: '', autocomplete: 'off', spellcheck: 'false' }),
        ]),
        el('label', { for: 'set-key' }, [
          'API key ',
          el('span', { class: 'hint' }, ['(kept in sessionStorage only; leave blank for the scripted stand-in)']),
          el('input', { type: 'password', id: 'set-key', name: 'key', value: '', autocomplete: 'off', spellcheck: 'false' }),
        ]),
        el('div', { class: 'row' }, [
          el('button', { class: 'button-primary', id: 'set-save', type: 'submit', value: 'save' }, ['Save']),
          el('button', { class: 'button-ghost', id: 'set-close', type: 'submit', value: 'close', formnovalidate: '' }, ['Close']),
        ]),
      ]),
    );
    dlg.querySelector('#settings-form')?.addEventListener('submit', (ev) => {
      const submitter = (ev as SubmitEvent).submitter as HTMLElement | null;
      if (submitter?.id === 'set-save') {
        settings.baseURL = ($('set-base') as HTMLInputElement).value.trim() || settings.baseURL;
        settings.model = ($('set-model') as HTMLInputElement).value.trim() || settings.model;
        settings.apiKey = ($('set-key') as HTMLInputElement).value;
        saveSettings(settings);
        state.agentModel = settings.apiKey.trim() ? 'live' : 'scripted';
        state.statusMsg = settings.apiKey.trim()
          ? `Agent will call ${settings.model} at Act.`
          : 'Agent will run as the scripted stand-in at Act.';
        state.statusErr = null;
        renderAll();
      }
    });
    return dlg;
  }

  function syncSettingsForm(): void {
    ($('set-base') as HTMLInputElement).value = settings.baseURL;
    ($('set-model') as HTMLInputElement).value = settings.model;
    ($('set-key') as HTMLInputElement).value = settings.apiKey;
  }

  /* ----- intro ----- */

  function introEl(): HTMLElement {
    const wrap = el('div', { class: 'intro', id: 'intro', role: 'dialog', 'aria-label': 'Introduction' });
    const stage = el('div', { class: 'stage', id: 'intro-stage' });
    const skip = el('button', { class: 'skip-intro', id: 'intro-skip', type: 'button' }, ['Skip intro']);
    skip.addEventListener('click', () => void skipIntro());
    wrap.append(stage, skip);
    return wrap;
  }

  const introTimers: ReturnType<typeof setTimeout>[] = [];
  const later = (ms: number, fn: () => void) => {
    introTimers.push(setTimeout(fn, ms));
  };
  const clearIntroTimers = () => {
    while (introTimers.length) clearTimeout(introTimers.pop());
  };

  function runIntro(): void {
    const stage = $('intro-stage');
    if (REDUCED()) {
      // Calm path: the two lines, the key line, and a way in.
      stage.append(
        el('div', { class: 'lines' }, [
          el('p', { class: 'big' }, ['Your library lives on your devices.']),
          el('p', { class: 'big' }, ['Your keys decide who gets access.']),
          el('p', { class: 'key-line' }, ['Generating your keys in this tab. They never leave it.']),
        ]),
        el('p', {}, [
          el('button', { class: 'button-primary', id: 'intro-continue', type: 'button' }, ['Open my library']),
        ]),
      );
      $('intro-continue').addEventListener('click', () => void skipIntro());
      return;
    }
    const book = el('div', { class: 'book', id: 'intro-book' });
    book.append(
      el('div', { class: 'cover' }, [el('span', {}, ['C'])]),
      el('div', { class: 'pages' }, [
        el('p', {}, ['Set in Fraunces.']),
        el('p', {}, ['Printed on paper you own.']),
        el('p', {}, ['— the last page']),
      ]),
    );
    stage.append(book, el('div', { class: 'lines', id: 'intro-lines' }));
    later(1200, () => book.classList.add('open'));
    later(5200, () => {
      book.style.display = 'none';
      $('intro-lines').append(
        el('p', { class: 'big' }, ['Your library lives on your devices.']),
        el('p', { class: 'big' }, ['Your keys decide who gets access.']),
      );
    });
    later(9200, () => {
      $('intro-lines').innerHTML = '';
      $('intro-lines').append(
        el('div', { class: 'keys-row' }, [
          el('span', { class: 'glyph', role: 'img', 'aria-label': 'Seal' }, [sealSvg()]),
          el('span', { class: 'glyph', role: 'img', 'aria-label': 'Key' }, [keySvg()]),
        ]),
        el('p', { class: 'key-line' }, ['Generating your keys in this tab. They never leave it.']),
      );
      void createLibrary();
    });
    later(12500, () => void finishIntro());
  }

  function sealSvg(): Node {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.innerHTML = '<circle cx="12" cy="9" r="5"/><path d="M8.5 13.5 7 21l5-2.4L17 21l-1.5-7.5"/>';
    return s as unknown as Node;
  }

  function keySvg(): Node {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.innerHTML = '<circle cx="8" cy="8" r="4"/><path d="M11 11l9 9M17 17l2.5 2.5M14.5 14.5L17 12"/>';
    return s as unknown as Node;
  }

  let creating: Promise<void> | null = null;

  function createLibrary(): Promise<void> {
    if (!creating) {
      creating = (async () => {
        const ownerKeys = await core.WebCryptoKeys.generate();
        const library = await core.Library.create({
          owner: ownerKeys,
          label: `${OWNER_LABEL}'s library`,
          ownerLabel: OWNER_LABEL,
          namespaces: [...NAMESPACES],
        });
        await seedLibrary(library);
        state.ownerKeys = ownerKeys;
        state.library = library;
        await persist();
        renderAll();
      })();
    }
    return creating;
  }

  async function skipIntro(): Promise<void> {
    clearIntroTimers();
    if (!state.introDone) {
      state.busy = 'intro';
      renderDemo();
      await createLibrary().catch((err: unknown) => {
        state.statusErr = err instanceof Error ? err.message : String(err);
      });
      state.busy = null;
      finishIntro();
    }
  }

  function finishIntro(): void {
    if (state.introDone) return;
    // The library must exist before the page reveals; if creation is still
    // running (slow timers beat slow crypto), wait for it first.
    if (!state.library) {
      void createLibrary().then(() => finishIntro());
      return;
    }
    state.introDone = true;
    clearIntroTimers();
    const intro = $('intro');
    intro.classList.add('leaving');
    setTimeout(() => intro.remove(), REDUCED() ? 50 : 750);
    renderAll();
    announce('Your library is ready. This is its colophon page.');
    $('colophon').focus({ preventScroll: true });
  }

  /* ----- persistence ----- */

  async function persist(): Promise<void> {
    if (!state.library) return;
    try {
      await saveRecords(state.library.records);
    } catch (err) {
      console.warn('could not persist records', err);
    }
  }

  /* ----- the five verbs ----- */

  async function doKnock(): Promise<void> {
    if (!state.library || state.busy || state.verbsDone.knock) return;
    state.busy = 'knock';
    state.statusErr = null;
    renderAll();
    try {
      const agentKeys = await core.WebCryptoKeys.generate();
      const pending = await core.Library.requestAccess({
        libraryID: state.library.id,
        keys: agentKeys,
        label: AGENT_LABEL,
        kind: 'agent',
        namespaces: ['listening', 'notes'],
        access: ['read', 'write'],
      });
      // File the request so it ledgers. Mock-only helper; otherwise merge.
      const note = (state.library as unknown as { noteRequest?: (r: Uint8Array) => Promise<void> }).noteRequest;
      if (typeof note === 'function') await note.call(state.library, pending.record);
      else state.library.merge(new Map([[`requests/${pending.id}.json`, pending.record]]));
      state.agentKeys = agentKeys;
      state.pending = pending;
      state.consentOpen = true;
      state.agentPhase = 'knocked';
      state.verbsDone.knock = true;
      agentLogNotice(`${AGENT_LABEL} is asking to join. Its pairing code is below — check it matches the library’s.`);
      await persist();
      announce(`${AGENT_LABEL} knocked. A consent card waits on the colophon page.`);
    } catch (err) {
      state.statusErr = err instanceof Error ? err.message : String(err);
    } finally {
      state.busy = null;
      renderAll();
    }
  }

  async function doGrant(): Promise<void> {
    if (!state.library || !state.pending || state.busy || state.verbsDone.grant) return;
    state.busy = 'grant';
    state.statusErr = null;
    renderAll();
    try {
      const readOnly = ($('grant-readonly') as HTMLInputElement | null)?.checked ?? false;
      const expirySel = ($('grant-expiry') as HTMLSelectElement | null)?.value ?? 'never';
      const budgetRaw = ($('grant-budget') as HTMLInputElement | null)?.value ?? '';
      const partial: Partial<core.Grant> = { namespaces: [...state.pending.namespaces] };
      partial.access = readOnly ? ['read'] : [...state.pending.access];
      if (expirySel === 'hour') partial.expires = new Date(Date.now() + 3600_000).toISOString();
      if (expirySel === 'day') partial.expires = new Date(Date.now() + 86400_000).toISOString();
      const budget = Number.parseInt(budgetRaw, 10);
      if (Number.isFinite(budget) && budget > 0) partial.writeBudget = Math.floor(budget);
      const outcome = await state.library.approve(state.pending.record, partial);
      if (!outcome.ok) {
        state.statusErr = outcome.detail;
        return;
      }
      if (!state.agentKeys) throw new Error('agent keys went missing');
      state.agentLibrary = await core.Library.open(state.library.records, state.agentKeys);
      state.agentMemberID = outcome.value.id;
      state.pending = null;
      state.consentOpen = false;
      state.agentPhase = 'granted';
      state.verbsDone.grant = true;
      // Prove the negative early: the agent's view of reading is notGranted.
      state.readingProof = await state.agentLibrary.call('reading_list', {});
      agentLogNotice('Access granted. This device can read listening and write notes — nothing else.');
      await persist();
      announce(`Granted. ${outcome.value.label} joined the library.`);
    } catch (err) {
      state.statusErr = err instanceof Error ? err.message : String(err);
    } finally {
      state.busy = null;
      renderAll();
    }
  }

  async function doAct(): Promise<void> {
    if (!state.agentLibrary || state.busy || state.verbsDone.act) return;
    state.busy = 'act';
    state.statusErr = null;
    state.agentPhase = 'working';
    renderAll();
    agentLogPerson(DEMO_QUESTION);
    try {
      await runActTurn(state.agentLibrary, settings, DEMO_QUESTION, (e) => agentEvent(e));
      state.readingProof = await state.agentLibrary.call('reading_list', {});
      state.verbsDone.act = true;
      state.agentPhase = 'granted';
      await persist();
      announce('The agent finished. Its notes are in your notebook, marked as written by AI.');
    } catch (err) {
      state.statusErr = err instanceof Error ? err.message : String(err);
      state.agentPhase = 'granted';
    } finally {
      state.busy = null;
      renderAll();
    }
  }

  async function doEnd(): Promise<void> {
    if (!state.library || !state.agentLibrary || !state.agentMemberID || state.busy || state.verbsDone.end) return;
    state.busy = 'end';
    state.statusErr = null;
    renderAll();
    try {
      const outcome = await state.library.revoke(state.agentMemberID);
      if (!outcome.ok) {
        state.statusErr = outcome.detail;
        return;
      }
      // Its next tool call visibly fails.
      const probe = await state.agentLibrary.call('notes_list', {});
      state.probeAfterEnd = probe;
      appendToolCard('notes_list', {}, probe);
      state.agentPhase = 'ended';
      state.verbsDone.end = true;
      await persist();
      const notes = countAINotes();
      announce(`Access ended. Its ${notes} notes stay, marked as written by AI.`);
    } catch (err) {
      state.statusErr = err instanceof Error ? err.message : String(err);
    } finally {
      state.busy = null;
      renderAll();
    }
  }

  async function doRecover(): Promise<void> {
    if (!state.library || !state.ownerKeys || state.busy || state.verbsDone.recover) return;
    state.busy = 'recover';
    state.statusErr = null;
    state.statusMsg = 'Closing this tab’s memory…';
    await persist();
    const dropped = state.library.records.size;
    state.library = null;
    state.agentLibrary = null;
    renderAll();
    announce('Closing in-memory state. Reopening from stored records.');
    try {
      await new Promise((r) => setTimeout(r, REDUCED() ? 60 : 700));
      const stored = await loadRecords();
      if (!stored || stored.size === 0) throw new Error('No stored records found in this browser.');
      const library = await core.Library.open(stored, state.ownerKeys);
      state.library = library;
      if (state.agentKeys) state.agentLibrary = await core.Library.open(stored, state.agentKeys);
      state.verbsDone.recover = true;
      state.recoveredNote = `Rebuilt from ${stored.size} stored records (dropped ${dropped} in-memory). Same page, same keys.`;
      state.statusMsg = null;
      announce(state.recoveredNote);
    } catch (err) {
      state.statusErr = err instanceof Error ? err.message : String(err);
      state.statusMsg = null;
    } finally {
      state.busy = null;
      renderAll();
    }
  }

  /* ----- guided demo mode (?demo) ----- */

  function demoStepIndex(): number {
    if (!state.introDone || !state.library) return 0;
    if (!state.verbsDone.knock) return 1;
    if (!state.verbsDone.grant) return 2;
    if (!state.verbsDone.act) return 3;
    if (!state.verbsDone.end) return 4;
    if (!state.verbsDone.recover) return 5;
    return 6;
  }

  async function demoNext(): Promise<void> {
    if (!demoMode() || state.busy) return;
    const step = demoStepIndex();
    if (step === 0) await skipIntro();
    else if (step === 1) await doKnock();
    else if (step === 2) await doGrant();
    else if (step === 3) await doAct();
    else if (step === 4) await doEnd();
    else if (step === 5) await doRecover();
  }

  /* ----- agent log (append-only; the other device keeps its own history) ----- */

  function agentLogEl(): HTMLElement {
    return $('agent-log');
  }

  function scrollAgent(): void {
    const log = agentLogEl();
    log.scrollTop = log.scrollHeight;
  }

  function agentLogNotice(text: string): void {
    agentLogEl().append(el('p', { class: 'agent-notice' }, [text]));
    scrollAgent();
  }

  function agentLogPerson(text: string): void {
    agentLogEl().append(el('p', { class: 'msg person' }, [text]));
    scrollAgent();
  }

  async function agentLogAgent(text: string): Promise<void> {
    const p = el('p', { class: 'msg agent' }, []);
    agentLogEl().append(p);
    scrollAgent();
    if (REDUCED()) {
      p.textContent = text;
      return;
    }
    // Typed out, a few characters at a time.
    const span = el('span', { class: 'caret' }, []);
    p.append(span);
    const step = 3;
    for (let i = 0; i < text.length; i += step) {
      span.textContent = text.slice(0, i + step);
      if (i % 24 === 0) scrollAgent();
      await new Promise((r) => setTimeout(r, 14));
    }
    span.classList.remove('caret');
    span.textContent = text;
    scrollAgent();
  }

  function summarizeOutcome(name: string, outcome: core.Outcome<unknown>): string {
    if (!outcome.ok) return `${outcome.reason}: ${outcome.detail}`;
    const v = outcome.value as Record<string, unknown>;
    if (name === 'listening_list_episodes') {
      const eps = (v['episodes'] as { title?: string }[] | undefined) ?? [];
      return `${eps.length} episode${eps.length === 1 ? '' : 's'}${eps[0]?.title ? ` — first: “${String(eps[0].title)}”` : ''}`;
    }
    if (name === 'listening_get_transcript') {
      const c = typeof v['citation'] === 'string' ? (v['citation'] as string) : 'transcript';
      const t = typeof v['text'] === 'string' ? (v['text'] as string) : '';
      return `${c} (${t.length} chars)`;
    }
    if (name === 'notes_write') {
      const note = v['note'] as { id?: string; origin?: string } | undefined;
      return `admitted${note?.id ? ` · ${String(note.id)}` : ''}${note?.origin ? ` · origin ${String(note.origin)}` : ''}`;
    }
    const s = JSON.stringify(outcome.value);
    return s.length > 140 ? `${s.slice(0, 140)}…` : s;
  }

  function appendToolCard(name: string, input: unknown, outcome: core.Outcome<unknown> | null): HTMLElement {
    const card = el('div', { class: outcome ? (outcome.ok ? 'tool-card ok' : 'tool-card fail') : 'tool-card' });
    card.append(el('div', { class: 't-name' }, [`◈ ${name}`]));
    const io = JSON.stringify(input);
    if (io !== '{}') card.append(el('p', { class: 't-io' }, [`in: ${io.length > 160 ? `${io.slice(0, 160)}…` : io}`]));
    if (outcome) {
      const r = el('p', { class: outcome.ok ? 't-result ok-text' : 't-result' }, [outcome.ok ? `✓ ${summarizeOutcome(name, outcome)}` : `✕ ${summarizeOutcome(name, outcome)}`]);
      card.append(r);
    }
    agentLogEl().append(card);
    scrollAgent();
    lastToolCard = outcome ? null : card;
    return card;
  }

  async function agentEvent(e: import('./agent').AgentEvent): Promise<void> {
    if (e.type === 'message') await agentLogAgent(e.text);
    else if (e.type === 'notice') agentLogNotice(e.text);
    else if (e.type === 'tool_call') appendToolCard(e.name, e.input, null);
    else if (e.type === 'tool_result') {
      const card = lastToolCard;
      lastToolCard = null;
      if (card) {
        card.classList.add(e.outcome.ok ? 'ok' : 'fail');
        card.append(
          el('p', { class: e.outcome.ok ? 't-result ok-text' : 't-result' }, [
            e.outcome.ok ? `✓ ${summarizeOutcome(e.name, e.outcome)}` : `✕ ${summarizeOutcome(e.name, e.outcome)}`,
          ]),
        );
        scrollAgent();
      } else {
        appendToolCard(e.name, {}, e.outcome);
      }
      if (e.outcome.ok && e.name === 'notes_write') renderContent();
    }
  }

  /* ----- content folds (from admitted operations; swap-proof) ----- */

  interface FoldEpisode {
    id: string;
    showTitle: string;
    title: string;
    published: string;
    durationSec: number;
    excerpt: string;
    transcript: string;
  }
  interface FoldNote {
    id: string;
    opId: string;
    notebook: string;
    title: string;
    text: string;
    origin: 'person' | 'ai';
    authorLabel: string;
    created: string;
  }
  interface FoldLink {
    id: string;
    url: string;
    title: string;
    saved: string;
  }

  function str(v: unknown): string {
    return typeof v === 'string' ? v : '';
  }

  function foldListening(ops: core.OperationView[]): { shows: string[]; episodes: FoldEpisode[] } {
    const shows = new Map<string, string>();
    const eps = new Map<string, { showId: string; title: string; published: string; durationSec: number }>();
    const transcripts = new Map<string, string>();
    for (const op of ops) {
      const p = (op.payload ?? {}) as Record<string, unknown>;
      // Order-independent: references may fold before what they name.
      if (op.kind === 'show.follow' && str(p['showId'])) shows.set(str(p['showId']), str(p['title']) || 'Untitled show');
      else if (op.kind === 'episode.add' && str(p['episodeId'])) {
        if (str(p['showId']) && !shows.has(str(p['showId']))) shows.set(str(p['showId']), 'Unknown show');
        eps.set(str(p['episodeId']), {
          showId: str(p['showId']),
          title: str(p['title']) || 'Untitled episode',
          published: str(p['published']),
          durationSec: typeof p['durationSec'] === 'number' ? (p['durationSec'] as number) : 0,
        });
      } else if (op.kind === 'episode.transcript' && str(p['episodeId'])) {
        transcripts.set(str(p['episodeId']), str(p['text']));
      }
    }
    const episodes: FoldEpisode[] = [...eps.entries()].map(([id, e]) => {
      const t = transcripts.get(id) ?? '';
      return {
        id,
        showTitle: shows.get(e.showId) ?? 'Unknown show',
        title: e.title,
        published: e.published,
        durationSec: e.durationSec,
        transcript: t,
        excerpt: t.length > 200 ? `${t.slice(0, 200)}…` : t,
      };
    });
    return { shows: [...shows.values()], episodes };
  }

  function foldNotes(ops: core.OperationView[]): { notebooks: { id: string; title: string; cells: FoldNote[] }[] } {
    const notebooks = new Map<string, { id: string; title: string; cells: FoldNote[] }>();
    for (const op of ops) {
      const p = (op.payload ?? {}) as Record<string, unknown>;
      if (op.kind === 'notebook.create' && str(p['notebookId'])) {
        const id = str(p['notebookId']);
        const existing = notebooks.get(id);
        if (existing) existing.title = str(p['title']) || existing.title;
        else notebooks.set(id, { id, title: str(p['title']) || 'Notebook', cells: [] });
      } else if (op.kind === 'cell.put' && str(p['notebookId'])) {
        const nbId = str(p['notebookId']);
        let nb = notebooks.get(nbId);
        if (!nb) {
          // A note arriving before its notebook opens a shell; the later
          // notebook.create fills in the title.
          nb = { id: nbId, title: 'Untitled notebook', cells: [] };
          notebooks.set(nbId, nb);
        }
        const cellId = str(p['cellId']) || op.id;
        const cell: FoldNote = {
          id: cellId,
          opId: op.id,
          notebook: nb.id,
          title: str(p['title']),
          text: str(p['text']),
          origin: op.origin,
          authorLabel: op.authorLabel,
          created: op.created,
        };
        const ix = nb.cells.findIndex((c) => c.id === cellId);
        if (ix >= 0) nb.cells[ix] = cell;
        else nb.cells.push(cell);
      }
    }
    return { notebooks: [...notebooks.values()] };
  }

  function foldReading(ops: core.OperationView[]): FoldLink[] {
    const items: FoldLink[] = [];
    for (const op of ops) {
      const p = (op.payload ?? {}) as Record<string, unknown>;
      if (op.kind === 'capture.link' && str(p['itemId'])) {
        items.push({ id: str(p['itemId']), url: str(p['url']), title: str(p['title']) || 'Untitled', saved: op.created });
      }
    }
    return items;
  }

  function admitted(ns: Tab): core.OperationView[] {
    if (!state.library) return [];
    const v = state.library.view(ns);
    return v.ok ? v.value.admitted : [];
  }

  function countAINotes(): number {
    return foldNotes(admitted('notes')).notebooks.reduce(
      (n, nb) => n + nb.cells.filter((c) => c.origin === 'ai').length,
      0,
    );
  }

  /* ----- "show the record" ----- */

  interface RecordInspection {
    path: string;
    recordPretty: string;
    sealedBytes: number;
    authorLabel: string;
    origin: 'person' | 'ai';
    verified: boolean | null; // null: shown raw; the core checked it on open
  }

  async function inspectRecord(opId: string): Promise<RecordInspection | null> {
    if (!state.library) return null;
    const cached = recordCache.get(opId);
    if (cached !== undefined) return cached;
    // Preferred: the core's own inspection (mock). Otherwise read the stored
    // bytes straight from the live records view.
    const op = (state.library as unknown as { operationRecord?: (id: string) => Promise<{
      path: string; record: string; sealedBytes: number; authorLabel: string; origin: 'person' | 'ai'; verified: boolean;
    } | null> }).operationRecord;
    if (typeof op === 'function') {
      const r = await op.call(state.library, opId);
      if (!r) {
        recordCache.set(opId, null);
        return null;
      }
      const insp: RecordInspection = {
        path: r.path,
        recordPretty: pretty(r.record),
        sealedBytes: r.sealedBytes,
        authorLabel: r.authorLabel,
        origin: r.origin,
        verified: r.verified,
      };
      recordCache.set(opId, insp);
      return insp;
    }
    for (const [path, bytes] of state.library.records) {
      if (path.endsWith(`-${opId}.json`)) {
        const raw = new TextDecoder().decode(bytes);
        let sealedBytes = 0;
        try {
          const rec = JSON.parse(raw) as { body?: string };
          const header = JSON.parse(atobToText(rec.body ?? '')) as { sealed?: string };
          sealedBytes = header.sealed ? Math.ceil((header.sealed.length * 3) / 4) : 0;
        } catch {
          /* show what we have */
        }
        const insp: RecordInspection = {
          path,
          recordPretty: pretty(raw),
          sealedBytes,
          authorLabel: '',
          origin: 'person',
          verified: null,
        };
        recordCache.set(opId, insp);
        return insp;
      }
    }
    recordCache.set(opId, null);
    return null;
  }

  function atobToText(b64: string): string {
    try {
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder().decode(bytes);
    } catch {
      return '';
    }
  }

  function pretty(rawJson: string): string {
    try {
      return JSON.stringify(JSON.parse(rawJson) as unknown, null, 2);
    } catch {
      return rawJson;
    }
  }

  /* ----- rendering ----- */

  function renderAll(): void {
    renderColophon();
    renderContent();
    renderAgent();
    renderDemo();
    renderSheets();
    renderFooter();
  }

  function renderColophon(): void {
    const page = $('colophon');
    page.innerHTML = '';
    if (!state.library) {
      page.append(
        el('h2', {}, ['Colophon']),
        el('p', { class: 'belongs' }, [state.busy === 'recover' ? 'Rebuilding from stored records…' : 'Preparing your library…']),
      );
      if (state.statusErr) {
        page.append(el('p', { class: 'status-line error' }, [state.statusErr]));
        const retry = el('button', { type: 'button', class: 'button-ghost', id: 'replay' }, ['Reload the playground']);
        page.append(el('p', {}, [retry]));
      }
      return;
    }
    const members = new Map(state.library.members().map((m) => [m.id, m]));
    const revoked = new Set([...members.values()].filter((m) => m.revokedAt !== null).map((m) => m.id));
    page.append(el('h2', {}, ['Colophon']));
    page.append(
      el('p', { class: 'belongs' }, [
        'This library belongs to ',
        el('strong', {}, [OWNER_LABEL]),
        '. It lives in this browser tab.',
      ]),
    );
    if (state.recoveredNote) page.append(el('p', { class: 'status-line' }, [state.recoveredNote]));

    const ledger = el('ol', { class: 'ledger', id: 'ledger', 'aria-label': 'Library ledger' });
    for (const e of state.library.ledger()) {
      const key = `${e.sequence}|${e.event}|${e.subject ?? ''}|${e.text}`;
      const fresh = !seenLedger.has(key);
      seenLedger.add(key);
      const cls: string[] = [];
      if (fresh) cls.push('fresh');
      if (e.event === 'granted' && e.subject && revoked.has(e.subject)) cls.push('struck');
      if (e.event === 'revoked') cls.push('revoked-line');
      if (e.event === 'rekeyed') cls.push('rekey');
      const li = el('li', { class: cls.join(' ') });
      li.append(el('span', { class: 'seq', 'aria-hidden': 'true' }, [String(e.sequence).padStart(2, '0')]));
      const words = el('span', { class: 'words' }, [e.text]);
      const actor = members.get(e.actor);
      if ((e.event === 'wrote' || e.event === 'granted' || e.event === 'requested') && actor?.kind === 'agent') {
        words.append(el('span', { class: 'ai-mark ai-tag' }, ['AI']));
      }
      li.append(words);
      const when = fmtTime(e.at);
      if (when) li.append(el('span', { class: 'when' }, [when]));
      ledger.append(li);
    }
    page.append(ledger);

    // Verbs
    const verbs = el('div', { class: 'verbs' });
    verbs.append(el('h3', {}, ['Five moments']));
    const row = el('div', { class: 'verb-row' });
    const defs: [keyof State['verbsDone'], string, boolean][] = [
      ['knock', 'Knock', !!state.library && !state.verbsDone.knock && !state.busy],
      ['grant', 'Grant', state.verbsDone.knock && !!state.pending && !state.verbsDone.grant && !state.busy],
      ['act', 'Act', state.verbsDone.grant && !!state.agentLibrary && !state.verbsDone.act && !state.busy],
      ['end', 'End', state.verbsDone.act && !state.verbsDone.end && !state.busy],
      ['recover', 'Recover', state.verbsDone.end && !state.verbsDone.recover && !state.busy],
    ];
    let nextMarked = false;
    defs.forEach(([id, label, enabled], i) => {
      const done = state.verbsDone[id];
      const isNext = enabled && !nextMarked;
      if (isNext) nextMarked = true;
      const b = el(
        'button',
        {
          type: 'button',
          class: `verb${done ? ' done' : ''}${isNext ? ' next' : ''}`,
          'data-verb': id,
          ...(enabled ? {} : { disabled: '', 'aria-disabled': 'true' }),
          ...(done ? { 'aria-label': `${label}, completed` } : {}),
        },
        [el('span', { class: 'n', 'aria-hidden': 'true' }, [done ? '✓' : String(i + 1)]), label],
      );
      row.append(b);
    });
    verbs.append(row);
    verbs.append(el('p', { class: 'verb-hint', id: 'verb-hint' }, [verbHint()]));
    if (Object.values(state.verbsDone).every(Boolean)) {
      verbs.append(el('p', {}, [el('button', { type: 'button', class: 'button-ghost', id: 'replay' }, ['Replay the tour'])]));
    }
    page.append(verbs);

    // Consent
    if (state.pending && !state.verbsDone.grant && state.consentOpen) page.append(consentCard());
    else if (state.pending && !state.verbsDone.grant) {
      page.append(
        el('p', { class: 'pending-chip' }, [
          `A request from ${state.pending.label} is waiting. `,
          el('button', { type: 'button', id: 'pending-review' }, ['Review request']),
        ]),
      );
    }
    if (state.statusMsg) page.append(el('p', { class: 'status-line' }, [state.statusMsg]));
    if (state.statusErr) page.append(el('p', { class: 'status-line error' }, [state.statusErr]));
    if (state.busy && state.busy !== 'intro') {
      const last = page.querySelector('#verb-hint');
      if (last) last.textContent = `${verbLabel(state.busy)}…`;
    }
  }

  function verbLabel(id: string): string {
    return { knock: 'Knocking', grant: 'Granting', act: 'The agent is working', end: 'Ending access', recover: 'Recovering' }[id] ?? 'Working';
  }

  function verbHint(): string {
    const v = state.verbsDone;
    if (!v.knock) return 'First, the agent knocks.';
    if (!v.grant) return state.consentOpen ? 'Check the codes match, narrow if you like, then Grant.' : 'A request is waiting — review it when ready.';
    if (!v.act) return 'Now let it work: Act. It reads, answers with a citation, and writes notes.';
    if (!v.end) return 'One tap ends its access. Its notes stay.';
    if (!v.recover) return 'Drop this tab’s memory and rebuild from stored records.';
    return 'That was the whole tour: knock, grant, act, end, recover.';
  }

  function consentCard(): HTMLElement {
    const p = state.pending;
    if (!p) return el('div', {}, []);
    const reads = p.access.includes('read') ? p.namespaces : [];
    const writes = p.access.includes('write') ? p.namespaces : [];
    const others = NAMESPACES.filter((n) => !p.namespaces.includes(n));
    const card = el('div', { class: 'consent', id: 'consent', role: 'group', 'aria-label': `Access request from ${p.label}` });
    card.append(
      el('h4', {}, [`${p.label} is asking to join`]),
      el('p', { class: 'kind-line' }, ['Member kind: AI agent · it holds its own keys on its own device']),
      el('div', { class: 'codes' }, [
        el('div', { class: 'code-side' }, [el('div', { class: 'who' }, ['This library shows']), el('p', { class: 'code' }, [p.pairingCode])]),
        el('div', { class: 'code-side' }, [el('div', { class: 'who' }, [`${p.label} shows`]), el('p', { class: 'code' }, [p.pairingCode])]),
      ]),
      el('p', { class: 'scope' }, [
        reads.length > 0 && writes.length > 0 && reads.join() === writes.join()
          ? `Read and write ${andJoin(reads.map((n) => `your ${n}`))}. `
          : `${reads.length > 0 ? `Read ${andJoin(reads.map((n) => `your ${n}`))}. ` : ''}${writes.length > 0 ? `Write ${andJoin(writes.map((n) => n))}. ` : ''}`,
        others.length > 0 ? el('span', { class: 'not' }, [`Not your ${andJoin(others)}.`]) : '',
      ]),
    );
    const fieldset = el('fieldset', {}, [el('legend', {}, ['Narrow the grant (optional)'])]);
    const narrow = el('div', { class: 'narrow' });
    const roLabel = el('label', { for: 'grant-readonly' }, [
      (() => {
        const c = document.createElement('input');
        c.type = 'checkbox';
        c.id = 'grant-readonly';
        return c;
      })(),
      'Read-only',
    ]);
    const expLabel = el('label', { for: 'grant-expiry' }, [
      'Access ends ',
      (() => {
        const s = document.createElement('select');
        s.id = 'grant-expiry';
        for (const [v, t] of [['never', 'Never'], ['hour', 'In one hour'], ['day', 'In one day']] as [string, string][]) {
          const o = document.createElement('option');
          o.value = v;
          o.textContent = t;
          s.append(o);
        }
        return s;
      })(),
    ]);
    const budgetLabel = el('label', { for: 'grant-budget' }, [
      'Write budget ',
      (() => {
        const n = document.createElement('input');
        n.type = 'number';
        n.id = 'grant-budget';
        n.min = '1';
        n.placeholder = 'Unlimited';
        n.setAttribute('aria-label', 'Write budget, blank for unlimited');
        return n;
      })(),
    ]);
    narrow.append(roLabel, expLabel, budgetLabel);
    fieldset.append(narrow);
    card.append(fieldset);
    const actions = el('div', { class: 'actions' });
    const approve = el('button', { type: 'button', class: 'button-primary', id: 'grant-approve' }, ['Grant access']);
    const laterBtn = el('button', { type: 'button', class: 'button-ghost', id: 'grant-later' }, ['Not now']);
    actions.append(approve, laterBtn);
    card.append(actions);
    return card;
  }

  function andJoin(parts: string[]): string {
    if (parts.length <= 1) return parts.join('');
    return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
  }

  /* ----- content tabs ----- */

  function renderContent(): void {
    const tabs = $('tabs');
    tabs.innerHTML = '';
    const defs: [Tab, string][] = [['listening', 'Listening'], ['notes', 'Notes'], ['reading', 'Reading']];
    for (const [id, label] of defs) {
      const selected = state.tab === id;
      const b = el(
        'button',
        { type: 'button', role: 'tab', id: `tab-${id}`, 'aria-selected': selected ? 'true' : 'false', tabindex: selected ? '0' : '-1' },
        [label],
      );
      tabs.append(b);
    }
    const body = $('tab-body');
    body.innerHTML = '';
    body.setAttribute('aria-labelledby', `tab-${state.tab}`);
    if (!state.library) {
      body.append(el('p', { class: 'empty-note' }, ['Your library is on its way.']));
      return;
    }
    if (state.tab === 'listening') renderListening(body);
    else if (state.tab === 'notes') renderNotes(body);
    else renderReading(body);
  }

  function renderListening(body: HTMLElement): void {
    const { episodes } = foldListening(admitted('listening'));
    body.append(el('h3', {}, ['Listening']));
    if (episodes.length === 0) {
      body.append(el('p', { class: 'empty-note' }, ['Nothing saved yet.']));
      return;
    }
    for (const e of episodes) {
      const mins = Math.round(e.durationSec / 60);
      const art = el('article', { class: 'episode' });
      art.append(
        el('div', { class: 'show' }, [e.showTitle]),
        el('p', { class: 'title' }, [e.title]),
        el('p', { class: 'meta' }, [`${e.published}${mins > 0 ? ` · ${mins} min` : ''}`]),
      );
      if (e.excerpt) art.append(el('p', { class: 'excerpt' }, [`“${e.excerpt}”`]));
      if (e.transcript) {
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = 'Read the saved excerpt';
        const t = el('p', { class: 'transcript' }, [e.transcript]);
        details.append(summary, t);
        art.append(details);
      }
      body.append(art);
    }
  }

  function renderNotes(body: HTMLElement): void {
    const { notebooks } = foldNotes(admitted('notes'));
    body.append(el('h3', {}, ['Notes']));
    if (notebooks.length === 0) {
      body.append(el('p', { class: 'empty-note' }, ['No notebooks yet.']));
      return;
    }
    const pendingFills: [string, string, 'person' | 'ai'][] = [];
    for (const nb of notebooks) {
      body.append(el('h3', {}, [nb.title]));
      if (nb.cells.length === 0) {
        body.append(el('p', { class: 'empty-note' }, ['Empty — nothing written here yet.']));
        continue;
      }
      for (const c of nb.cells) {
        const cell = el('article', { class: 'note-cell' });
        const head = el('div', { class: 'note-head' });
        head.append(el('span', { class: 'note-title' }, [c.title || 'Untitled note']));
        if (c.origin === 'ai') head.append(el('span', { class: 'ai-mark' }, ['AI']));
        cell.append(head);
        cell.append(el('p', { class: 'byline' }, [`by ${c.authorLabel}${fmtTime(c.created) ? ` · ${fmtTime(c.created)}` : ''}`]));
        if (c.text) cell.append(el('p', { class: 'text' }, [c.text]));
        const open = state.showRecordFor === c.opId;
        const toggle = el(
          'button',
          {
            type: 'button',
            class: 'record-toggle',
            'data-record': c.opId,
            'aria-expanded': open ? 'true' : 'false',
            'aria-controls': `record-${esc(c.opId)}`,
          },
          [open ? 'Hide the record' : 'Show the record'],
        );
        cell.append(toggle);
        if (open) {
          cell.append(el('div', { class: 'record-view', id: `record-${c.opId}` }, ['Checking the record…']));
          pendingFills.push([c.opId, c.authorLabel, c.origin]);
        }
        body.append(cell);
      }
    }
    // Fill after appending: fillRecordView looks the box up in the document.
    for (const [opId, authorLabel, origin] of pendingFills) void fillRecordView(opId, authorLabel, origin);
  }

  async function fillRecordView(opId: string, authorLabel: string, origin: 'person' | 'ai'): Promise<void> {
    const box = document.getElementById(`record-${opId}`);
    if (!box) return;
    const insp = await inspectRecord(opId);
    box.innerHTML = '';
    if (!insp) {
      box.append(el('p', {}, ['No stored record found for this note.']));
      return;
    }
    if (insp.verified === true) {
      const line = el('p', { class: 'verified' }, [`✓ Signature verified. Written by ${insp.authorLabel || authorLabel}.`]);
      if ((insp.origin || origin) === 'ai') line.append(' ', el('span', { class: 'ai-mark' }, ['AI']));
      box.append(line);
    } else if (insp.verified === false) {
      box.append(el('p', {}, ['✕ The signature did not verify.']));
    } else {
      box.append(el('p', {}, [`Stored bytes for ${authorLabel}’s note. The core checked the signature when the library opened.`]));
    }
    const dl = document.createElement('dl');
    dl.append(
      (() => {
        const dt = document.createElement('dt');
        dt.textContent = 'Record';
        return dt;
      })(),
      (() => {
        const dd = document.createElement('dd');
        dd.textContent = insp.path;
        return dd;
      })(),
      (() => {
        const dt = document.createElement('dt');
        dt.textContent = 'Sealed bytes';
        return dt;
      })(),
      (() => {
        const dd = document.createElement('dd');
        dd.textContent = insp.sealedBytes > 0 ? String(insp.sealedBytes) : '—';
        return dd;
      })(),
    );
    box.append(dl);
    const pre = el('pre', {}, [insp.recordPretty]);
    box.append(pre);
    box.append(el('p', { class: 'byline' }, ['Pretty-printed for reading; the signature covers the stored bytes.']));
  }

  function renderReading(body: HTMLElement): void {
    const items = foldReading(admitted('reading'));
    body.append(el('h3', {}, ['Reading']));
    body.append(el('p', { class: 'empty-note' }, ['The agent was never granted this shelf.']));
    if (items.length === 0) {
      body.append(el('p', { class: 'empty-note' }, ['Nothing saved yet.']));
      return;
    }
    for (const item of items) {
      const div = el('div', { class: 'link-item' });
      const a = document.createElement('a');
      a.href = item.url;
      a.textContent = item.title;
      a.rel = 'noopener';
      div.append(a);
      div.append(el('p', { class: 'url' }, [item.url]));
      body.append(div);
    }
  }

  /* ----- agent panel ----- */

  function renderAgent(): void {
    const log = agentLogEl();
    if (!log.firstChild) {
      log.append(el('p', { class: 'agent-empty', id: 'agent-empty' }, ['Nothing yet. When the agent knocks, its side of the conversation appears here.']));
    }
    const status = $('agent-status');
    status.className = `agent-status${state.agentPhase === 'granted' || state.agentPhase === 'working' ? ' live' : ''}${state.agentPhase === 'ended' ? ' ended' : ''}`;
    const dot = el('span', { class: 'dot', 'aria-hidden': 'true' }, []);
    const label =
      state.agentPhase === 'idle'
        ? 'Waiting'
        : state.agentPhase === 'knocked'
          ? 'Knocking…'
          : state.agentPhase === 'working'
            ? 'Working…'
            : state.agentPhase === 'ended'
              ? 'Access ended'
              : state.agentModel === 'live'
                ? 'Has access · live model'
                : 'Has access · scripted stand-in';
    status.innerHTML = '';
    status.append(dot, label);

    const codeWrap = $('agent-code-wrap');
    codeWrap.innerHTML = '';
    if (state.pending && !state.verbsDone.grant) {
      codeWrap.append(
        el('div', { class: 'agent-code' }, [
          el('div', { class: 'who' }, [`${state.pending.label} shows`]),
          el('p', { class: 'code' }, [state.pending.pairingCode]),
        ]),
      );
    }
    const proof = $('agent-proof');
    proof.innerHTML = '';
    if (state.readingProof && state.verbsDone.grant) {
      const box = el('div', { class: 'reading-proof' });
      box.append(el('h5', {}, ['Reading, as Llama sees it']));
      if (state.readingProof.ok) {
        const items = (state.readingProof.value as { items?: unknown[] }).items;
        box.append(el('p', {}, [`${Array.isArray(items) ? items.length : 0} items visible.`]));
      } else {
        box.append(el('code', {}, [state.readingProof.reason]));
        box.append(el('p', {}, [state.readingProof.detail]));
      }
      proof.append(box);
    }
    const banner = $('agent-banner');
    banner.innerHTML = '';
    if (state.agentPhase === 'ended') {
      const notes = state.library ? countAINotes() : 0;
      banner.append(
        el('div', { class: 'access-banner' }, [
          `Access ended. Its ${notes} note${notes === 1 ? '' : 's'} stay${notes === 1 ? 's' : ''}, marked as written by AI.`,
        ]),
      );
    }
  }

  function clearAgentPlaceholder(): void {
    document.getElementById('agent-empty')?.remove();
  }

  /* ----- demo bar / sheets / footer ----- */

  function renderDemo(): void {
    if (!demoMode()) return;
    const steps = [
      'Intro — your keys are born in this tab',
      'Knock — the agent asks to join',
      'Grant — you approve, narrowed if you like',
      'Act — it reads, answers, and writes notes',
      'End — access ends, its notes stay',
      'Recover — rebuilt from stored records',
      'Done — the whole tour',
    ];
    const i = demoStepIndex();
    $('demo-count').textContent = `Step ${Math.min(i + 1, 7)} of 7`;
    $('demo-step').textContent = steps[i] ?? '';
    ($('demo-next') as HTMLButtonElement).disabled = state.busy !== null || i >= 6;
  }

  function renderSheets(): void {
    const nav = $('sheets-nav');
    for (const b of nav.querySelectorAll('button')) {
      b.setAttribute('aria-selected', (b as HTMLElement).dataset['sheet'] === state.activeSheet ? 'true' : 'false');
    }
    const map: Record<State['activeSheet'], string> = { colophon: 'colophon', library: 'panel-library', agent: 'panel-agent' };
    for (const [sheet, id] of Object.entries(map)) {
      document.getElementById(id)?.classList.toggle('active', sheet === state.activeSheet);
    }
  }

  function renderFooter(): void {
    const records = state.library ? state.library.records.size : 0;
    $('footer-line').textContent =
      `Agent: ${state.agentModel === 'live' ? 'live model' : 'scripted stand-in'} · ` +
      `${state.library ? `${records} records in memory` : 'no library yet'}${IS_MOCK ? ' · preview core' : ''}`;
  }

  /* ----- events (delegated; panels re-render) ----- */

  $('colophon').addEventListener('click', (ev) => {
    const t = ev.target as HTMLElement;
    const verb = t.closest('[data-verb]') as HTMLElement | null;
    if (verb) {
      const id = verb.dataset['verb'];
      if (id === 'knock') void doKnock();
      else if (id === 'grant') {
        state.consentOpen = true;
        renderColophon();
        document.getElementById('grant-approve')?.focus();
      } else if (id === 'act') void doAct();
      else if (id === 'end') void doEnd();
      else if (id === 'recover') void doRecover();
      return;
    }
    if (t.closest('#grant-approve')) void doGrant();
    else if (t.closest('#grant-later')) {
      state.consentOpen = false;
      renderColophon();
    } else if (t.closest('#pending-review')) {
      state.consentOpen = true;
      renderColophon();
      document.getElementById('grant-approve')?.focus();
    } else if (t.closest('#replay')) location.reload();
  });

  $('tabs').addEventListener('click', (ev) => {
    const t = (ev.target as HTMLElement).closest('[role="tab"]') as HTMLElement | null;
    if (!t) return;
    const id = t.id.replace('tab-', '') as Tab;
    if (id === 'listening' || id === 'notes' || id === 'reading') {
      state.tab = id;
      renderContent();
    }
  });

  $('tabs').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft' && ev.key !== 'Home' && ev.key !== 'End') return;
    ev.preventDefault();
    const order: Tab[] = ['listening', 'notes', 'reading'];
    let i = order.indexOf(state.tab);
    if (ev.key === 'ArrowRight') i = (i + 1) % 3;
    else if (ev.key === 'ArrowLeft') i = (i + 2) % 3;
    else if (ev.key === 'Home') i = 0;
    else i = 2;
    state.tab = order[i] as Tab;
    renderContent();
    document.getElementById(`tab-${state.tab}`)?.focus();
  });

  $('tab-body').addEventListener('click', (ev) => {
    const t = (ev.target as HTMLElement).closest('[data-record]') as HTMLElement | null;
    if (!t?.dataset['record']) return;
    const opId = t.dataset['record'];
    state.showRecordFor = state.showRecordFor === opId ? null : opId;
    renderContent();
  });

  /* ----- go ----- */

  // The first real log entry removes the placeholder.
  const logObserver = new MutationObserver(() => {
    const empty = document.getElementById('agent-empty');
    if (empty && agentLogEl().children.length > 1) empty.remove();
  });
  logObserver.observe(agentLogEl(), { childList: true });
  void clearAgentPlaceholder;

  renderAll();
  runIntro();
}
