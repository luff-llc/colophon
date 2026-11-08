/* Believable public-domain-style seed content, written for this demo.
 * Two invented podcast shows with short transcript excerpts, three saved
 * links to well-known public sites, and one empty notebook.
 */

import type { Library } from './core';

export const EPISODE_IDS = { harbourTape: 'ep-harbour-014', margins: 'ep-margins-022', knots: 'ep-knots-007' };

const TRANSCRIPTS: Record<string, { showId: string; showTitle: string; feed: string; title: string; published: string; durationSec: number; text: string }> = {
  [EPISODE_IDS.harbourTape]: {
    showId: 'show-harbour',
    showTitle: 'The Harbour Tape',
    feed: 'https://example.org/feeds/harbour-tape.xml',
    title: 'Fourteen: The Foghorn Ledger',
    published: '2026-09-18',
    durationSec: 1842,
    text:
      'MARA: The foghorn ledger is my favourite object in the harbour office. Every sounding since 1961, in pencil, in the same hand for the first twenty years. ' +
      'JONAS: Keeper Ilsa Brandt. She logged the weather in the margins. “Sleet, gulls quiet.” That is the whole entry for March 3rd, 1974. ' +
      'MARA: What I love is that nobody asked her to do it. The regulation only wanted times. She gave the fog a diary anyway. ' +
      'JONAS: And now the acoustics lab uses those margins to calibrate their models. The unofficial record became the useful one.',
  },
  [EPISODE_IDS.margins]: {
    showId: 'show-margins',
    showTitle: 'Margins',
    feed: 'https://example.org/feeds/margins.xml',
    title: 'Twenty-two: Borrowing a Library Card',
    published: '2026-10-02',
    durationSec: 2210,
    text:
      'DEV: When I moved to the city I had no proof of address, so no library card, so no books. My neighbour lent me hers for a year. ' +
      'PRIYA: That is the whole thesis of the episode, really. Access is a social object before it is a technical one. Somebody vouches. ' +
      'DEV: And she could see everything I borrowed, which kept me honest. I read better books that year than any year since. ' +
      'PRIYA: Visibility plus consent. We keep rebuilding that with cryptography and forgetting the neighbour part.',
  },
  [EPISODE_IDS.knots]: {
    showId: 'show-knots',
    showTitle: 'Knots & Volts',
    feed: 'https://example.org/feeds/knots-volts.xml',
    title: 'Seven: Splicing Fibre at Sea',
    published: '2026-10-24',
    durationSec: 1568,
    text:
      'ANA: You splice fibre on a moving ship the same way you do it on land, except the land is lying to you. The deck moves; your hands learn the swell. ' +
      'THEO: How many splices in the repair? ' +
      'ANA: Forty-one. Each one tested before the next. Slow is fast when the nearest spare spool is nine hundred kilometres behind you. ' +
      'THEO: There is a proverb in there about writing things down as you go. ' +
      'ANA: The logbook is the splice that holds the crew together. I will die on this hill, which is also moving.',
  },
};

export const SEED_LINKS = [
  { itemId: 'link-gutenberg', url: 'https://www.gutenberg.org/', title: 'Project Gutenberg' },
  { itemId: 'link-mdn', url: 'https://developer.mozilla.org/', title: 'MDN Web Docs' },
  { itemId: 'link-wiki', url: 'https://en.wikipedia.org/wiki/Colophon_(publishing)', title: 'Colophon (publishing) — Wikipedia' },
];

export const SEED_NOTEBOOK = { id: 'nb-field', title: 'Field notes' };

export async function seedLibrary(library: Library): Promise<void> {
  const followed = new Set<string>();
  for (const epId of Object.values(EPISODE_IDS)) {
    const ep = TRANSCRIPTS[epId];
    if (!ep) continue;
    if (!followed.has(ep.showId)) {
      followed.add(ep.showId);
      const r = await library.write('listening.podcasts', 'follow', { id: ep.showId, url: ep.feed, title: ep.showTitle });
      if (!r.ok) throw new Error(`seed follow failed: ${r.reason}`);
    }
    // Use the listening schema’s date-time and duration fields.
    const a = await library.write('listening.podcasts', 'episode', {
      id: epId,
      show: ep.showId,
      title: ep.title,
      transcriptExcerpt: ep.text,
      published: `${ep.published}T00:00:00Z`,
      duration: ep.durationSec,
    });
    if (!a.ok) throw new Error(`seed episode failed: ${a.reason}`);
  }
  for (const link of SEED_LINKS) {
    const r = await library.write('reading.saved', 'capture', { id: link.itemId, url: link.url, title: link.title });
    if (!r.ok) throw new Error(`seed capture failed: ${r.reason}`);
  }
  const nb = await library.write('notes', 'createNotebook', { id: SEED_NOTEBOOK.id, title: SEED_NOTEBOOK.title });
  if (!nb.ok) throw new Error(`seed createNotebook failed: ${nb.reason}`);
}

/** The question the scripted (and suggested-to-real) agent answers in Act. */
export const DEMO_QUESTION = 'What did the foghorn ledger keep in its margins, and why did it matter?';
