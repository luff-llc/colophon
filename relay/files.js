// File helpers the relay's durable logs share. I/O only.
import { promises as fsp } from 'node:fs';

/**
 * The rows of a line log: `[]` when the file does not exist (not written yet); an unterminated
 * last line (an append a crash interrupted) is dropped. Any other read error, and any complete
 * line that is not a row `valid` accepts, throws: a log that cannot be read whole is never taken
 * as empty, since what it holds would then be forgotten.
 */
export async function readLogRows(file, valid, what) {
  let text;
  try { text = await fsp.readFile(file, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw new Error(`${what} ${file} cannot be read: ${error.message}`); }
  const end = text.lastIndexOf('\n');
  text = text.slice(0, end + 1);
  const rows = [];
  let n = 0;
  for (const line of text.split('\n')) {
    n += 1;
    if (!line) continue;
    let row;
    try { row = JSON.parse(line); } catch { row = undefined; }
    if (!valid(row)) throw new Error(`${what} ${file} is damaged at line ${n}; restore it from a backup`);
    rows.push(row);
  }
  return rows;
}

/** A replay log's row (§12.4): a reservation `{r, d, s, at[, e | t]}` or a completion `{c, t}`.
 * `effect` checks a reservation's effect. */
export function replayRow(effect) {
  const str = (v) => typeof v === 'string';
  return (e) => {
    if (!e || typeof e !== 'object' || Array.isArray(e)) return false;
    if (str(e.r)) {
      return str(e.d) && str(e.s) && Number.isFinite(e.at)
        && (e.t === undefined || str(e.t))
        && (e.e === undefined || (e.e !== null && typeof e.e === 'object' && effect(e.e)));
    }
    return str(e.c) && str(e.t);
  };
}
