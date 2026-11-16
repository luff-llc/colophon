// Writes one batch into a FileMedium and kills itself (SIGKILL) at the step named on the command line.
import { FileMedium } from '../src/session/node.js';
const [root, at] = process.argv.slice(2);
const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const medium = new FileMedium(root!, { onStep: (step, index) => { if (`${step}${index === undefined ? '' : `:${index}`}` === at) process.kill(process.pid, 'SIGKILL'); } });
await medium.write([{ path: 'ops/a.json', bytes: text('a') }, { path: 'ops/b.json', bytes: text('b') }, { path: 'state/x.json', bytes: text('x1') }]);
