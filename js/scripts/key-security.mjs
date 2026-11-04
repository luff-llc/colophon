import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { WebCryptoKeys } from '../dist/index.js';

// Instrument accesses, rather than relying on noisy wall-clock timing measurements.
const source = await readFile(new URL('../dist/index.js', import.meta.url), 'utf8');
const compareSource = source.slice(source.indexOf('function equal('), source.indexOf('function entropy('));
const equal = runInNewContext(`(${compareSource.trim()})`);
for (const mismatch of [-1, 0, 15, 31]) {
  const reads = [[], []];
  const inputs = [Array(32).fill(7), Array(32).fill(7)];
  if (mismatch >= 0) inputs[1][mismatch] ^= 1;
  const observed = inputs.map((input, side) => new Proxy(input, {
    get(target, key, receiver) {
      if (/^\d+$/.test(String(key))) reads[side].push(Number(key));
      return Reflect.get(target, key, receiver);
    },
  }));
  assert.equal(equal(...observed), mismatch < 0);
  for (const read of reads) assert.deepEqual(read, Array.from({ length: 32 }, (_, i) => i));
}
assert.equal(equal([1], [1, 2]), false);

const first = (await WebCryptoKeys.generate()).keyPairs();
const other = (await WebCryptoKeys.generate()).keyPairs();
for (const mode of ['match', 'mismatch', 'failure']) {
  const secrets = [];
  const original = crypto.subtle.deriveBits;
  crypto.subtle.deriveBits = async function (...args) {
    if (mode === 'failure' && secrets.length === 1) throw new Error('Injected ECDH failure');
    const result = await original.apply(this, args);
    secrets.push(new Uint8Array(result));
    return result;
  };
  try {
    const agreement = mode === 'mismatch'
      ? { privateKey: first.agreement.privateKey, publicKey: other.agreement.publicKey }
      : first.agreement;
    const attempt = WebCryptoKeys.fromKeyPairs(first.signing, agreement);
    if (mode === 'match') await attempt;
    else await assert.rejects(attempt, mode === 'mismatch' ? /Agreement key pair mismatch/ : /Injected ECDH failure/);
    assert.equal(secrets.length, mode === 'failure' ? 1 : 2);
    for (const secret of secrets) assert(secret.every(byte => byte === 0), 'Temporary ECDH secret was not cleared');
  } finally {
    crypto.subtle.deriveBits = original;
  }
}
console.log('Key validation security regressions passed.');
