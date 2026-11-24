// Every instance of the home module is named the build it was made from (the SHA-256 of the
// module's bytes), before its first request: a home's proof of its fold names that build, so a
// proof another build wrote is never taken.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, test } from 'node:test';
import { HomeModule, ModuleError } from '../home.js';

const target = process.env.CARGO_TARGET_DIR ?? path.join(import.meta.dir, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');

describe('the module build', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, () => {
  test('is named to every instance, and only once', async () => {
    const fingerprint = createHash('sha256').update(readFileSync(wasm)).digest('hex');
    const module = await HomeModule.load(wasm);
    assert.equal(module.fingerprint, fingerprint);
    assert.equal(module.call({ op: 'limits' }).build, true);
    // Named already: the same name is taken again, another is refused.
    assert.ok(module.call({ op: 'build', fingerprint }).ok);
    assert.throws(() => module.call({ op: 'build', fingerprint: '0'.repeat(64) }), ModuleError);
    // An instance replaced after every call is named again each time.
    const small = await HomeModule.load(wasm, { resetBytes: 1 });
    for (let i = 0; i < 3; i++) {
      assert.ok(small.call({ op: 'build', fingerprint }).ok);
      assert.throws(() => small.call({ op: 'build', fingerprint: '0'.repeat(64) }), ModuleError);
    }
    assert.ok(small.resets >= 6);
    // An instance that could not be named is dropped, never used unnamed.
    const wrong = await HomeModule.load(wasm);
    wrong.fingerprint = 'not a fingerprint';
    assert.throws(() => wrong.call({ op: 'limits' }), ModuleError);
    assert.equal(wrong.instance, null);
    wrong.fingerprint = fingerprint;
    assert.ok(wrong.call({ op: 'build', fingerprint }).ok);
    assert.throws(() => wrong.call({ op: 'build', fingerprint: '0'.repeat(64) }), ModuleError);
  });
});
