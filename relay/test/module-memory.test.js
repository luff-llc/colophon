// The home module's memory bound: an instance whose memory grew past it is replaced after the
// call, so a WebAssembly memory (which never shrinks) does not keep what one big request took.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, test } from 'node:test';
import { HomeModule, MODULE_MEMORY_MB, moduleMemoryBytes } from '../home.js';

const target = process.env.CARGO_TARGET_DIR ?? path.join(import.meta.dir, '../../target');
const wasm = process.env.COLOPHON_HOME_WASM ?? path.join(target, 'wasm32-unknown-unknown/release/colophon_home_wasm.wasm');

describe('the module memory setting', () => {
  test('is whole MiB, at least 16, with a default that suits a 1 GiB machine', () => {
    assert.equal(MODULE_MEMORY_MB, 128);
    assert.equal(moduleMemoryBytes(undefined), 128 * 1024 * 1024);
    assert.equal(moduleMemoryBytes(''), 128 * 1024 * 1024);
    assert.equal(moduleMemoryBytes('64'), 64 * 1024 * 1024);
    assert.equal(moduleMemoryBytes(256), 256 * 1024 * 1024);
    for (const bad of ['15', '0', '-1', '1.5', '64MB', 'lots']) {
      assert.throws(() => moduleMemoryBytes(bad), /COLOPHON_MODULE_MEMORY_MB/, bad);
    }
  });
});

describe('the module memory bound', { skip: existsSync(wasm) ? false : 'build colophon-home-wasm first' }, () => {
  test('an instance past the bound is replaced after the call; one under it is kept', async () => {
    const kept = await HomeModule.load(wasm);
    kept.call({ op: 'limits' });
    const instance = kept.instance;
    assert.ok(kept.memoryBytes() > 0);
    kept.call({ op: 'limits' });
    assert.equal(kept.instance, instance, 'under the default bound the instance is kept');
    assert.equal(kept.resets, 0);

    // A bound below any instance's memory: every call ends with a new instance to come.
    const small = await HomeModule.load(wasm, { resetBytes: 1 });
    assert.ok(small.call({ op: 'limits' }).ok);
    assert.equal(small.instance, null);
    assert.equal(small.resets, 1);
    assert.equal(small.memoryBytes(), 0);
    assert.ok(small.call({ op: 'limits' }).ok, 'the next call instantiates again');
    assert.equal(small.resets, 2);
  });
});
