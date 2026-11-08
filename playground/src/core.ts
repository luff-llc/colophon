/* Every call to the core goes through this module.
 *
 * This re-exports the real Rust/WASM package (@colophon/core, file:../js).
 * Everything else imports from './core' and stays untouched by core internals.
 */

export * from '@colophon/core';

/** Generated creation transport; the SDK facade’s create() still exposes only owner-only genesis. */
export { WasmLibrary } from '../../js/dist/wasm/colophon_wasm.js';
