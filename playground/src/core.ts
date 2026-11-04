/* Every call to the core goes through this module.
 *
 * ONE-LINE SWAP: when @colophon/core (the real Rust/WASM package) is ready,
 * change the import line below to:
 *
 *   export * from '@colophon/core';
 *
 * and delete mock-core.ts. Everything else imports from './core'.
 */

export * from './mock-core';
