/**
 * The Colophon 0.5 session for JavaScript: what the Swift `ColophonSession` and the Kotlin
 * `com.luff.colophon.session` give native apps, over the web05 wasm exports. See docs/js-session.md.
 */
export { init, glue, isAccountFault, plain, type AccountFault } from './wasm.js';
export * from './errors.js';
export * from './records.js';
export { SecretBytes, withEntropy } from './secrets.js';
export { MemoryMedium, RecordPaths, type MediumEntry, type MediumWrite, type RecordMedium } from './medium.js';
export { IndexedDBMedium, IndexedDBPrivateStore, WebCryptoDeviceSecrets, WebCryptoKeyStore, type StoredKeyPairs } from './indexeddb.js';
export { MemoryDeviceSecrets, MemoryPrivateStore, type DeviceSecretStore, type PrivateStore } from './private.js';
export { KeyCustody, WebCryptoKeyProvider, keyDescriptorOf, keyIdOf, type AsyncKeyProvider, type KeyAssertion } from './keys.js';
export { PasskeyProvider, type CredentialClient, type PasskeyRegistration } from './passkey.js';
export { FetchHomeTransport, HomeLimits, HomeWords, homeRefusal, isResultCode, type HomeRefusal, type FetchTransportOptions, type HomeAnswer, type HomeHeader, type HomeIssue, type HomeProblem, type HomeRequest, type HomeSyncState, type HomeTransport } from './transport.js';
export * from './types.js';
export { ColophonSession } from './session.js';
export { blobAvailability, blobData, downloadRequiredBlobs, prefetchBlob, putBlob, setBlobReference, type BlobAvailabilityState, type ColophonBlob } from './blobs.js';
export { attachPageLifecycle, gateContent, performGateAction, StoppedWords, type GateAction, type GateContent, type PageLifecycleOptions } from './gate.js';
export { ColophonEngine } from './engine.js';
export type { ExchangeResult } from './worker.js';
export { narrowedTerms } from './worker.js';
