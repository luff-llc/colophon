/**
 * The Colophon 0.6 hosts for JavaScript (docs/hosts-06.md): the home stream over a real WebSocket, session cells over
 * that stream, and a small typed API per cell. The state machines are the core's (`HomeStream`, `SessionEndpoint` in the
 * web05 wasm exports); these classes own the socket, the requests, the timers and the store, and add no policy.
 */
export { accountOf, transportOf, type HostAccount } from './account.js';
export { Deadline, systemClock, type HostClock } from './clock.js';
export { frameBytes, frameCell, frameText, sessionFrameText } from './frames.js';
export { webSocketFactory, type HostSocket, type SocketFactory, type SocketHandlers } from './socket.js';
export { HomeStreamHost, type StreamCell, type StreamEventValue, type StreamHostEvent, type StreamHostOptions, type StreamStatusValue, type StreamStepValue } from './stream-host.js';
export {
  base64, base64url, CellHostError, SessionCellHost, unbase64,
  type CellCarrier, type CellHostEvent, type CellHostOptions, type ClaimStore, type FailReason, type RebuildReason, type SessionEffectValue, type SessionStepValue,
} from './cell-host.js';
export { CellSession, cellEvent, type CellEvent, type CellState, type Claim } from './cell.js';
