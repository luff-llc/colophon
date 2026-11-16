// A separately signalled owner: the parent test never kills a relay by PID.
import { World } from "./device";
const world = await new World("members", 1).init();
const device = world.device("swift", "signal-device");
await device.start(); await device.call("create");
console.log(JSON.stringify({ root: device.root, ready: true }));
setInterval(() => {}, 1000);
