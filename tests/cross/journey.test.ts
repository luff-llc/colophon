import { expect, test } from "bun:test";
import { cp, readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { b64, unb64, delay, Device, World, settle, type Platform } from "./device";

const entropy = b64(Uint8Array.from({ length: 32 }, (_, n) => n + 1));
const nb = b64(Uint8Array.from({ length: 32 }, (_, n) => n + 33));
const na = b64(Uint8Array.from({ length: 32 }, (_, n) => n + 65));
const other = (p: Platform): Platform => p === "swift" ? "kotlin" : "swift";
const hash = (...parts: (string | Uint8Array)[]) => {
  const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest();
};

async function ceremony(existing: Device, joining: Device, account: string, mode: "qr" | "code", wrong = false) {
  // Deterministic inputs above are only for byte fixtures. Real journeys, including a retry
  // after rejecting a code, start with a fresh transfer key and both fresh nonces (§7.3).
  const entropy = b64(randomBytes(32)), nb = b64(randomBytes(32)), na = b64(randomBytes(32));
  const offered = await joining.call("join", { mode, account, entropy, nb });
  if (mode === "qr") {
    expect(unb64(offered.qr).toString()).toBe(JSON.stringify({ account, e: offered.e, nB: nb, protocol: "colophon/pair-qr/5" }));
  } else {
    expect(offered.commitment).toBe(b64(hash("colophon/pair/5", account, unb64(offered.e), unb64(nb))));
  }
  await existing.call("scan", { mode, account, ...offered });
  const nonce = await existing.call("nonce", { na });
  expect(nonce).toBe(na);
  const reveal = await joining.call("receiveNonce", { na: nonce });
  if (mode === "code") {
    expect(reveal.e).toBe(offered.e); expect(reveal.nb).toBe(nb);
    const digits = await existing.call("reveal", reveal);
    const expected = (hash("colophon/pair-code/5", account, unb64(offered.e), unb64(na), unb64(nb)).readUInt32BE(0) % 1_000_000).toString().padStart(6, "0");
    expect(digits).toBe(expected); expect(reveal.digits).toBe(digits);
    const compared = wrong ? ((Number(digits) + 1) % 1_000_000).toString().padStart(6, "0") : digits;
    for (const d of [existing, joining]) {
      expect(await d.call("confirm", { digits: compared })).toEqual({ accepted: !wrong, stage: wrong ? "spent" : "confirmed" });
    }
  }
  for (const d of [existing, joining]) expect(await d.call("pairingStage")).toBe(wrong ? "spent" : "confirmed");
}

async function bootstrap(from: Device, to: Device) {
  // Only pre-approval authority (including the creator's sealed slot): no content, heads,
  // private state, or this joining device's slot/approval.
  await cp(join(from.root, "records/authority"), join(to.root, "records/authority"), { recursive: true });
  const state = await to.call("restore");
  expect(state.phase).toBe("waiting");
  expect(state.account).toBe((await from.call("state")).account);
}
async function files(root: string, prefix = ""): Promise<string[]> {
  const result: string[] = [];
  for (const f of await readdir(join(root, prefix), { withFileTypes: true })) {
    if (f.name.startsWith(".")) continue;
    const path = join(prefix, f.name);
    if (f.isDirectory()) result.push(...await files(root, path)); else result.push(path);
  }
  return result.sort();
}
async function operationBytes(a: Device, b: Device, expected: number) {
  const paths = (await files(join(a.root, "records"))).filter(p => p.startsWith("ops/"));
  expect(paths.length).toBe(expected);
  const otherPaths = (await files(join(b.root, "records"))).filter(p => p.startsWith("ops/"));
  expect(otherPaths).toEqual(paths);
  for (const path of paths) expect(await readFile(join(b.root, "records", path))).toEqual(await readFile(join(a.root, "records", path)));
}
const title = (id: string) => `${id}: café / 東京 / 🪶 / e\u0301 / \"quote\"\nsecond line\t\u0000`;
async function write(device: Device, id: string) {
  await device.call("write", { payload: b64(JSON.stringify({ id, url: `https://example.org/${id}`, title: title(id) })) });
}
async function projection(device: Device) {
  return JSON.parse(unb64(await device.call("read")).toString());
}
async function assertItems(device: Device, ids: string[]) {
  const value = await projection(device);
  // Both SDKs expose the domain projection; compare the UTF-8 bytes of every field, including combining marks/NUL.
  for (const id of ids) {
    const item = value.items.find((i: any) => i.id === id);
    expect(item).toBeDefined();
    expect(Buffer.from(item.title)).toEqual(Buffer.from(title(id)));
    expect(item.url).toBe(`https://example.org/${id}`);
  }
  expect(value.items.length).toBe(ids.length);
  return value;
}
async function blobs(writer: Device, reader: Device, label: string) {
  const required = Buffer.from(Array.from({ length: 90_000 }, (_, i) => (i * 7 + label.charCodeAt(0)) & 255));
  const optional = Buffer.from(Array.from({ length: 20_000 }, (_, i) => (i * 13 + label.charCodeAt(0)) & 255));
  const a = await writer.call("putBlob", { bytes: b64(required), reference: `${label}-required`, required: true });
  const b = await writer.call("putBlob", { bytes: b64(optional), reference: `${label}-optional`, required: false });
  expect(a).toBe(hash(required).toString("hex")); expect(b).toBe(hash(optional).toString("hex"));
  return { required, optional, a, b, reader };
}
async function readBlobs(b: Awaited<ReturnType<typeof blobs>>) {
  expect(await b.reader.call("availability", { digest: b.a })).toBe("available");
  expect(unb64(await b.reader.call("blob", { digest: b.a }))).toEqual(b.required);
  expect(await b.reader.call("availability", { digest: b.b })).toBe("missing");
  await b.reader.call("prefetch", { digest: b.b });
  expect(await b.reader.call("availability", { digest: b.b })).toBe("available");
  expect(unb64(await b.reader.call("blob", { digest: b.b }))).toEqual(b.optional);
}
async function veto(proposer: Device, vetoer: Device, change: number) {
  const vetoesBefore = (await proposer.call("ledger")).filter((e: any) => e.event === "vetoed").length;
  const digest = await proposer.call("propose", { change: JSON.stringify({ policy: { headMaxAge: change } }) });
  await settle(proposer); const shown = await settle(vetoer);
  expect(shown.pending.find((p: any) => p.digest === digest)?.vetoable).toBe(true);
  await vetoer.call("veto", { digest }); await settle(vetoer);
  for (let n = 0; n < 60; n++) {
    const state = await proposer.call("sync");
    if (!state.pending.some((p: any) => p.digest === digest)) {
      // The verified ledger must record vetoed; disappearance alone could mean activation.
      const recorded = await proposer.call("ledger");
      expect(recorded.filter((e: any) => e.event === "vetoed").length).toBeGreaterThan(vetoesBefore);
      return;
    }
    await delay(100);
  }
  throw new Error("veto did not reach proposer");
}

for (const creator of ["swift", "kotlin"] as const) {
  test(`pairing exact bytes, QR and code: ${creator} to ${other(creator)}`, async () => {
    const world = await new World("members", 1).init();
    try {
      const existing = world.device(other(creator), "existing"), joining = world.device(creator, "joining");
      await existing.start(); await joining.start();
      const account = "ab".repeat(32);
      // The same public inputs serialize identically through both language bindings, including the transfer point.
      for (const mode of ["code", "qr"]) {
        const a = await joining.call("join", { mode, account, entropy, nb });
        const b = await existing.call("join", { mode, account, entropy, nb });
        expect(a).toEqual(b);
      }
      await ceremony(existing, joining, account, "code");
      await ceremony(existing, joining, account, "code", true);
      await expect(existing.call("confirm", { digits: "000000" })).rejects.toThrow("consumed");
      await ceremony(existing, joining, account, "qr");
      const offered = await joining.call("join", { mode: "qr", account, entropy, nb });
      await expect(existing.call("scan", { mode: "qr", account: "cd".repeat(32), ...offered })).rejects.toThrow("pairing:wrongAccount");
      await expect(existing.call("scan", { mode: "qr", account, qr: b64(unb64(offered.qr).toString() + "\n") })).rejects.toThrow("body is not canonical JSON");
      const code = await joining.call("join", { mode: "code", account, entropy, nb });
      await existing.call("scan", { mode: "code", account, ...code }); await existing.call("nonce", { na });
      const reveal = await joining.call("receiveNonce", { na });
      await expect(existing.call("reveal", { ...reveal, nb: b64(Buffer.alloc(32)) })).rejects.toThrow("pairing:commitmentMismatch");
      expect(await existing.call("pairingStage")).toBe("spent");
      await expect(existing.call("reveal", reveal)).rejects.toThrow("consumed");
    } finally { await world.close(); }
  }, 120_000);

  for (const history of ["members", "public"] as const) for (const count of [1, 2]) {
    test(`real home journey: ${creator} creates, ${history}, ${count} home(s), quorum ${count}`, async () => {
      const world = await new World(history, count).init();
      try {
        const first = world.device(creator, "first"), second = world.device(other(creator), "second");
        const secondOwner = await second.start(); first.signer = second;
        await first.start(secondOwner);
        const created = await first.call("create");
        expect(created.phase, JSON.stringify(created)).toBe("ready"); expect(created.homes).toBe(count);
        const account = created.account;
        await write(first, "a"); const firstBlobs = await blobs(first, second, "a");
        await settle(first);
        // The real home protects the feed with a signed call; public history does not grant record access.
        for (const home of world.homes) {
          expect((await fetch(`${home.local}/changes`)).status).toBe(401);
          expect((await fetch(`${home.local}/authority?after=0&limit=64`)).status).toBe(history === "members" ? 401 : 200);
        }
        await bootstrap(first, second);
        const wrongPoint = (await first.call("join", { mode: "qr", account, entropy, nb })).e;
        // A mismatched comparison cannot seal or accept the seed, and writes no slot.
        await ceremony(first, second, account, "code", true);
        await expect(first.call("transfer")).rejects.toThrow("consumed");
        const before = await files(join(second.root, "records"));
        await expect(second.call("accept", { enc: wrongPoint, ciphertext: b64(Buffer.alloc(48)) })).rejects.toThrow("consumed");
        expect(await files(join(second.root, "records"))).toEqual(before);
        // Alternate successful path so both QR and compared-code transfers run in each creation direction.
        await ceremony(first, second, account, count === 1 ? "qr" : "code");
        const sealed = await first.call("transfer");
        // Correct pairing, but a different valid P-256 encapsulation point: reach HPKE authentication,
        // rather than failing point/length validation or the unconfirmed-pairing guard.
        await expect(second.call("accept", { enc: wrongPoint, ciphertext: sealed.ciphertext })).rejects.toThrow("refused:vaultLocked");
        expect(await files(join(second.root, "records"))).toEqual(before);
        expect((await second.call("accept", sealed)).phase).toBe("waiting");
        // Seed acceptance appends this controller's slot. Publish that authority entry before the
        // existing device appends approval, so both append to the same history tip.
        await second.call("sync"); await settle(first);
        const request = await second.call("request");
        await first.call("approve", { request }); await settle(first);
        const secondReady = await settle(second);
        expect(secondReady.account).toBe(account);
        await assertItems(second, ["a"]); await readBlobs(firstBlobs);
        await write(second, "b"); const secondBlobs = await blobs(second, first, "b");
        await settle(second); await settle(first); await readBlobs(secondBlobs);
        expect(await assertItems(first, ["a", "b"])).toEqual(await assertItems(second, ["a", "b"]));
        await operationBytes(first, second, 6);

        // A dishonest home says revoked while verified records still authorize these devices.
        // Both SDKs must tell the person without denying or erasing their local data.
        for (const device of [first, second]) {
          await device.call("refuseCalls", { enabled: true });
          const liedTo = await device.call("sync");
          expect(liedTo.phase).toBe("ready");
          expect([...new Set(liedTo.issues)]).toEqual(["refused:revoked"]);
          expect([...new Set(liedTo.remoteRefusals)]).toEqual(["refused:revoked"]);
          await assertItems(device, ["a", "b"]);
          await device.call("refuseCalls", { enabled: false });
          await settle(device);
        }
        const third = world.device(creator, "third"); await third.start(); await bootstrap(second, third);
        await ceremony(second, third, account, "code");
        await second.call("approve", { request: await third.call("request") }); await settle(second); await settle(first);
        const thirdReady = await settle(third); await assertItems(third, ["a", "b"]);
        await third.call("checkpoint"); // Keep a pre-revocation saved state to test on cold reopen too.
        await first.call("revoke", { member: thirdReady.member }); await write(first, "c"); await settle(first);
        let refused: any;
        for (let n = 0; n < 30; n++) {
          refused = await third.call("sync");
          if (refused.refusals.length || refused.issues.length) break;
          await delay(100);
        }
        const codes = [...refused.refusals, ...refused.issues];
        expect(codes.length).toBeGreaterThan(0); expect([...new Set(codes)]).toEqual(["refused:revoked"]);
        if (history === "members") {
          expect(refused.phase).toBe("ready");
          expect([...new Set(refused.remoteRefusals)]).toEqual(["refused:revoked"]);
          expect([...new Set(refused.issues)]).toEqual(["refused:revoked"]);
          await assertItems(third, ["a", "b"]);
        } else {
          expect(refused.phase).toBe("denied");
          expect(refused.remoteRefusals).toEqual([]);
          await expect(third.call("read")).rejects.toThrow(creator === "swift" ? "notReady" : "NotReady");
        }
        await settle(second); await assertItems(second, ["a", "b", "c"]);
        await veto(first, second, 600); await veto(second, first, 900);

        for (const device of [first, second, third]) {
          const identity = await device.call("state");
          expect((await device.call("lock")).phase).toBe("locked");
          await expect(device.call("read")).rejects.toThrow(device.platform === "swift" ? "notReady" : "NotReady");
          const saved = (await files(join(device.root, "private"))).filter(f => f.endsWith(".checkpoint") || (f.startsWith("saved-") && f.endsWith(".bin")));
          expect(saved.length).toBe(1); expect((await stat(join(device.root, "private", saved[0]))).size).toBeGreaterThan(0);
          const reopened = await device.reopen();
          expect(reopened.account).toBe(account); expect(reopened.member).toBe(identity.member);
        }
        await settle(first); await settle(second);
        expect(await assertItems(first, ["a", "b", "c"])).toEqual(await assertItems(second, ["a", "b", "c"]));
        await operationBytes(first, second, 7);
        for (const [d, digest, value] of [[second, firstBlobs.a, firstBlobs.required], [second, firstBlobs.b, firstBlobs.optional],
          [first, secondBlobs.a, secondBlobs.required], [first, secondBlobs.b, secondBlobs.optional]] as const) {
          expect(unb64(await d.call("blob", { digest }))).toEqual(value);
        }
        const reopenedThird = await third.call("sync");
        expect(reopenedThird.phase).toBe(history === "members" ? "ready" : "denied");
        expect([...new Set(reopenedThird.remoteRefusals)]).toEqual(history === "members" ? ["refused:revoked"] : []);
        expect([...new Set(reopenedThird.issues)], JSON.stringify(reopenedThird)).toEqual(["refused:revoked"]);
        if (history === "members") await assertItems(third, ["a", "b"]);
        else await expect(third.call("read")).rejects.toThrow(creator === "swift" ? "notReady" : "NotReady");
        console.log(`cross ${creator}->${other(creator)} ${history}/${count}: 7 identical record files; 220000 blob bytes; 2 cross vetoes; revoked=${codes.join(",")}; 3 cold reopens; approval passes=${secondReady.passes}`);
      } finally { await world.close(); }
    }, 240_000);
  }
}
