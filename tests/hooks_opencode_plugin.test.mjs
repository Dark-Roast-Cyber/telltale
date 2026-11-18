// Actual child processes, not live-harness qualification. The only substituted
// boundary is the executable; the plugin's spawning, framing and limits run.
import { test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { createPlugin } from "../scripts/hooks/opencode-v2.mjs"

function executable(t, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tth-plugin-"))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, "hook")
  fs.writeFileSync(file, `#!${process.execPath}\n${body}`, { mode: 0o700 })
  return file
}

async function callback(options) {
  let before
  const plugin = createPlugin({ configDirs: ["/synthetic/config"], ...options })
  await plugin.setup({
    location: { directory: "/synthetic/work" },
    tool: { hook: async (name, fn) => { assert.equal(name, "execute.before"); before = fn } },
  })
  return before
}
const event = { sessionID: "synthetic", messageID: "m", id: "outer", agent: "build", tool: "shell", input: {} }
const noop = `process.stdin.resume();process.stdin.on('end',()=>console.log(JSON.stringify({
  protocol:'telltale.hook-reply.v1',mode:'enforce',output:null})))`

async function waitFor(check) {
  const deadline = performance.now() + 5000
  for (;;) {
    try { return await check() } catch (error) {
      if (performance.now() >= deadline) throw error
      await new Promise(resolve => setTimeout(resolve, 10))
    }
  }
}

test("a framed noop leaves native permissions unchanged", async t => {
  const before = await callback({ executable: executable(t, noop), mode: "enforce" })
  assert.equal(await before(event), undefined)
})

test("a framed deny throws its reason", async t => {
  const before = await callback({ executable: executable(t, `console.log(JSON.stringify({
    protocol:'telltale.hook-reply.v1',mode:'enforce',output:{decision:'deny',reason:'marker denied'}}));
    process.stdin.resume()`), mode: "enforce" })
  await assert.rejects(before(event), /marker denied/)
})

test("empty output is not a successful noop", async t => {
  const before = await callback({ executable: executable(t, "process.stdin.resume()"), mode: "enforce" })
  await assert.rejects(before(event), /hook unavailable/)
})

test("missing executable denies under the explicit failure policy", async () => {
  const before = await callback({ executable: "/nonexistent/telltale-pilot", mode: "enforce" })
  await assert.rejects(before(event), /hook unavailable/)
})

test("invalid and oversized replies deny without leaking reply text", async t => {
  const before = await callback({ executable: executable(t, "console.log('SECRET'.repeat(10000));process.stdin.resume()"),
    mode: "enforce", maxReplyBytes: 100 })
  await assert.rejects(before(event), /^Error: Telltale: hook unavailable; tool call denied$/)
})

test("an explicit native allow is not a valid plugin reply", async t => {
  const before = await callback({ executable: executable(t, `console.log(JSON.stringify({
    protocol:'telltale.hook-reply.v1',mode:'enforce',output:{decision:'allow'}}));process.stdin.resume()`),
    mode: "enforce" })
  await assert.rejects(before(event), /hook unavailable/)
})

test("a nonzero child exit is not a successful noop", async t => {
  const before = await callback({ executable: executable(t, "process.stdin.resume();process.exitCode=1"), mode: "enforce" })
  await assert.rejects(before(event), /hook unavailable/)
})

test("a timed-out child is killed and the capacity slot is reusable", async t => {
  const pidfile = path.join(os.tmpdir(), `tth-pid-${process.pid}.json`)
  t.after(() => fs.rmSync(pidfile, { force: true }))
  const before = await callback({ executable: executable(t,
    `require('fs').writeFileSync(${JSON.stringify(pidfile)},String(process.pid));setInterval(()=>{},1000)`),
    mode: "enforce", timeoutMs: 500, maxConcurrent: 1 })
  await assert.rejects(before(event), /hook unavailable/)
  const pid = Number(fs.readFileSync(pidfile))
  await waitFor(() => assert.throws(() => process.kill(pid, 0), { code: "ESRCH" }))
  await assert.rejects(before(event), /hook unavailable/)
  const second = Number(fs.readFileSync(pidfile))
  assert.notEqual(pid, second)
  await waitFor(() => assert.throws(() => process.kill(second, 0), { code: "ESRCH" }))
})

test("late inherited pipe closure cannot delay the caller or signal an exited group", { timeout: 8000 }, async t => {
  const file = executable(t, "")
  const pidfile = file + ".pid", release = file + ".release"
  const holder = `
    const fs=require('fs');
    const watcher=fs.watch(${JSON.stringify(path.dirname(file))},()=>{
      if(fs.existsSync(${JSON.stringify(release)}))process.exit(0)
    });
    setTimeout(()=>process.exit(0),4000);
  `
  fs.writeFileSync(file, `#!${process.execPath}
    const fs=require('fs'),{spawn}=require('child_process');
    process.stdin.resume();process.stdin.on('end',()=>{
      fs.writeFileSync(${JSON.stringify(pidfile)},String(process.pid));
      const child=spawn(process.execPath,['-e',${JSON.stringify(holder)}],
        {detached:true,stdio:['ignore',process.stdout,'ignore']});
      child.unref();
      console.log(JSON.stringify({protocol:'telltale.hook-reply.v1',mode:'enforce',output:null}));
      process.exit(0);
    });
  `)
  const realKill = process.kill.bind(process), signals = []
  t.mock.method(process, "kill", (pid, signal) => {
    if (pid < 0 && signal === "SIGKILL") {
      signals.push(pid)
      return true // Observe the unsafe attempt without signaling an old group.
    }
    return realKill(pid, signal)
  })
  const before = await callback({ executable: file, mode: "enforce", timeoutMs: 1000 })
  const start = performance.now()
  const denied = assert.rejects(before(event), /hook unavailable/)
  try {
    await waitFor(() => {
      const pid = Number(fs.readFileSync(pidfile))
      assert.throws(() => realKill(pid, 0), { code: "ESRCH" })
    })
    await denied
    assert.ok(performance.now() - start < 3000, "caller waited for the inherited pipe")
    assert.deepEqual(signals, [], "a known-exited child/group must never be signaled")
  } finally {
    fs.writeFileSync(release, "")
  }
})

test("a deadline does not release capacity while the child remains unreaped", { timeout: 8000 }, async t => {
  const file = executable(t, "")
  const pidfile = file + ".pid", release = file + ".release", launches = file + ".launches"
  fs.writeFileSync(file, `#!${process.execPath}
    const fs=require('fs');
    fs.appendFileSync(${JSON.stringify(launches)},'x');
    process.stdin.resume();process.stdin.on('end',()=>{
      if(fs.existsSync(${JSON.stringify(release)})){
        console.log(JSON.stringify({protocol:'telltale.hook-reply.v1',mode:'enforce',output:null}));
        return;
      }
      fs.writeFileSync(${JSON.stringify(pidfile)},String(process.pid));
      fs.watch(${JSON.stringify(path.dirname(file))},()=>{
        if(fs.existsSync(${JSON.stringify(release)}))process.exit(0)
      });
      setTimeout(()=>process.exit(0),4000);
    });
  `)
  const realKill = process.kill.bind(process)
  // Substitute delayed/failed OS cleanup, not the plugin or the child process.
  t.mock.method(process, "kill", (pid, signal) => {
    if (signal === "SIGKILL" && fs.existsSync(pidfile) &&
        pid === -Number(fs.readFileSync(pidfile))) return true
    return realKill(pid, signal)
  })
  const before = await callback({ executable: file, mode: "enforce", timeoutMs: 1000, maxConcurrent: 1 })
  const start = performance.now()
  try {
    await assert.rejects(before(event), /hook unavailable/)
    assert.ok(performance.now() - start < 3000, "caller waited for reaping")
    const pid = Number(fs.readFileSync(pidfile))
    assert.equal(realKill(pid, 0), true, "the child must still be live in this regression")
    await assert.rejects(before(event), /hook unavailable/)
    // The second call waited in the queue until its own deadline.
    assert.equal(fs.readFileSync(launches, "utf8"), "x", "deadline freed an unreaped slot")
    fs.writeFileSync(release, "")
    await waitFor(() => assert.throws(() => realKill(pid, 0), { code: "ESRCH" }))
    await waitFor(async () => assert.equal(await before(event), undefined))
  } finally {
    fs.writeFileSync(release, "")
  }
})

test("with no queue, a call over capacity takes the failure policy without waiting", async t => {
  const file = executable(t, "")
  const launched = file + ".launched"
  fs.writeFileSync(file, `#!${process.execPath}
    require('fs').writeFileSync(${JSON.stringify(launched)},'');setInterval(()=>{},1000)`)
  const before = await callback({ executable: file,
    mode: "enforce", timeoutMs: 1000, maxConcurrent: 1, maxQueued: 0 })
  const first = before(event).catch(() => "first")
  await waitFor(() => assert.ok(fs.existsSync(launched)))
  const second = before(event).catch(() => "second")
  assert.equal(await Promise.race([first, second]), "second")
  await first
})

test("calls over capacity wait for a slot and are all forwarded, one at a time", async t => {
  const file = executable(t, "")
  const running = file + ".running", log = file + ".log"
  fs.writeFileSync(file, `#!${process.execPath}
    const fs=require('fs');
    fs.appendFileSync(${JSON.stringify(log)},fs.existsSync(${JSON.stringify(running)})?'overlap ':'x');
    fs.writeFileSync(${JSON.stringify(running)},'');
    process.stdin.resume();process.stdin.on('end',()=>setTimeout(()=>{
      fs.rmSync(${JSON.stringify(running)});
      console.log(JSON.stringify({protocol:'telltale.hook-reply.v1',mode:'enforce',output:null}));
    },100));
  `)
  const before = await callback({ executable: file, mode: "enforce", maxConcurrent: 1, maxQueued: 2 })
  assert.deepEqual(await Promise.all([before(event), before(event), before(event)]),
    [undefined, undefined, undefined])
  assert.equal(fs.readFileSync(log, "utf8"), "xxx")
})

test("a call beyond the queue takes the failure policy without waiting", async t => {
  const before = await callback({ executable: executable(t, "setInterval(()=>{},1000)"),
    mode: "enforce", timeoutMs: 500, maxConcurrent: 1, maxQueued: 1 })
  const running = before(event).catch(() => "running")
  const queued = before(event).catch(() => "queued")
  const beyond = before(event).catch(() => "beyond")
  assert.equal(await Promise.race([running, queued, beyond]), "beyond")
  await Promise.all([running, queued])
})

test("a queue size outside its bounds is refused when the plugin is created", () => {
  assert.throws(() => createPlugin({ executable: "/synthetic/telltale", configDirs: ["/synthetic/config"],
    maxQueued: 257 }), /invalid operator plugin configuration/)
})

test("detect-only never throws on missing executable or malformed reply", async t => {
  const missing = await callback({ executable: "/nonexistent/telltale-pilot" })
  assert.equal(await missing(event), undefined)
  const invalid = await callback({ executable: executable(t, "console.log('invalid');process.stdin.resume()") })
  assert.equal(await invalid(event), undefined)
})

test("identical nested inputs get independent occurrence IDs", async t => {
  const file = executable(t, `let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>{
    const p=JSON.parse(input);console.log(JSON.stringify({protocol:'telltale.hook-reply.v1',mode:'enforce',
    output:{decision:'deny',reason:p.occurrence}}))})`)
  const before = await callback({ executable: file, mode: "enforce" })
  const results = await Promise.allSettled([before(event), before(event)])
  assert.equal(results[0].status, "rejected")
  assert.equal(results[1].status, "rejected")
  assert.match(results[0].reason.message, /^tth-occ-/)
  assert.notEqual(results[0].reason.message, results[1].reason.message)
})
