// OpenCode @opencode/cli 2.2.5 pilot. Request-only: never infer settlement
// from reused Code Mode IDs, input hashes, execute.after or bus notifications.
import { spawn } from "node:child_process"
import { randomUUID } from "node:crypto"
import { isAbsolute } from "node:path"

const FAILURE_CLASSES = ["capacity", "timeout", "input_size", "spawn", "stdin", "stdout",
  "exit", "reply_size", "reply_invalid"]
const failureClass = error =>
  FAILURE_CLASSES.includes(error?.message) ? error.message : "internal"

export function createPlugin({
  executable,
  configDirs,
  mode = "detect_only",
  onError = "deny",
  timeoutMs = 15000,
  maxReplyBytes = 65536,
  maxConcurrent = 4,
  maxQueued = 32,
}) {
  // These are operator-owned settings, never tool input or model arguments.
  if (!isAbsolute(executable ?? "") || !Array.isArray(configDirs) || !configDirs.length ||
      configDirs.some(p => !isAbsolute(p)) ||
      !["enforce", "detect_only"].includes(mode) || !["deny", "noop"].includes(onError) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 ||
      !Number.isInteger(maxReplyBytes) || maxReplyBytes < 1 || maxReplyBytes > 1048576 ||
      !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16 ||
      !Number.isInteger(maxQueued) || maxQueued < 0 || maxQueued > 256)
    throw new Error("Telltale: invalid operator plugin configuration")

  let active = 0
  const waiting = [] // Callbacks waiting for a child slot, oldest first.

  // Hold a child slot, waiting behind earlier callbacks when all are busy.
  // The wait counts against the callback's own deadline.
  function slot(deadline) {
    if (active < maxConcurrent) {
      active++
      return Promise.resolve()
    }
    if (waiting.length >= maxQueued) return Promise.reject(new Error("capacity"))
    return new Promise((resolve, reject) => {
      const entry = { resolve }
      entry.timer = setTimeout(() => {
        waiting.splice(waiting.indexOf(entry), 1)
        reject(new Error("timeout"))
      }, deadline - performance.now())
      waiting.push(entry)
    })
  }
  // Pass a freed slot to the oldest waiting callback, or give it back.
  function free() {
    const next = waiting.shift()
    if (!next) active--
    else {
      clearTimeout(next.timer)
      next.resolve()
    }
  }
  const args = ["hooks", "opencode", "hook", "--json-reply",
    ...(mode === "detect_only" ? ["--detect-only"] : []),
    ...configDirs.flatMap(p => ["--config-dir", p])]

  async function request(payload) {
    const input = JSON.stringify(payload)
    if (Buffer.byteLength(input) > 1048576) throw new Error("input_size")
    const deadline = performance.now() + timeoutMs
    await slot(deadline)
    if (performance.now() >= deadline) {
      free()
      throw new Error("timeout")
    }
    return await new Promise((resolve, reject) => {
      let child, timer, size = 0, chunks = []
      let settled = false, reaped = false, released = false, cleaned = false
      const release = () => {
        // A returned timeout is not evidence that its child has stopped.
        if (settled && reaped && !released) {
          released = true
          free()
        }
      }
      const cleanup = stop => {
        if (cleaned) return
        cleaned = true
        child?.stdin?.destroy()
        child?.stdout?.destroy()
        // 'exit' and 'close' are distinct: descendants can retain our pipe
        // after the direct child is reaped. Never signal that old group ID.
        if (stop && !reaped && child?.pid &&
            child.exitCode === null && child.signalCode === null) {
          try {
            if (process.platform !== "win32") process.kill(-child.pid, "SIGKILL")
            else child.kill("SIGKILL")
          } catch {}
        }
      }
      const finish = (error, output) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        chunks = []
        cleanup(Boolean(error))
        if (error) reject(new Error(error))
        else resolve(output)
        release()
      }
      try {
        child = spawn(executable, args, {
          shell: false, detached: process.platform !== "win32",
          stdio: ["pipe", "pipe", "ignore"],
          env: { ...process.env, TELLTALE_HOOKS_EVALUATOR: "0" },
        })
      } catch {
        reaped = true // No child was created.
        finish("spawn")
        return
      }
      timer = setTimeout(() => finish("timeout"), deadline - performance.now())
      child.once("exit", () => {
        reaped = true
        release()
      })
      child.on("error", () => {
        if (!child.pid) reaped = true // Failed spawn, not a live child.
        finish("spawn")
      })
      child.stdin.on("error", () => finish("stdin"))
      child.stdout.on("error", () => finish("stdout"))
      child.stdout.on("data", chunk => {
        if (settled) return
        size += chunk.length
        if (size > maxReplyBytes) finish("reply_size")
        else chunks.push(chunk)
      })
      child.once("close", code => {
        if (settled) return
        if (code !== 0) { finish("exit"); return }
        try {
          const reply = JSON.parse(Buffer.concat(chunks).toString("utf8"))
          if (reply.protocol !== "telltale.hook-reply.v1" ||
              !["enforce", "detect_only"].includes(reply.mode) ||
              !Object.hasOwn(reply, "output")) throw new Error()
          if (reply.output !== null &&
              (reply.mode !== "enforce" || reply.output.decision !== "deny" ||
               typeof reply.output.reason !== "string" || !reply.output.reason.trim())) throw new Error()
          finish(null, reply.output)
        } catch { finish("reply_invalid") }
      })
      child.stdin.end(input)
    })
  }

  return {
    id: "telltale-hooks-v2-pilot",
    setup: async ctx => {
      await ctx.tool.hook("execute.before", async event => {
        let output
        try {
          output = await request({
            protocol: "telltale.opencode-v2.v1", hook_event: "execute.before",
            occurrence: `tth-occ-${randomUUID()}`,
            cwd: ctx.location.directory, event,
          })
        } catch (error) {
          // A fixed failure class only: no arguments, paths, stdout or
          // exception details in diagnostics.
          console.error(`Telltale: hook transport failed (${failureClass(error)}); apply configured plugin failure policy`)
          if (mode === "enforce" && onError === "deny")
            throw new Error("Telltale: hook unavailable; tool call denied")
          return
        }
        if (mode === "enforce" && output !== null) throw new Error(output.reason)
        // No native allow, no permission.evaluate mutation, no ask.
      })
    },
  }
}
