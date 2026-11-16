// CAPTURE TOOLING ONLY. This is not an OpenCode shim for telltale hooks.
//
// OpenCode v1 plugin API (opencode-ai 1.x, @opencode-ai/plugin). Records every
// hook input to $REC_LOG and, for tool calls whose arguments contain $STUB_MATCH
// (default TTH_CANARY), behaves as $STUB_MODE:
//   noop        record only
//   throw       throw new Error(...) from tool.execute.before
//   hang        never resolve tool.execute.before
//   sleep:N     resolve after N seconds (then noop)
//   init-throw  throw while the plugin initializes (load failure)
//   perm-deny / perm-allow   set output.status in permission.ask (if that hook fires)
import fs from "node:fs"

const LOG = process.env.REC_LOG
const MODE = process.env.STUB_MODE || "noop"
const MATCH = process.env.STUB_MATCH || "TTH_CANARY"

function rec(label, payload, mode = "noop") {
  if (!LOG) return
  let text
  try {
    text = JSON.stringify(payload)
  } catch (e) {
    text = JSON.stringify({ _unserializable: String(e) })
  }
  fs.appendFileSync(LOG, `{"t":${Date.now() / 1000},"label":${JSON.stringify(label)},"mode":${JSON.stringify(mode)},"payload":${text}}\n`)
}

const active = (value) => JSON.stringify(value ?? null).includes(MATCH)

export const TthCapture = async (ctx) => {
  rec("plugin.init", { directory: ctx.directory, worktree: ctx.worktree, project: ctx.project, serverUrl: String(ctx.serverUrl ?? "") })
  if (MODE === "init-throw") throw new Error("TTH capture plugin init failure")
  return {
    "tool.execute.before": async (input, output) => {
      const hit = active(output?.args)
      rec("tool.execute.before", { input, output }, hit ? MODE : "noop")
      if (!hit) return
      if (MODE === "throw") throw new Error("TTH stub deny: canary command blocked by capture plugin")
      if (MODE === "hang") return new Promise(() => {})
      if (MODE.startsWith("sleep:")) await new Promise((r) => setTimeout(r, Number(MODE.slice(6)) * 1000))
    },
    "tool.execute.after": async (input, output) => {
      rec("tool.execute.after", { input, output })
    },
    "permission.ask": async (input, output) => {
      rec("permission.ask", { input, output }, MODE.startsWith("perm-") ? MODE : "noop")
      if (MODE === "perm-deny") output.status = "deny"
      if (MODE === "perm-allow") output.status = "allow"
    },
    event: async ({ event }) => {
      // Streaming deltas are noise; tool part state changes are the settlement evidence.
      if (event?.type === "message.part.delta") return
      if (event?.type === "message.part.updated" && event.properties?.part?.type !== "tool") return
      rec(`event:${event?.type}`, event)
    },
  }
}
