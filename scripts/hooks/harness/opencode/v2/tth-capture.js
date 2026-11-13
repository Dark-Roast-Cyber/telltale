// CAPTURE TOOLING ONLY. This is not an OpenCode shim for telltale hooks.
//
// OpenCode v2 plugin API (@opencode/cli 2.x, @opencode/plugin Promise API).
// Records hook inputs to $REC_LOG and, for tool calls whose input contains
// $STUB_MATCH (default TTH_CANARY), behaves as $STUB_MODE:
//   noop        record only
//   throw       throw a plain Error from tool execute.before
//   toolerror   throw a Tool.Error from tool execute.before
//   hang        never resolve execute.before
//   sleep:N     resolve after N seconds (then noop)
//   init-throw  throw during setup (load failure)
//   perm-deny / perm-ask / perm-allow   set effect in permission evaluate
import fs from "node:fs"

const LOG = process.env.REC_LOG
const MODE = process.env.STUB_MODE || "noop"
const MATCH = process.env.STUB_MATCH || "TTH_CANARY"
const REASON = "TTH stub deny: canary command blocked by capture plugin"

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

export default {
  id: "tth-capture",
  setup: async (ctx) => {
    rec("plugin.setup", { location: ctx.location, options: ctx.options })
    if (MODE === "init-throw") throw new Error("TTH capture plugin init failure")
    let ToolError
    try {
      ToolError = (await import("@opencode/plugin/promise/tool")).Error
    } catch (e) {
      rec("plugin.toolerror-import-failed", { error: String(e) })
    }
    await ctx.tool.hook("execute.before", async (event) => {
      const hit = active(event.input)
      rec("tool.execute.before", event, hit ? MODE : "noop")
      if (!hit) return
      if (MODE === "throw") throw new Error(REASON)
      if (MODE === "toolerror") throw new ToolError({ message: REASON })
      if (MODE === "hang") return new Promise(() => {})
      if (MODE.startsWith("sleep:")) await new Promise((r) => setTimeout(r, Number(MODE.slice(6)) * 1000))
    })
    await ctx.tool.hook("execute.after", async (event) => {
      rec("tool.execute.after", event)
    })
    await ctx.permission.hook("evaluate", async (event) => {
      const hit = MODE.startsWith("perm-") && active(event)
      rec("permission.evaluate", event, hit ? MODE : "noop")
      if (!hit) return
      event.effect = MODE.slice(5)
      event.message = REASON
    })
    // Background event recorder (permission, session and tool-part lifecycle).
    ;(async () => {
      try {
        for await (const event of ctx.event.subscribe()) {
          const type = event?.type ?? ""
          if (/delta|heartbeat/.test(type)) continue
          rec(`event:${type}`, event)
        }
      } catch (e) {
        rec("event.subscribe-failed", { error: String(e) })
      }
    })()
  },
}
