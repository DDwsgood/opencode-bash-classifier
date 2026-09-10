// TUI companion for opencode-bash-classifier.
//
// User-facing half of the `/bypass-classifier` notification design: the server
// plugin cannot publish toasts (its context has only `event.subscribe`), and it
// must not report state through a session message because every message type is
// model-visible. Instead the server emits an ephemeral RPC event
// (`src/bypass-rpc.ts`) and this companion turns it into a toast.
//
// No sidebar and no JSX: only `client.rpc(...).events.on` and `ui.toast`, so the
// entrypoint stays plain TypeScript and the package remains build-free.
//
// The RPC event is ephemeral (live-only): a TUI that reconnects after the event
// misses it. The agent-side reminder is unaffected; a future method on the RPC
// could let the companion re-read state on mount.
import type { Plugin } from "@opencode-ai/plugin/tui"
import { BypassRpc, type BypassChangedData } from "./bypass-rpc"

type Context = Plugin.Context

const plugin: Plugin.Definition = {
  id: "opencode-bash-classifier",
  setup(context: Context) {
    const client = context.client as Context["client"] & {
      rpc?: (definition: unknown) => {
        events: { on: (name: string, handler: (event: { data: unknown; location?: unknown }) => void) => () => void }
      }
    }
    if (!client?.rpc) return () => {}
    let unsubscribe: (() => void) | undefined
    try {
      unsubscribe = client.rpc(BypassRpc).events.on("changed", (event) => {
        try {
          // `context.location` is a live getter: read it here, not once at
          // setup. Capturing it at setup froze the location the TUI happened to
          // be on when the plugin loaded, so switching to a session in another
          // directory silently dropped every toast (the original bug).
          const here = context.location as { directory?: string; workspaceID?: string } | undefined
          const there = event.location as { directory?: string; workspaceID?: string } | undefined
          // The server RPC event is not location-scoped, so a host with several
          // locations would deliver all of them. Only filter when the reliable
          // identity (workspaceID) is present on both sides and actually differs;
          // never drop on a directory spelling/timing mismatch.
          if (
            here?.workspaceID !== undefined &&
            there?.workspaceID !== undefined &&
            here.workspaceID !== there.workspaceID
          )
            return
          context.ui.toast.show(toastFor(event.data as BypassChangedData))
        } catch (error) {
          console.error("[opencode-bash-classifier] bypass toast failed", error)
        }
      })
    } catch (error) {
      console.error("[opencode-bash-classifier] bypass notification setup failed", error)
    }
    return () => unsubscribe?.()
  },
}

type Toast = { title: string; message: string; variant: "info" | "success" | "warning" | "error"; duration: number }

function toastFor(data: BypassChangedData): Toast {
  const active = data.active.length > 0 ? data.active.join(", ") : "none"
  const temporary = data.temporary.length > 0 ? data.temporary.join(", ") : "none"
  switch (data.reason) {
    case "armed":
      return {
        title: "Classifier bypass armed",
        message: `Active: ${active}. Protections relaxed for this session; expires after inactivity. Run /bypass-classifier for details.`,
        variant: "warning",
        duration: 8000,
      }
    case "updated":
      return {
        title: "Classifier bypass updated",
        message: `Active: ${active} (temporary: ${temporary}).`,
        variant: "warning",
        duration: 6000,
      }
    case "expired":
      return {
        title: "Classifier bypass expired",
        message: "Normal command-safety checks are active again.",
        variant: "info",
        duration: 8000,
      }
    case "cleared":
      return {
        title: "Classifier bypass cleared",
        message: "Normal command-safety checks are active again.",
        variant: "info",
        duration: 6000,
      }
    default:
      return {
        title: "Classifier bypass status",
        message: `Active: ${active} (temporary: ${temporary}; permanent: ${data.permanent.length > 0 ? data.permanent.join(", ") : "none"}).`,
        variant: "info",
        duration: 6000,
      }
  }
}

export default plugin
