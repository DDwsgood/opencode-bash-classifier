// Shared RPC contract for the `/bypass-classifier` **user notification** channel.
//
// Why this exists: v2 has no session message type that is visible to the user
// but hidden from the model — `synthetic`/`system`/`shell` all enter the model
// context (`packages/core/src/session/runner/to-llm-message.ts`). The server
// plugin therefore reports bypass state changes over an ephemeral RPC event, and
// the optional TUI companion (`src/tui.ts`) turns those events into toasts.
//
// The definition is a plain JSON-Schema object on purpose: both the server
// entrypoint and the TUI entrypoint can share it without a runtime import from
// `@opencode-ai/plugin` (the host owns the RPC implementation), keeping the
// package build-free. The `as const` shape satisfies `Rpc.Definition`.
export const BypassRpc = {
  id: "bash-classifier.bypass",
  // Event-only: the command drives state mutations; the TUI only listens.
  methods: {},
  events: {
    changed: {
      schema: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          // armed | updated | cleared | expired | status
          reason: { type: "string" },
          active: { type: "array", items: { type: "string" } },
          temporary: { type: "array", items: { type: "string" } },
          permanent: { type: "array", items: { type: "string" } },
        },
        required: ["sessionID", "reason", "active", "temporary", "permanent"],
        additionalProperties: false,
      },
    },
  },
} as const

export type BypassChangedData = {
  readonly sessionID: string
  readonly reason: "armed" | "updated" | "cleared" | "expired" | "status"
  readonly active: readonly string[]
  readonly temporary: readonly string[]
  readonly permanent: readonly string[]
}
