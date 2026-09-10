# /bypass-classifier 通知机制与提示词改进设计

> 状态：**调研/设计稿，未改代码**。既有文件只读。
> 证据均来自本仓库 `src/` 与 `opencode-v2-src-latest`（branch v2）源码，引用格式 `文件:行`。
> 日期：2026-09-10。

---

## 0. 问题诊断：为什么现在“注入”是错的

现状回执走 `ctx.session.synthetic`：

- `src/index.ts:1448-1456`（非法参数）、`src/index.ts:1479-1486`（状态）。
- 调用带 `resume:false`，**确实不会唤醒 agent**：`opencode-v2-src-latest/packages/core/src/session/session.ts:319`
  仅在 `resume !== false` 时 `execution.wake(sessionID)`。

但有两个致命点：

1. **synthetic 是模型可见的 user 消息**。`packages/core/src/session/runner/to-llm-message.ts:256-257`：
   `case "synthetic": return [Message.make({ role: "user", content: message.text })]`。
   即“给用户看的回执”被塞进了模型上下文，并伪装成一条 user 发言。
2. **它同时又是用户看不见的**。TUI 只显示带 `description` 的 synthetic：
   `packages/tui/src/routes/session/rows.ts:298`（`if (message.type === "synthetic" && !message.description?.trim()) return rows`），
   事件订阅亦同 `rows.ts:227-229`。当前实现只传 `metadata`、不传 `description`，
   所以 **模型看得到、TUI 聊天里反而看不到**——完全反了。

**关键结论（决定了整个方案）**：v2 里不存在“用户可见、模型不可见”的 session 消息类型。
`synthetic` / `system` / `shell` 全部会进入模型
（`to-llm-message.ts:256-278`）。因此：

- **用户侧反馈必须走 TUI 事件通道**（toast / slot / dialog），绝不能写进 session；
- **agent 侧警告**另行注入，且必须显式声明“不唤醒”。

这两条路径必须分开，不能再用同一条 synthetic 兼顾。

---

## 1. 目标与约束

| # | 目标 | 硬约束 |
|---|---|---|
| G1 | 用户侧：状态、help、生效/失效立即可见，且不进模型 | 不得使用任何 session 消息 |
| G2 | agent 侧：生效/失效时收到**警告性**提示，而非状态罗列 | 不得主动唤醒（不触发 `execution.wake`） |
| G3 | help：`/bypass-classifier invalid` 由用户侧显示 usage | 不得把 usage 塞给 agent |
| G4 | 服务端为权威状态，headless（`opencode2 run`）仍可用 | 无 TUI 时优雅降级 |
| G5 | 复用现有租约/传导/缓存键逻辑，不重写安全面 | 只改通知与提示词 |

---

## 2. 可用通道能力盘点（已逐条核实）

| 通道 | 用户可见 | 模型可见 | 主动唤醒 | 适用 |
|---|---|---|---|---|
| `session.synthetic(resume:false, 无 description)` | 否 | **是** | 否 | ✗（就是当前 bug） |
| `session.synthetic(resume:false, 有 description)` | 是（聊天行） | **是** | 否 | △ 状态变更可用，但污染上下文 |
| `session.synthetic(resume:true)` | 是 | 是 | **是** | ✗ 禁止 |
| 命令 `execute` 抛错 → `Command.ExecutionError` | 是（toast `Failed to run command`） | 否 | 否 | ✓ help/错误（`prompt/index.tsx:1309-1313`） |
| `session.hook("context")` 注入 SystemPart | 否 | **是（每步）** | 否 | ✓ agent 警告（`host.ts:505`、`model-request.ts:308-318`） |
| RPC `register().events.emit` → TUI `client.rpc(def).events.on` | 经 TUI 插件 | 否 | 否 | ✓ 用户 toast 的正规推送通道（`core/src/rpc.ts:87-106`） |
| TUI `ui.toast` / `ui.slot("sidebar.content")` | 是 | 否 | 否 | ✓ 需要 TUI 伴随插件 |
| TUI keymap slash（`arguments:true`） | 是 | 否 | 否 | ✓ 用户侧 help/交互 |

补充证据：

- 服务端**没有**任何代码发布 `tui.toast.show`（全仓仅 `tui/src/app.tsx:1234` 消费 + `prompt/index.tsx:338` 消费
  `tui.prompt.append`）。server 插件 ctx 只有 `event.subscribe`，**没有** `bus.publish`
  （`packages/core/src/plugin/host.ts:192-194`、`packages/plugin/src/effect/event.ts:1-3`）。
  故“用户 toast”只能由 TUI 插件经 RPC 事件触发。
- RPC 事件是 ephemeral / live-only（`core/src/rpc.ts:193`），TUI 断线重连会漏事件，需要拉取补偿。

---

## 3. 推荐架构（分层）

```
┌─────────────────────────── server plugin (权威) ───────────────────────────┐
│ 租约/传导/缓存键：保持现状                                                   │
│ 命令 /bypass-classifier：只改状态，不再 synthetic                            │
│   ├─ 非法参数 → 抛错（用户 toast）；或交给 TUI 命令显示 help                 │
│   └─ 合法变更 → setLease + emit RPC "changed"                               │
│ RPC 定义 bashClassifier.bypass：methods {get,set}，events {changed}         │
│ session.hook("context")：按 activeBypass(sessionID) 注入警告 SystemPart      │
│   └─ 消费 pendingNotices（生效/失效一次性提示）                              │
│ 到期 sweep（定时）：检测 TTL → emit changed(reason:expired) + queue notice   │
└──────────────────────────────────────────────────────────────────────────┘
                                   │ RPC events (ephemeral)
                                   ▼
┌─────────────────────── TUI companion plugin (增强，可选) ───────────────────┐
│ client.rpc(Bypass).events.on("changed") → ui.toast({variant:"warning"})    │
│ keymap slash /bypass-classifier (arguments:true) → get/set + dialog.alert   │
│ ui.slot({append:"sidebar.content"}) → 状态行（可选，需 JSX 构建）           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. 逐项设计

### 4.1 用户通知（G1/G3）

- **help / 非法参数**：优先在 TUI 命令侧用 `ui.dialog.alert` 或 `ui.toast` 展示 usage，
  完全不经过 session。headless 下服务端命令抛 `Command.ExecutionError`（TUI 原生 toast）。
- **生效/变更/失效**：服务端 `emit("changed", state)`；TUI 订阅后
  `ui.toast.show({ title: "Classifier bypass", message, variant: "warning", duration: 5000 })`。
- **持续状态**：见 §6 侧边栏。
- **命令正常状态查询**：不要在服务端 synthetic 回显；由 TUI 命令调用 RPC `get` 后自行渲染。

> 文案要点：toast 用 `warning`，明确“这是用户授权的临时放宽”，避免误读为普通提示。

### 4.2 agent 通知与提示词（G2）

用 `session.hook("context")`，在每次 model step 前把当前状态写进 `event.system`：

- **位置**：`event.system.push(...)`（追加到 system 末尾）。理由：prompt cache 是前缀缓存，
  末尾追加不破坏静态 system 前缀的缓存；而 `splice(1,0,...)` 会使其后的 system 段全部失效。
- **文本保持静态**：活动期内不要插入随 TTL 变化的秒数，否则每步都变、缓存全废。
- **一次性过渡**：维护 `pendingNotices: Map<sessionID, string[]>`：
  - arm/change 时 push “bypass armed/changed”；
  - 到期 sweep 时 push “bypass expired”；
  - context hook 里 drain 成 SystemPart 后清空，保证精确一次。
- **覆盖子代理**：context hook 对每个 session 触发，`activeBypass(sessionID)` 已沿祖先链并集租约
  （`src/index.ts:604-616`），子代理会自动收到警告。

**关键区分**：“持续活动”用每步渲染的 system 行；“状态跳变”用一次性 pendingNotice。
两者都不唤醒，都在 agent 真正运行时才可见。

### 4.3 help（G3）

- 解析失败不要 `return` 静默（现状 `src/index.ts:1447-1457`），改为：
  - 服务端命令：`Effect.fail(new Error(usage))` → `Command.ExecutionError` → TUI toast；
  - TUI 命令：`ui.dialog.alert({ title, message: usage })`，原生用户侧。
- usage 文案建议包含五类语义一句话，避免用户不确定 `os`/`secret` 范围。

### 4.4 到期检测

现状租约是**惰性** prune（`src/index.ts:596-602`，仅在被查询时清理），没有任何地方在到期瞬间通知。
新增一个作用域内的定时 sweep（如 `Effect.repeat`/`Schedule.spaced` 每 15–30s）：

```
for each lease: if expiresAt <= now → 删除 + emit("changed", {active:false, reason:"expired"}) + queueNotice("expired")
```

- 到期文案要说明“保护已自动恢复”。
- 断线/重连：TUI 在 `server.connected` 或挂载时调用 RPC `get` 对齐一次。

### 4.5 缓存键（保持现状）

`dynamicAllowCacheKey` 已把 bypass 类别集纳入键（`src/index.ts:345`、`:318`），
通知改造不触碰该逻辑，无需变更。

---

## 5. 提示词草案

agent 侧文本必须英文（与现有 system prompt 一致），且以**告警**口吻而非状态口吻。

**活动期（system，每步，静态）**

```
[SECURITY BYPASS ACTIVE — session scope]
The user has explicitly armed classifier bypass categories for this session: {categories}.
While active, those static rules and/or the dynamic reviewer will not block matching actions.
Treat this only as a temporary relaxation of the checks, NOT as authorization to do more than
the current task requires. Do not perform destructive, irreversible, credential-touching, or
system-level changes unless the user explicitly asked for them in this task.
Prefer reversible actions; when unsure, stop and ask. The bypass ends automatically and is
never permanent.
```

**失效一次性（system，一步）**

```
[SECURITY BYPASS ENDED]
The classifier bypass for this session has expired; normal static and dynamic checks are
active again. Resume normal caution; nothing here is a standing permission.
```

**用户侧 toast**

- arm：`Bypass armed: filesystem, os — protections relaxed for this session (auto-expires).`
- expired：`Bypass expired: normal classifier checks are active again.`
- invalid：usage 全文。

**动态审查器提示词**（`auditor.py` 的 `userBypass` 静态块）保持既有“用户已显式豁免”措辞即可，
但建议补一句与上面同源的边界：“豁免不等于允许破坏性/不可逆操作”。

---

## 6. 该不该注册 TUI 侧边栏？

**建议：做，但作为第二阶段；且只做“只读指示器”，不做可点击开关。**

理由与代价：

- 这是唯一能持续展示“当前 session 处于 bypass”的用户通道，且完全不进模型、不唤醒
  （`ui.slot({append:"sidebar.content", render:({sessionID}) => ...})`，slot 输入 `{sessionID}`，
  `packages/plugin/src/tui/context.ts:191-201`）。
- **代价**：`render` 必须返回 `JSX.Element`，而本插件目前是零构建的裸 TS（`package.json` `main: ./src/index.ts`）。
  若加 TSX 侧边栏，需要引入 esbuild + `esbuild-plugin-solid` 预编译
  （参考 `opencode-tokenwatch/build.tui.mjs`）。这与“最小改动”原则冲突。
- **折中**：
  - 第一阶段：TUI 命令 + toast（**纯 API，无 JSX、无构建**）即可满足 G1/G3。
  - 第二阶段：再加侧边栏；优先 `sidebar.content`，warning 色，只显示
    `BYPASS fs, os · 12m`，并在失效后自动消失。
- **安全性**：不要把侧边栏做成“一键开关”，避免误触削弱安全边界；开关仍只认显式 slash 命令。

---

## 7. “不得主动唤醒”核对

- 现状 `resume:false` 已不唤醒（`session.ts:319`），新方案继续不调用 `resume:true`、
  不调用 `session.prompt`、不调用 `execution.wake`。
- `session.hook("context")` 只在既有 model step 内触发，不产生新 step。
- RPC `events.emit` 只 publish 到 bus，不触发会话执行。
- TUI toast/slot 纯客户端。
- **结论**：新方案在所有路径上都不主动唤起 agent。

---

## 8. 变更清单（文件级，预估）

| 文件 | 变更 |
|---|---|
| `src/index.ts` | 删除命令内的两处 `session.synthetic`；非法参数改为 fail；注册 RPC（定义放 `src/rpc-bypass.ts`）；`EffectPluginContext` 增 `rpc` 与 `session.hook` 镜像；`session.hook("context")` 注入警告 + drain pendingNotices；到期 sweep 定时器；`emit("changed")` |
| `src/rpc-bypass.ts`（新增） | 手写 `Rpc.Definition` 对象（JSON Schema），避免运行时 import `@opencode-ai/plugin`（沿用本插件“只 import type”约束，`V2-PLUGIN-API.md:84`） |
| `src/tui.tsx`（新增，二阶段） | TUI 命令（无 JSX 也可）+ 订阅 RPC → toast；侧边栏 slot（需 JSX） |
| `package.json` | 加 `exports["./tui"]`；sideEffect 等；若做 JSX 加 `build.tui.mjs` |
| `README.md` / `CHANGELOG.md` | 通知行为、help 位置、sidebar、RPC id |
| `src/security/auditor.py` | （可选）bypass 边界措辞补强 |

> 注意：`src/index.ts` 现有本地 `EffectPluginContext` 是“窄化镜像”，加 `rpc`/`session.hook` 时
> 仍只写结构类型，不引入运行时 import。

---

## 9. 风险与边界

1. **system 注入的 token/缓存成本**：活动期每步多一段文本。缓解：文本静态、放 system 末尾；
   仅在 `activeBypass` 非空时注入。
2. **RPC 事件 live-only**：TUI 重连漏事件。缓解：挂载/`server.connected` 时 RPC `get` 对齐。
3. **到期通知依赖定时器**：无定时器时退化为“下次 context hook 按当前状态渲染”（不会误报 active）。
4. **无 TUI 的 headless**：仅 agent 警告 + 命令错误 toast 语义（run 模式无 UI），符合 G4。
5. **子代理**：警告随祖先租约覆盖，但 context hook 无法区分“本 session 自己的租约”与“继承”，
   文案统一即可，不暴露内部来源。
6. **迁移**：现状所有 `/bypass-classifier` 回执都从“模型可见”改为“用户侧”，
   是行为变更，需在 CHANGELOG 标注。

---

## 10. 待决策

1. 第一阶段是否接受“无侧边栏、仅 TUI 命令 + toast + agent system 警告”？
2. 是否引入 TUI 构建（esbuild + solid）以支持侧边栏？
3. 到期 sweep 周期（建议 15–30s）与是否在 arm 时也发一次性 agent 提示（现设计为持续 system 行）。
4. agent 警告文本最终措辞（§5 草案）。
