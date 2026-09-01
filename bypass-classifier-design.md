# opencode-bash-classifier 逃逸路径（Bypass）设计调研

> **实现状态注记（2026-09-01，定稿）**：本文档为设计期调研记录，保留原貌供追溯。最终决策与实现有
> 三处差异：租约 TTL 默认 **20 分钟**（范围 1min–24h，`bypassLeaseTtlMs`）；子代理传导 **默认开**
> （`bypassPropagateToSubagents`，默认 `true`）；`network.reverse-shell` 连同其他 9 条规则列入
> **不可绕过底线**（FLOOR_RULES，任何类别都不豁免）。租约模型实现为：`activeBypass` 沿祖先链
> **并集**所有存活租约，活动事件续期自身 + 全部祖先租约；子代理向父传导 arm 时从当前 active 集
> 合叠加。静态层豁免后返回 `bypass.static-allow` ASK 交动态审查器（配合按类别的 BYPASS RULE 提示
> 词），不直接 ALLOW。以 `src/security/bypass.ts`、`src/index.ts`、README 为准。

日期：2026-09-01。所有可行性结论均已对照 `opencode-v2-src`（branch v2）源码与本插件现有实现核实，引用格式 `文件:行`。

## 0. 需求回顾

分类器误判率高、过于谨慎，需要用户手工配置的逃逸路径：

- **永久**：`config.json` 顶层 `BypassClassifier: [list]`。
- **暂时**：命令 `/bypass-classifier <category>`，仅作用于当前 session 与本次 TUI 活动；
  其他 session 不生效；TUI 关闭再打开（用户关掉终端窗口 = 离开工作）或 opencode2 服务重启后失效。

五个类别：

| 类别 | 语义 | 备注 |
|---|---|---|
| `filesystem` | 停止一切文件系统检查（删除项目文件、破坏数据不再阻止） | `rm -rf /` 这类明显毁系统的仍拦截 |
| `os` | 停止一切系统状态检查（杀关键进程、改注册表、`sudo chmod 777 *`、`wsl --shutdown` 均不阻止） | 完全放开系统操作权 |
| `secret` | 停止敏感文件检查（读 env/secret key、打印/发送/修改密钥） | |
| `dynamic` | 禁用动态审查器，视为不可用，走 failPolicy | |
| `web` | 信任一切网络操作（每个 HTTP 地址/域名都可信） | |

## 1. 可行性结论总览

| 机制 | 结论 | 关键证据 |
|---|---|---|
| config.json 永久 bypass | **可行**，小改动 | `src/index.ts` resolveStartup 已有 config.json 读取；需注意当前 live 配置走 options 时 config.json 被跳过（见 §2.3） |
| server 插件注册 slash 命令 | **可行，无需 TUI 伴随插件** | effect 插件 ctx 有 `command` 域（`packages/plugin/src/effect/plugin.ts:31`）；TUI 提示框对 server 命令有原生分发（见 §3） |
| 暂时 bypass 状态存插件进程内存 | **可行且是唯一正确位置** | KV/DB 会跨重启持久（违反重启失效）；TUI storage 跨进程不可达（见 §4） |
| session 隔离 | **可行**，天然按 sessionID 键控 | 命令 execute 收到 `sessionID`（`packages/core/src/command.ts:20-24`）；execute.before 事件带 `sessionID` |
| **服务端精确检测 TUI 关闭** | **不可行**（无客户端在场事件） | 证据链见 §6.1；只能用"活动续期 TTL"近似（方案 A）或 TUI 伴随心跳（方案 B） |
| 服务重启失效 | **免费满足**（内存态） | 插件 effect 闭包内 Map，进程死即清 |

## 2. 永久逃逸：config.json `BypassClassifier`

### 2.1 形状

```json
{
  "BypassClassifier": ["filesystem", "os", "secret", "dynamic", "web"]
}
```

- `config.ts`：`ALLOWED_TOP_LEVEL` 增加 `BypassClassifier`；`ResolvedPluginConfig` 增加 `bypassClassifier: ReadonlySet<Category>`。
- 校验：数组、元素必须是五类之一。未知类别 **warn + 忽略该元素**（不抛错）：抛错会让整个插件加载失败（`resolveStartup` 失败 → 插件不加载 → 分类器整体关闭），对一个安全功能而言"部分生效的分类器"远好于"分类器整个消失"；warn 语义与现有 `dynamicReview` 的 reason-warning 一致（`config.ts:346-349`）。
- 生效范围：**所有 session**（含 headless `opencode2 run`），这是"永久"的自然语义。

### 2.2 类别 → 规则映射（永久与暂时共用）

映射是规则 ID 前缀/成员到类别的表。静态层在每个判定点按"当前 session 的 bypass 集"跳过对应类别的规则（详见 §7）。

- **filesystem**：`filesystem.*`（find-delete、forced-recursive-delete、root-glob-delete、brace-root-delete、backup-destruction、find-delete-root、compression-root、tar-extract-system、scoped-delete、broad-scan、outside-write）、`data.destructive-delete`、`data.destructive-overwrite`、`execution.script-one-liner-destructive`、`execution.xargs-destructive`、`git.irrecoverable-change`、`cleanup.*`、`operation.context-required` 的重定向分支
- **os**：`system.*`（service-destruction、shutdown、critical-process-kill、file-override、sensitive-write）、`process.termination`、`permissions.root-recursive`、`permissions.world-writable`、`permissions.setuid`、`kernel.sysctl-write`、`execution.kernel-module-load`、`namespace.escape`、`persistence.backdoor`、`persistence.git-hooks`、`forensic.*`、`operation.context-required` 的 kill/sudo 分支
- **secret**：`credentials.sensitive-access`、`credentials.foreign-home`、`data.critical-read/write/delete`（凭据文件）、`exfiltration.sensitive-data`、`exfiltration.dns`、`filesystem.compression-sensitive`、`permissions.sensitive-mode`、`SENSITIVE_ENV_PREFIX`（`LD_*` 等注入）
- **dynamic**：不映射规则；直接让该 session 的动态审查"不可用"（§7.2）
- **web**：`network.*`（reverse-shell、destructive-api、firewall-mutate）、`execution.remote-pipe`、`operation.context-required` 的 curl/wget/ssh 分支；动态审查器提示词追加"端点全部可信"（§7.3）

### 2.3 重要发现：live 配置当前根本不读 config.json

`resolveStartup`（`src/index.ts:450-509`）的优先级是：`options.configFile` > **options 非空时跳过 config.json** > options 为空才兜底读包根 `config.json`。当前 live 安装（`~/.config/opencode/opencode.json:525-540`）带完整 options，所以 config.json 现在只是摆设。

要满足"永久项写在 config.json"，需要把 config.json 提升为 **基础层**：始终读取（若存在），逐字段被 options 覆盖。当前两处内容一致（strictness/failPolicy/logReviewerTrace/dynamicReview 完全相同），所以此改动对现状零行为差异。这是一个语义变化点，实现时在 README 标注。

## 3. 暂时逃逸：`/bypass-classifier <category>` —— 服务端命令注册

**结论：直接用 v2 effect 插件的 `command` 域注册 server 命令，TUI 原生支持，不需要任何 TUI 侧代码。**

已核实的完整链路：

1. **注册**：`ctx.command.transform(draft => draft.add({...}))`。effect 插件 Context 含 `command: CommandDomain`（`packages/plugin/src/effect/plugin.ts:31`、`command.ts:8-22`），宿主接线在 `packages/core/src/plugin/host.ts:188-191`。本插件 `src/index.ts` 的本地 `EffectPluginContext` 镜像需补 `command` 域。
2. **TUI 输入分发**：用户在提示框敲 `/bypass-classifier filesystem`：
   - 补全列表含 server 命令（`packages/tui/src/component/prompt/index.tsx:540` 读 `data.location.command.list`）；
   - 提交时命中 server 命令 → `client.api.session.command({sessionID, command, text: 参数})`（`index.tsx:1164-1166, 1286-1293`）。
3. **服务端执行**：`session.command`（`packages/core/src/session.ts:517-535`）→ flush 插件 → `Command.Service.execute`，invocation 携带 **sessionID** 与 `prompt.text`（= 命令后参数）。
4. **回执**：execute 内用 `ctx.session.synthetic({sessionID, text, resume: false})` 向当前会话发确认消息（本插件已有此用法，`src/index.ts:651-660`）；参数非法时抛错 → `Command.ExecutionError` → TUI toast。
5. **不会进模型**：命令 execute 不调用 `session.prompt`，参数文本不会交给 LLM。

命令语法设计：

```
/bypass-classifier                    # 查看状态（synthetic 回显当前集 + 剩余 TTL）
/bypass-classifier filesystem web     # 添加类别（空格或逗号分隔）
/bypass-classifier all                # 五类全开
/bypass-classifier off                # 清除本 session 的暂时 bypass
```

## 4. Q1：暂时 bypass 的状态如何存储

**结论：唯一正确位置是插件 effect 闭包内的进程内存 Map（现状 `sessions`/`dynamicAllowCache` 同款），配 TTL 租约。**

```ts
const temporaryBypass = new Map<string /* sessionID */, {
  categories: Set<Category>
  expiresAt: number   // 租约到期时刻
}>
```

排除的其他选项（均为硬性缺陷）：

| 候选 | 为什么不行 |
|---|---|
| `ctx.storage`（KV/sqlite，`packages/core/src/kv/sql.ts`） | 持久化跨服务重启 → 违反"重启后失效" |
| session 数据库/消息 | 同上；且把逃逸状态写进持久会话数据语义混乱 |
| TUI `storage.store` | 落盘持久化；且 server 进程读不到 |
| TUI `storage.memory` | 语义完美（"本次 TUI 活动"=TUI 进程内存），但物理上在 TUI 进程里，server 分类器在 execute.before 时无法读取 —— 除非配心跳桥（方案 B，§6.3） |

进程内存同时免费满足"服务重启失效"：effect 闭包随进程死；插件重载时现有 `Effect.addFinalizer`（`src/index.ts:1196-1204`）清空全部 Map。

## 5. Q2：怎么隔离 session

- **键控**：`Map<sessionID, …>`。命令 execute 拿 `input.sessionID` 写入；`execute.before` 用 `ev.sessionID` 查询。跨 session 不可能串。
- **位置隔离（额外一层）**：插件实例本身是 per-location 的（`packages/core/src/plugin.ts:183` `makeLocationNode`），不同项目目录各有一份闭包与 Map。
- **清理**：沿用现有 `session.deleted` 事件消费（`src/index.ts:1179-1192`）删除对应条目。
- **生效集**：`active(sessionID) = permanentSet ∪ temporaryBypass.get(sessionID)`。
- **子代理 session（重要设计点）**：子代理（subagent）是独立 sessionID，字面语义"只作用于当前 session"意味着 **bypass 不传导给子代理**。但实际干活的常常是子代理，主 agent 很少直接跑 shell。若严格不传导，该功能对子代理驱动的工作几乎无效。事件 `session.created` 携带 `parentID`，可低成本实现"向本 session 的后代 session 传导"。**建议默认传导**（用户武装的是同一工作意图），留 config 开关。待用户拍板（§10）。
- **缓存键必须包含 bypass 集（关键坑）**：`dynamicAllowCache`/`dynamicDenyCache` 是全局缓存，仅按上下文寻址（`src/index.ts:302-350`）。bypass 后的 ALLOW 若被无 bypass 的 session 复用 = 检查被间接绕过。**`dynamicAllowCacheKey` 的 payload 必须加入该 session 的 bypass 类别集合**，deny 缓存同理；bypass 集合不同 → 键不同 → 天然隔离。
- **武装时清历史**：`/bypass-classifier` 生效时对该 session 调一次现有 `recordRejection` 的清空（`sessionState.lastRejected = undefined` + generation 递增），避免 bypass 前的拒绝记录在 HARD 模式下继续强制审查。

## 6. Q3：怎么检测"TUI 遭关闭"

### 6.1 事实：服务端无法直接感知客户端在场/离场

逐条核实过：

- 公开事件流上**没有客户端连接生命周期事件**。`server-event.ts` 全部内容只有 `server.connected` 与 `global.disposed`。
- `server.connected` **不是** Bus 事件：它在 SSE handler 内对每条新订阅本地注入（`packages/server/src/handlers/event.ts:12-22`），从不 `Bus.publish`。插件能看到的 `ctx.event.subscribe()` 是 `bus.subscribe().pipe(Stream.filter(EventManifest.isServer))`（`packages/core/src/plugin/host.ts:192-194`）——因此插件**看不到**任何 per-client 连接/断开。
- SSE 订阅者集合在 server 包内部（`packages/server/src/event-feed.ts`），不暴露给插件 API；心跳（15s `: heartbeat`）是 server→client 方向，服务端无插件可见痕迹。
- `tui-event.ts`（toast/command.execute/session.select）全部是 server→TUI 方向。
- TUI 的连接状态（connecting/connected/reconnecting，`packages/client/src/solid/connection.ts`）只存在于 TUI 进程的 Solid store。
- 关终端窗口 = TUI 进程收到 SIGHUP（或被 SIGKILL），**优雅清理不保证执行**，所以"关闭时主动通知 server"不可靠。

结论：精确检测必须由**仍然活着的 TUI 进程**持续表态；server 只能做租约。

### 6.2 方案 A（推荐起步）：活动续期 TTL 租约，纯服务端

- 租约：`expiresAt = now + LEASE_TTL_MS`（建议默认 **10 分钟**，config 可调 `bypassLeaseTtlMs`）。
- **续期信号**（插件已在订阅 Bus 事件流）：该 sessionID 的任何活动事件都续期——`session.viewed`（TUI 查看未读会话时上报，`packages/tui/src/context/session-tabs.tsx:245`）、`session.inbox.delivered`、`session.execution.started`、step/tool/text 事件，以及 `execute.before` 命中该 session 时自续。
- TUI 开着 → 事件持续流（生成期密集、查看未读时也有）→ 租约不断续。TUI 关掉 → 会话安静 → 租约到期 → bypass 失效。**服务重启 → 内存清零。**
- 已知偏差（必须向用户如实声明）：
  1. 关 TUI 后若 session 仍在生成（服务后台继续跑），事件继续流 → 租约续到生成结束 + TTL。这其实贴合"仍在执行用户工作"。
  2. 关 TUI 后 **TTL 窗口内**重开 TUI，bypass 仍在（无法区分"没关过"和"刚重开"）。上界即 TTL。
  3. 失效方向是**安全侧**：宁可提前让分类器回来（用户重敲一次命令即可），不会让 bypass 超期存活。
- 成本：约 30 行代码，零新组件。

### 6.3 方案 B（精确语义，可后加）：TUI 伴随插件 + storage.memory + 心跳

- 本包加 `exports["./tui"]` + server 插件定义标 `tui: true` → TUI 自动加载其 tui 模块（`packages/tui/src/plugin/context.tsx:488-493` 对 active 且 `tui` 的包插件解析 `subpaths:["tui"]`；usage-stat 已走通此路）。
- TUI 侧把开关放在 `context.storage.memory`（TUI 进程内存，**任何形式的关闭都必然清零**）；每 60s 对每个已武装 session 调 `client.api.session.command`（一个静默 heartbeat 子命令）续租；server 租约 TTL = 2× 心跳间隔。
- TUI 进程死亡（SIGHUP/SIGKILL/正常退出）→ 心跳停 → 租约 2 分钟内过期。**精确满足"TUI 关闭即失效"。**
- 服务重启失效：server 内存清零；TUI 伴随插件观察到 `server.connected`（重连时流上会再收到，`packages/tui/src/mini/stream-v2.transport.ts:1412` 证实断线重连语义）即**清空本地开关**，不自动复活。此点需运行时验证。
- 无 JSX 也能写（keymap 注册可借 `ui.slot({append:"app", render: () => {注册; return null}})`，无需预编译 JSX；host 模块映射保证 `@opencode-ai/plugin/tui/*` 运行时可用，`packages/tui/src/plugin/runtime-plugin-support.bun.ts`）。
- 成本：新增 tui 入口、心跳计时器、重连清零逻辑；复杂度约为方案 A 的 3 倍。

### 6.4 对比与推荐

| | A：活动 TTL | B：TUI 心跳 |
|---|---|---|
| "TUI 关闭即失效" | 近似（≤ TTL 滞留） | 精确（≤ 2 心跳周期） |
| 服务重启失效 | 精确 | 精确（需重连清零） |
| 实现量 | 小 | 中（多一个 tui 出口） |
| 失效偏差方向 | 安全侧（提前失效） | 无 |
| 对 headless `opencode2 run` | 同样工作 | 同样工作（server 命令不依赖 TUI） |

**推荐：先落地方案 A（10 分钟 TTL），把方案 B 列为增强**。A 的唯一偏差是"TTL 内重开仍生效"，而用户要求的本质是"人走了 bypass 不该永久化"——10 分钟上界已满足该本质，且偏差方向安全。

## 7. 分类管线中的接入点

### 7.1 静态层

推荐做法：`ClassifyShellCommandInput` 增加 `bypassedCategories?: ReadonlySet<string>`，在 `classifyShellCommand` 内部各判定点按类别跳过：

- `SECURITY_SIGNAL_RULES` / `HARD_DENY_LOOSE_ASK_RULES` 循环：跳过类别命中且不在底线（floor）的规则；
- `classifyPathTarget`（`paths.ts:302`）：secret/filesystem/os 对应的 read/write/delete 敏感判定分别放行（类别旗标传入 `PathContext`）；
- 复合 ASK（`operation.context-required`，`classifier.ts:3967-3976`）按触发原语分流：kill/sudo→os、curl/wget/ssh→web、重定向→filesystem；
- `data.*`、`git.irrecoverable-change`、`exfiltration.*` 等按 §2.2 映射。

**不可绕过底线（floor，五类 bypass 也拦）**，用一个独立谓词而非规则 ID 成员：

- `rm -rf /`、`rm -rf /*`、`--no-preserve-root`（字面根删除）
- `filesystem.disk-destruction`（mkfs/dd 写设备/wipefs/shred 设备/format）
- `execution.fork-bomb`
- `filesystem.kernel-trigger`、`filesystem.kernel-core-pattern`（内核执行原语）

（`network.reverse-shell` 建议也进底线——它超出"信任 HTTP 地址"的范畴、属于远程控制原语；待用户确认，默认建议保留拦截。）

保留项（与安全类别无关，永不受 bypass 影响）：慢命令软拦截（性能成本）、`hardTimeoutMs` 注入、`apply_patch` 删文件块（工具路由约束）、`input.empty`。**OpenCode 原生权限层不受本插件 bypass 影响**，仍是最终关卡——这是良好的纵深防御残余。

### 7.2 `dynamic` 类别

exact 语义复用现有代码路径：`reviewerAvailable()` 对该 session 返回 false → `reviewError = "not configured"` → 现有 failPolicy 路由（`src/index.ts:949-951, 1095-1109`）。`fail_open`（当前 live 配置）下 ASK → 放行；`fail_close` 下 → 拒绝。协议类失败的特殊 fail-close 分支自然不触发（没有审查器调用）。连续失败 toast 逻辑不触发。

### 7.3 `secret` / `web` 的动态审查器联动（必须，否则语义不完整）

动态审查器提示词写死"credential files are sensitive in every mode"（`auditor.py` LOOSE/HARD_PROMPT）。若只放静态层，secret bypass 后动态层仍会 DENY 读 `.env`。需要：

- 请求 JSON 增加可选字段 `userBypass: [...]`（auditor.py 的 `ALLOWED_FIELDS`/校验同步扩展）；
- `_build_system_prompt` 按存在性追加**静态**提示块（照 `BYPASS_PROMPT` 模式，不插值不可信值）：secret → "用户已显式豁免本会话的敏感文件限制，不得仅因敏感文件访问而 DENY"；web → "用户已声明信任一切网络端点，不得因目标域名/HTTP 操作而 DENY"；
- bypass 类别进缓存键（§5）。

### 7.4 审计

`logReviewerTrace` 开启时追加 `kind: "bypass_allow"` 行（sessionID、命令、生效类别、static/dynamic 来源），保持可追责。

## 8. 实现改动清单（文件级，预估 ~600 行含测试）

| 文件 | 改动 |
|---|---|
| `src/config.ts` | `BypassClassifier` 白名单/解析；`bypassLeaseTtlMs`；`ResolvedPluginConfig` 扩展 |
| `src/index.ts` | config.json 基础层合并；`EffectPluginContext` 补 `command` 镜像；`/bypass-classifier` 命令注册与参数解析；`temporaryBypass` Map + 租约续期（事件订阅处）；`active(sessionID)` 查询；`runBefore`/`dynamicAllowCacheKey`/`recordRejection` 接入；trace |
| `src/security/classifier.ts` | `ClassifyShellCommandInput.bypassedCategories`；规则循环/复合 ASK/路径敏感判定按类别放行；floor 谓词 |
| `src/security/paths.ts` | `PathContext` 类别旗标；`classifyPathTarget` 分支 |
| `src/security/auditor.py` | `userBypass` 字段校验 + 静态提示块 |
| `src/security/reviewer.ts` | 请求字段透传 |
| `README.md` | 新章节：类别语义、永久/暂时用法、租约与失效边界、config.json 语义变化 |

## 9. 风险与限制（如实声明）

1. TUI 关闭的检测是**租约近似**（方案 A）：上界 TTL 内重开仍生效；关窗后仍在跑的生成会续租到结束。
2. bypass 是用户明确授权的风险决策：`filesystem` 下 `rm -rf ~/important-project` 会真实放行；OpenCode 原生权限层仍在其后（部分操作仍会弹权限确认）。
3. 动态审查器是 LLM，提示词修正只能引导，不能保证逐条一致（与现有审查不确定性同级）。
4. floor 谓词是正则级：极端混淆（多层解码等）可能绕过 floor——但这类命令本就大概率落入 `execution.wrapper` ASK 走动态审查，实际暴露有限。
5. 服务重启后 config.json 的永久集继续生效（这是"永久"的定义），暂时集全部消失。

## 10. 待用户决策

1. **TUI 关闭检测机制**：方案 A（活动 TTL 租约，推荐）还是方案 B（TUI 伴随心跳，精确）？或 A 先行、B 后补？
2. **子代理传导**：bypass 是否传导到当前 session 的 subagent 后代 session？（建议：传导，默认开）
3. **底线构成**：`network.reverse-shell` 是否保留在不可绕过底线中？（建议：保留）
4. **租约 TTL 默认值**（方案 A）：10 分钟？