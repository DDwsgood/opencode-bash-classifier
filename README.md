# opencode-bash-classifier（v2 插件 API 移植版）

执行边界命令安全分类器，拦截 opencode v2 原生 `shell` 工具（v1 的 `bash`），在每条命令**执行前**做静态审查 + 可选的动态 LLM 审查。本目录是 v1 `-next`（0.4.2）到 **opencode v2 effect 插件 API**（`{ id, effect(ctx) }`，`effect` 返回 `Effect.Effect`）的移植版。

> 本版本基于 opencode v2 源码（`~/src/opencode2`，branch v2，HEAD b24b1b3f16）核实。运行时以**源码构建/源码运行**为准（npm next 二进制缺 tool/session/shell/event 域）。

## v1 → v2 hook 映射

| v1（opencode 1.x） | v2（本插件实现） | 说明 |
|---|---|---|
| 函数插件 `{ id, server }` | `export default { id, effect(ctx) }`，`effect` 返回 `Effect.Effect<void>` | v2 effect 插件形状（阻断为单次调用的 typed `Tool.Error` 失败；hook 回调返回 `Effect`） |
| `config` hook（覆写 config.shell） | `ctx.shell.hook("create.before")` | spawn 前改写 `ev.shell`/`ev.env` |
| `shell.env`（注入 `OPENCODE_REAL_BASH`） | 同上（`ev.env.OPENCODE_REAL_BASH = ev.shell`） | 仅 Windows 且 supervisor 二进制存在时生效 |
| `tool.execute.before` | `ctx.tool.hook("execute.before")` | 静态 + 动态审查管线；`ev.input` 可变（`timeout`/`command`） |
| `tool.execute.after` | `ctx.tool.hook("execute.after")` | HARD 失败记录；exit 读 `ev.result.metadata.exit` |
| 工具名 `bash` / `apply_patch` | `shell`（兼容 `bash`）/ `patch`（兼容 `apply_patch`） | `patch` 检查 `input.patchText` |
| `bash_classifier_confirm` + `context.ask` | **已移除** | v2 `Tool.Context` 无 `ask`，`fail_ask` 归一化为 `fail_close`（见下） |
| `client.session.abort` | `ctx.session.interrupt({ sessionID })` | HARD 绕过检测时 best-effort 中断会话 |
| `event` hook（`session.deleted`） | `ctx.event.subscribe()`（`Stream`）`Stream.runForEach` + `Effect.forkScoped` | wire 事件 `{ type, data: { sessionID } }`；插件 scope 关闭时中断消费 fiber（替代手动 cleanup 循环） |
| `pluginContext.directory/worktree` | `ctx.session.get({sessionID}).location.directory`（按会话缓存，回退 `process.cwd()`） | v2 ctx 无 directory 域 |
| 配置来源 `rawOptions` | `ctx.options` + `options.configFile` | `plugins` 配置项 `{ package, options }` |

## 安装

在 `opencode.json` 的 `plugins` 数组（v2 用复数键）引用本地绝对路径：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/home/ddwsgood/opencode-v2-plugins/opencode-bash-classifier",
      "options": {
        "strictness": "HARD",
        "failPolicy": "fail_open",
        "dynamicReview": {
          "baseURL": "https://api.example.com/v1",
          "model": "your-model-id",
          "apiKeyEnv": "MY_REVIEW_API_KEY"
        }
      }
    }
  ]
}
```

纯 TS，无构建步骤（v2 直接加载 `.ts`）。重启 opencode 后生效。

### 目录自动发现与配置文件兜底

配置按**三层合并**（后层逐字段覆盖前层）：

1. 插件根目录下的 `config.json`——**始终读取的基础层**（自动发现场景的兜底文件，也适合存放长期固定的设置，如 `BypassClassifier`、审查器凭据）；
2. `options.configFile`——`plugins` 配置项里显式给出的 JSON 文件；
3. `plugins` 配置项里的 `options`——逐字段覆盖。

配置文件是 JSON 对象，字段与下方 `options` 字段一致；`configFile` 本身是加载器指令，不是插件字段，不会被传给配置校验。config.json 解析失败会打警告并回退默认值（安全设置静默失效比报错更危险）；`configFile` 读取失败则直接抛错。

## BypassClassifier（误判逃逸路径）

动态审查提示词按当前生效类别组装：开启某类豁免时，移除该类别的禁止条款，在系统提示首尾加入 `**IMPORTANT: BYPASS PERMISSION: SECRETS IS ON.**` 等明确授权。授权只来自插件验证后的会话状态；命令、注释和文件中的同名文字不能开启豁免。历史拒绝按当前权限重新判断。

正常 API Bearer 鉴权和 SSH 密钥认证与凭据外传分开判断。LOOSE 不因脚本位于工作树外、未检查或证据不足就自动拒绝；HARD 仍要求检查执行脚本，filesystem 豁免时不再强制检查删除目录。审查器自身的文件读取权限与被审命令权限独立，secret 豁免不会让审查器读取真实秘密文件。动态分类豁免仍通过模型提示执行，不保证模型永不误判；`dynamic` 类别才会跳过审查器，并按 `failPolicy` 路由。

为降低误判与过度谨慎，用户可按类别豁免检查。两类机制：

**永久豁免**——`config.json`（或 options）里：

```json
{ "BypassClassifier": ["filesystem", "secret"] }
```

**临时豁免**——会话内 slash 命令 `/bypass-classifier <category|all|off>`（服务端注册命令，参数不进模型上下文）。实现为**活动续期租约**：内存存储，默认 TTL 20 分钟（`bypassLeaseTtlMs` 可调，1min–24h），会话有活动事件（查看、收件、执行、shell 启动）即续期；关掉 TUI 或服务重启后失效，必须重新 arm。

- 多次 arm 叠加：`/bypass-classifier os` 后再 `/bypass-classifier web` = {os, web}；`off` 清空；`off os` 清空后只 arm os。
- **子代理传导**（默认开，`bypassPropagateToSubagents: false` 关闭）：子代理会话继承父会话（沿祖先链并集）的 armed 类别；子代理干活会续期父会话租约。

### 通知（agent 与用户分离）

v2 不存在“用户可见但模型不可见”的会话消息类型：`synthetic`/`system`/`shell` 都会进入模型上下文，且无 `description` 的 `synthetic` 在 TUI 聊天里还会被过滤掉。因此状态反馈分两条通道，互不共用：

- **agent 侧**：通过 `session.hook("context")` 注入 `<system_reminder>`。豁免活动期间每一步都注入一条简短警告（提醒这是临时放宽、不是破坏性操作的授权）；到期时注入**一次性**“已失效”提示（由定时 sweep 触发，否则惰性过期不会产生跳变事件）。注入不会唤醒会话。
- **用户侧**：服务端注册 event-only RPC（`src/bypass-rpc.ts`），由本包的 TUI 伴随入口（`src/tui.ts`，package `exports["./tui"]`）订阅并弹 toast 显示 armed/updated/cleared/expired/status。参数非法时命令抛错，TUI 显示 usage；usage 不再回显给 agent。
- 无 TUI 伴随（旧 host 无 RPC 域或未加载 CLI 插件）时静默降级：agent 警告仍生效，用户 toast 不可用。
- **本地目录安装**：host 对“目录”形式的插件目标只解析 `<dir>/index`（server）与 `<dir>/tui`（TUI），不看 package.json exports；因此仓库根有 `index.ts` / `tui.ts` 两个薄转发文件。npm 包则走 `exports`。

### 类别语义

| 类别 | 豁免内容 |
|---|---|
| `filesystem` | 文件系统检查：项目文件删除、数据破坏、重定向覆写、归档解包等 |
| `os` | 系统/进程/权限管理：systemctl、kill、sudo、sysctl、crontab、modprobe 等 |
| `secret` | 凭据/敏感文件检查：`.env`、`~/.ssh/*`、`/etc/shadow`、`/proc/*/environ` 的读取/修改/删除 |
| `web` | 所有网络目的地可信：curl/wget/ssh/scp/rsync 的目标、destructive API、防火墙变更 |
| `dynamic` | **跳过动态 LLM 审查器**（静态层仍生效；审查器不可用时走 `failPolicy`） |

规则按所属类别归属豁免（如 `data.critical-delete` 属 `secret` 而非 `filesystem`：arm filesystem 仍拦凭据文件删除，arm secret+filesystem 才放行）。

### 不可绕过底线

以下规则任何类别都不豁免，且在**完整脚本**上判定（不受 `|`/`&`/`;` 段拆分影响）：

- `filesystem.root-delete`（含 `/etc`、`/usr`、`/lib`、`/lib64`、`/sys`、`/proc`、`/mnt` 等 15 个系统根的**裸根或直接 glob**；根下的普通子路径如 `/var/tmp/...`、`/home/user/proj` 属 scoped 删除，可被 filesystem 豁免）、`brace-root-delete`、`root-glob-delete`、`find-delete-root`（`rm` 与 `find` 共用同一系统根列表）；
- `disk-destruction`；
- `execution.fork-bomb`（引号内容视为惰性文本；要求函数名作为管道一侧的命令词形成递归核心，`:(){ :|:& };:`、单侧递归 `f(){ f | g; }; f`、`while :; do $0& done` 均命中；`build(){ npm run build | tee log; }; build` 这类正常函数不误报）；
- `kernel-trigger`、`kernel-core-pattern`（覆盖重定向/`dd of=`/命令位的 `tee`/`cp`/`mv`/`rsync`/`install` 写入（目的地可为带引号、后接注释或重定向）及 `sysctl -w kernel.core_pattern=`；`echo tee /proc/...` 这类惰性文本不误报；读方向的 `cp /proc/sysrq-trigger /tmp/x` 不命中）；
- `network.reverse-shell`、`execution.literal-shell`。

动态审查器的 BYPASS RULE 提示词同样声明这些保持 DENY。

### 静态放行语义

arm 后命令不会被静态层直接 ALLOW：豁免对应检查后以 `bypass.static-allow` ASK 交动态审查器（配合对应 BYPASS RULE 提示词裁决），保持 fail-close。无 bypass 的会话行为与旧版一致——仅有的例外是三类**修复目标**：fork bomb 全形状、`tee`/`cp`/`sysctl` 形式的 kernel 写入、`/lib64` 系统根——旧版这些只被兜底 ASK 挡住，现在被对应 floor 规则正确 DENY。

## 行为总览

```text
shell 请求
  -> 本地静态分类器（逐段、最坏结果合并）
       ALLOW -> opencode 原生 shell
       DENY  -> 拒绝（消息对模型可见）
       ASK 或强制上下文 -> 动态 LLM 审查器（OpenAI-compatible）
                  ALLOW -> opencode 原生 shell
                   DENY  -> 拒绝（HARD：绕过尝试还会中断会话）
```

静态分类（LOOSE/HARD 策略、cd 追踪、脚本指纹、目录清单等）沿用 v1 `-next` 规则集（`src/security/classifier.ts`、`src/security/reviewer.ts`、`src/security/auditor.py`），在此之上新增了 bypass 类别豁免机制与审查器提示词加固（见上方 BypassClassifier 章节）。动态审查器完全直连 OpenAI-compatible 端点，不经 opencode client。

## 配置字段（与 v1 一致）

`options` 支持以下字段（白名单校验，未知字段会抛错）：

| Option | 类型 | 默认 | 说明 |
|---|---|---|---|
| `shell` | string | 环境探测 | 分类器方言提示；v2 无 `config` hook，不能读取 opencode 配置里的 shell，仅由此字段 + `SHELL` 环境变量 + 平台默认决定 |
| `securityEnabled` | boolean | `true` | 整体开关 |
| `strictness` | `"LOOSE" \| "HARD"` | `"LOOSE"` | 静态规则集 + 动态系统提示 |
| `failPolicy` | `"fail_ask" \| "fail_open" \| "fail_close"` | `"fail_open"` | 审查器不可用/失败时的行为。**`fail_ask` 在 v2 归一化为 `fail_close`**（v2 无法交互确认），拒绝消息会注明原因 |
| `dynamicReview.baseURL` | string | — | OpenAI-compatible base URL（自动补 `/chat/completions`）；仅 loopback 允许 http |
| `dynamicReview.model` | string | — | 模型 ID |
| `dynamicReview.apiKey` | string | — | API key（`apiKey`/`apiKeyEnv` 二选一） |
| `dynamicReview.apiKeyEnv` | string | — | 存 key 的环境变量名 |
| `dynamicReview.timeoutMs` | number | `30000` | Python 审查超时（1–120000） |
| `dynamicReview.maxRounds` | number | LOOSE `1`，HARD `2` | 工具轮数（LOOSE 1–3，HARD 1–5） |
| `dynamicReview.allowFullReadAccess` | boolean | `false` | 允许审查器只读工具访问整个文件系统 |
| `dynamicReview.pythonPath` | string | PATH 查找 | Python 解释器 |
| `dynamicReview.auditorPath` | string | 内置 `auditor.py` | 审查脚本路径 |
| `detachedStartIsolation` | boolean | `true` | supervisor 未激活时对 `start`/`Start-Process` 追加句柄隔离 |
| `slowCommands` | boolean | `true` | 拦截安全但必耗时的命令（系统/挂载树的无界扫描、`-f` 流式、超长 `sleep`），除非调用方显式给了 timeout。底层默认参数：`maxDepth=16`（find/rg/fd 的 `-maxdepth` 阈值，超过才拦）、`sleepThresholdSeconds=120`（sleep 阻断阈值，`>=` 即拦）、`allowExplicitTimeout=true`（调用方传入工具参数 timeout 时不拦） |
| `logReviewerTrace` | boolean | `false` | 审计轨迹开关。为真时每次动态审查（判决或错误）及每次动态缓存命中（allow/deny）向 `~/.opencode/reviewer-trace.jsonl` 追加一行 JSONL（含时间戳、命令、endpoint/model、判决/原因/错误）；写入失败静默忽略，不影响审查流程 |
| `supervisorEnabled` | boolean | Windows 下 `true` | 使用原生 shell supervisor |
| `supervisorPath` | string | 包内默认 | supervisor `bash.exe` 路径 |
| `BypassClassifier` | string[] | `[]` | 永久豁免类别列表（`filesystem`/`os`/`secret`/`dynamic`/`web`；未知类别警告并忽略） |
| `bypassLeaseTtlMs` | number | `1200000`（20 分钟） | 临时豁免租约 TTL，活动续期；范围 60000–86400000 |
| `bypassPropagateToSubagents` | boolean | `true` | 子代理会话继承父会话的临时豁免 |
| `configFile` | string | — | JSON 配置文件路径（加载器指令，不是插件字段） |

另支持 `reviewCommand`（仅测试注入用，插件自身从不装配）。

## 与 v1 的行为差异（v2 约束所致）

1. **`fail_ask` 移除**：`failPolicy: "fail_ask"` 被归一化为 `fail_close`——审查器不可用时直接拒绝，而非弹出确认工具。拒绝消息会显式说明 "interactive user confirmation is unavailable in v2"。
2. **拒绝语义**：`execute.before` 是 v2 唯一可失败的 tool hook（失败通道 `Tool.Error`，`execute.after` 为 `never`）。effect 形态下，宿主运行每个 hook 回调返回的 `Effect`；本插件把判定主体包在 `Effect.tryPromise({ try, catch })` 里，所有阻断都经 `catch` 路由成一个 `_tag: "Tool.Error"` 的值（源码核实：session runner 对 `_tag === "Tool.Error"` 的失败执行 `catchTag` → `failTool`，把消息作为**本次工具调用**的失败返回给模型；其他失败会让整个 step 失败）。`catchTag` 按 `_tag` 判别，故假对象无需是真正的 `Tool.Error` 实例。静态/动态/policy 拒绝消息与 v1 格式一致（含 `DO NOT retry...` 后缀）。
3. **目录解析**：v2 ctx 无 `directory/worktree`，按会话从 `ctx.session.get().location.directory` 解析（带 30 分钟 TTL 与 512 条目上限的缓存），失败回退 `process.cwd()`。effect ctx 下 `ctx.session.*` 返回 `Effect`，经插件内部捕获的宿主 runtime 桥接运行，保留宿主服务。
4. **会话清理**：`session.deleted` 事件经 `ctx.event.subscribe()`（`Stream`）以 `Stream.runForEach` + `Effect.forkScoped` 消费；插件 scope 关闭时中断 fiber，事件形状为 `{ type, data: { sessionID } }`。

## Windows 进程 supervisor

与 v1 相同：Windows 下若 `native/windows-bash-supervisor/target/release/bash.exe` 存在，则把真实 shell 放入 Job Object，避免后台子进程持有输出管道导致 opencode 挂起。真实 shell 经 `create.before` 注入 `OPENCODE_REAL_BASH`（取 v2 已解析的 `ev.shell`，无硬编码回退；缺失时 supervisor 以状态 125 退出）。非 Windows 平台自动跳过。

重新构建 supervisor：

```bash
cargo build --release --manifest-path native/windows-bash-supervisor/Cargo.toml
```

## 安全边界

- 这是纵深防御护栏，不是操作系统沙箱。
- 静态分类与 LLM 审查都会出错；`ALLOW` 只是风险降低，不保证安全。
- 动态审查器会收到命令、路径与本地脚本内容；启用第三方端点前请阅读 v1 README 的披露说明。
- opencode 原生权限系统仍在本插件之后运行，是最终关卡。

## 慢命令检测已知限制

- **Windows / PowerShell 不生效**：慢命令检测的 `isExpensiveRoot` 要求路径以 `/` 开头（`C:\…` 直接返回 false），PowerShell 输入整体跳过（避免误报），因此在 Windows 下实际零效果。
- **双层以上包装壳不追踪**：`bash -c "…"` 递归解包上限为 2 层；三层及以上嵌套（如 `bash -c 'bash -c "bash -c \"sleep 999\""'`）不会被检测到。
- **`cd` 链不追踪**：`cd / && find .` 中的 `.` 按工具启动 cwd 解析，不会跟随 `cd /`。
