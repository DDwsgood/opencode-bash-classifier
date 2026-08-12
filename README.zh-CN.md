# opencode-bash-classifier

[English](README.md)

0.4.2 版本——面向 OpenCode 原生 `bash` 工具的“执行边界”命令安全分类器。

## 概述

本插件不触碰 OpenCode 的原生 Bash 工具，而是通过注册 `tool.execute.before` / `tool.execute.after` 钩子在每条命令**运行之前**对其分类。分类是**静态优先**的：快速的本机静态分类器先审查每条命令，只有它无法证明安全的命令（`ASK`）——或在 HARD 模式下由于此前的拒绝/失败而被强制进入审查的命令——才会被发送给可选的动态 OpenAI-compatible 审阅器。正是这种设计让动态请求保持稀少；具体降幅取决于工作负载，因此这里不承诺任何固定百分比。

插件提供**两种用户策略**：`LOOSE` 和 `HARD`。策略标签和 `strictness` 值从不发送给模型：随附的审计器为每种策略选择**独立的 system prompt**，只把该提示连同审查数据一起发送。拦截消息同样从不暴露当前启用的是哪种策略。

它刻意**不**替换内置的 Bash 工具，因此 OpenCode 的 shell 选择、引号处理、进程管理、权限检查、输出捕获和 TUI 渲染均保持不变。命令字符串本身从不为了分类目的而被改写；两个可选的加固特性可能调整工具的*参数*（一个默认超时和分离启动句柄隔离），但绝不会改变命令的含义。

包含 `*** Delete File:` 行的 `apply_patch` 补丁会被静态拦截，并附带一条提示，让代理改用 bash 来删除文件，这样分类器和 OpenCode 的权限层都能对删除操作进行审查。

```text
native Bash request
  -> local static classifier (per-segment, worst-case combine)
       ALLOW -> OpenCode native Bash
       DENY  -> blocked
       ASK or forced context -> dynamic LLM reviewer (tool-enhanced, OpenAI-compatible)
                  ALLOW -> OpenCode native Bash
                   DENY  -> blocked (HARD: bypass attempts also abort the session)
```

## 安装

### 方式一：让 Agent 帮忙安装（推荐）

在 OpenCode 中直接对 agent 说：

> 帮我安装并配置 opencode-bash-classifier

agent 会完成安装、写入 `plugin` 配置，并按需引导你配置可选的动态审阅器。

### 方式二：NPM 包

在 `opencode.json` 的 `plugin` 数组中直接引用 npm 包名——OpenCode 会自动从 npm 安装该包，无需手动全局安装：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "opencode-bash-classifier",
      {
        "strictness": "HARD",
        "failPolicy": "fail_open"
      }
    ]
  ]
}
```

### 方式三：Clone 本地安装

```bash
git clone https://github.com/DDwsgood/opencode-bash-classifier.git
cd opencode-bash-classifier
bun install
bun run build
```

然后在 `opencode.json` 中用插件文件夹的绝对路径引用：

```json
{
  "plugin": [
    [
      "<absolute-path-to-plugin>",
      {
        "strictness": "HARD",
        "failPolicy": "fail_open"
      }
    ]
  ]
}
```

`<absolute-path-to-plugin>` 是本机上插件文件夹的绝对路径。本地安装如需 Windows 进程监督器，在重启前再执行一次 `bun run build:supervisor`（见后文）。

三种方式安装或修改配置后都需要**重启 OpenCode**。完整选项见[配置](#配置)一章；不配置 `dynamicReview` 时动态审阅器不可用，由 [`failPolicy`](#失败策略) 接管——不想用动态审阅器时推荐 `HARD + fail_open`。

## 静态分类

本机分类器会在 `&&`、`||`、`;`、换行、`|` 和 `&` 处把串联命令切分为多个分段，独立审查每个分段，最后按**最差**结果聚合：任何 `DENY` 都会拦截整条命令，任何 `ASK` 都会把整条命令转交动态审查，只有所有分段均为 `ALLOW` 的命令才无需审查即可运行。常见的 `timeout`、WSL、子 shell 和 heredoc 形式会被保守处理；复杂或无法解析的语法一律回退为 `ASK`。

### 目录切换（`cd`）基准跟踪

`cd`/`pushd`/`Set-Location` 分段会改变用于解析后续分段中字面量目标的基准目录，但这个被改变的基准**只在连续的、要求成功执行的 `&&` 链中**向后传播。在 `||`、`;`、换行、管道（`|`）或后台（`&`）连接符之后，下一个分段会重新针对原始工作目录解析——被改变的目录不会跨这些连接符泄漏。例如 `cd /tmp && rm -rf x` 会相对于 `/tmp` 解析 `x`，而 `cd /tmp; rm -rf x` 则会相对于原始工作目录解析 `x`。

### LOOSE（默认）—— 相信善意的输入，但杜绝意外的数据丢失

LOOSE 假定使用者是一位善意的开发者，其目标是防止持久化数据发生意外的、不可逆的丢失。

- **指定名称的临时目录删除**：纯删除命令（`rm`、`Remove-Item` 及其等价形式，无论是通过 bash/PowerShell/WSL/cmd/编码包装器执行的）只有在该命令的**每一个**永久删除目标都能在当前基准目录下解析到一条包含完整的、不区分大小写的、恰好为 `temp` 或 `tmp` 的目录段的路径时，才会被放行。像 `template`、`tmp-marker`、`attempt` 或 `.tmp` 这类在较长名称中出现的子串匹配**不**符合要求。任何目标中的 `..` 段都会使其不合格，混合目标列表也不能被掩盖——一个临时目标并不能为其他目标开脱。
- **用户本地临时目录**：严格位于规范 `%LOCALAPPDATA%\Temp` 目录之下的纯删除/复制/移动/重命名操作（用 `realpath` 解析，并拒绝 `..` 以及 junction/符号链接逃逸）会被放行。
- **备份**：备份名称（`.backup`、`-backup`、`.bak`、`-bak`，可后跟数字）只能通过复制创建；移动/重命名为备份名称会被拒绝。永久删除备份仅对独立、已验证的目标放行，要求同一目录下存在完全同名的原文件、文件系统类型匹配，且备份的创建时间早于两分钟。
- **数据文件**：删除 `.csv`、`.json`、`.yaml`、`.db`、`.sqlite`、`.xlsx`、`.pdf` 及类似的持久化文件不会被静态拒绝——它至少会变成 `ASK`，并基于具体的范围和目录内容进行评估。永久删除关键凭据材料——`.env`、`.pem`、`.key`、`.p12` 及类似的私钥文件——会被静态 `DENY`。
- **回收站**：真正纯粹的、把条目移入操作系统回收站/废纸篓的可恢复操作会被放行，即使目标是项目样式的文件；清空回收站、彻底删除（purge）或直接删除回收站内部条目则会被拒绝。
- **日常工作**：常见的测试运行器、构建、包安装、只读检查命令、git 日常操作（含非强制的 `push`/`pull`/`switch`/`merge`；强制推送仍需审查），以及对可丢弃目标（`node_modules`、`dist`、`build`、`coverage`、缓存）的受限清理都会被静态放行。
- **本地脚本**：工作树内的本地脚本会被读取（每个最多 256 KB，最多 8 个）、计算指纹并扫描其中的删除/杀死/写入原语。一个被完整读取、已计算指纹且不包含任何需要审查的行为的脚本会被静态放行；而包含 `rm`、`pkill`、写入等原语的脚本会把命令送往动态审查。
- **动态 ALLOW 缓存**：成功的动态 `ALLOW` 结果可缓存 30 分钟（上限 512 条），使完全相同的命令不会再次发送；该缓存仅在 LOOSE 模式下生效，当静态上下文无法完全检查时会跳过，动态 `DENY` 从不缓存。

### HARD —— 最严格，无任何放宽

- 所有强制递归删除（`rm -rf`、`Remove-Item -Recurse -Force` 及等价的标志组合）都会被静态 `DENY`。
- HARD 模式下**没有** temp/tmp、本地临时目录或备份例外；删除任何指定名称的临时目录、本地临时目录或备份目标都会被拒绝。
- 持久化数据文件的永久删除**或移入回收站**都会被拒绝；其余真实的回收站移动会被静态放行——移入操作系统回收站是可恢复操作，无需再占用动态审查。
- 清空回收站、彻底删除或直接删除回收站内部条目会被拒绝。
- 不缓存动态 `ALLOW` 结果。
- 发生**任何**拒绝之后，下一条 bash 命令都会被强制进入动态审查，并附带上一次拒绝作为上下文；审阅器必须返回 `{decision, reason, bypassing}`，一旦检测到绕过（`bypassing: true`），命令会被拦截，并会通过 `session.abort` 尽力中止会话。
- 动态审阅器使用其最悲观的提示：没有 temp/备份/回收站/rm-rf 的放宽，且歧义倾向于 `DENY`。

### 复合命令示例

| 命令 | LOOSE | HARD |
|---|---|---|
| `rm -rf ./tmp/x && rm -rf important` | DENY（第二分段是强制递归删除） | DENY |
| `rm -rf ./tmp/x && echo removed` | ALLOW（临时目录分段 + 无害尾部） | DENY（强制递归删除） |

### 被拦截命令的消息

每次**最终**的静态、动态或 `fail_close` 拦截都会**原样**附加如下后缀：

> DO NOT retry the same command or try using alternative method.Skip the step or stop and report the user if it's a essential step of the work

在 HARD 模式下，当拦截原因匹配某个删除类别时，还会在后缀之前插入一条按命令族细分的禁止重试提示（例如“DO NOT retry any rm -rf, split -r/-f, recursive Remove-Item, or equivalent deletion commands.”）。可见消息从不提及当前策略的名称。

`fail_ask` **不是**最终拒绝：它说明批准流程，要求代理用打印出来的 `requestId` 调用 `bash_classifier_confirm`（见下文），并且不带上述后缀。单独的 `apply_patch` 路由错误则会要求代理改用 bash 删除文件。

## 动态 LLM 审阅器

随附的 `auditor.py` 是一个独立的、与提供商无关的审阅器，可对接任何 **OpenAI-compatible**（OpenAI 兼容）端点。它只使用 Python 标准库，并以 `-I -B` 隔离标志运行。它要求端点支持：

- 带 `tools` 数组的 OpenAI-compatible **工具调用**（function calling）；
- **JSON 对象**输出模式（`response_format: {"type": "json_object"}`）。

只有你已验证支持上述两项要求的端点才能正常工作；这里不对任何提供商的既有能力作断言。

> **注意服务条款**：所配置的端点必须允许以 **API/SDK 方式**调用模型。许多订阅制的“coding plan”（编程套餐）只允许在其指定的编程工具内使用模型；把这类额度转用于本插件的第三方调用可能违反提供商条款，**有封号风险**。启用动态审阅器之前，请确认你的提供商明确允许这种用法。

### 轮次预算

`maxRounds` 是允许进行工具调用的轮数：**LOOSE 默认 1（可配 1–3），HARD 默认 2（可配 1–5）**。轮次预算用满后，审计器会再发起一次禁用工具的最终请求以强制得出结论，整个审查过程总工具调用最多 **8 次**。为保证合理的审查速度，建议优先选用无思考模式、低延迟的轻量模型。

### 结果契约

模型必须在每次最终回答中返回恰好一个 JSON 对象：

- LOOSE：`{"decision": "ALLOW"|"DENY", "reason": "..."}`——`ALLOW` 要求 reason 为空字符串。
- HARD：`{"decision": "ALLOW"|"DENY", "reason": "...", "bypassing": boolean}`。

模型载荷中既不包含策略标签，也不包含 `strictness` 值；策略只决定审计器发送哪个 system prompt。

### 配置要求

- **没有默认的提供商、URL、模型或 API 密钥**。`dynamicReview` 配置块必须提供 `baseURL`、`model`，以及 `apiKey` 与 `apiKeyEnv` 中恰好一个。
- `baseURL` 是 OpenAI-compatible 的基础 URL；如果其中尚未包含 `/chat/completions`，插件会追加它。**HTTP 仅允许用于 loopback 主机**（`localhost`、`127.*`、`::1`）；任何远端端点必须使用 **HTTPS**。包含 userinfo 或 fragment 的 URL 会被拒绝。
- **不**跟随重定向。
- `apiKeyEnv` 指定一个用于读取密钥的环境变量名（该名称必须是合法标识符）。插件从不读取 `~/.env`，也从不回退到 `API_KEY` 风格的变量。
- 动态配置缺失或无效会使**审阅器不可用**——插件仍然正常加载和运行；此时由配置的失败策略接管。未配置审阅器不是插件启动失败。
- 配置变更需要重启 OpenCode。

### 审阅器可见的内容（外发数据）

对于 `ASK`（或被强制审查的）命令，以下内容会被发送到所配置的端点：

- 确切的命令，以及规范的 `cwd` / 工作树路径；
- 最多 8 个被检查的本地脚本（每个 ≤ 256 KB，附带脚本字符总计最多 256,000；整个审查包上限为 1 MB）；
- 针对删除目标的有界、非递归目录条目列表（≤ 4 个目录，每个 ≤ 200 条）；
- 命令显式引用的路径（有界，并带截断标志）；
- 来自同一会话中上一次拒绝（HARD）或上一次失败的有界上下文（包含一段简短输出尾部）。

API 密钥本身**仅**在发送给所配置端点的请求的 `Authorization` 头中携带（不跟随重定向）。请记住，命令行、路径和本地源代码可能很敏感；在启用第三方审阅器之前请权衡利弊，敏感工作请优先选择 ZDR（作为注重隐私的托管选择）、自托管端点或禁用审阅器。

### 审计器的读取范围与敏感文件

审阅器恰好有两个本机只读工具——`read_file` 和 `list_directory`。**没有** glob 工具。两个工具都保持只读且受到限制（每次读取 256 KB，每次列出 200 条），把结果视为不可信数据，并拒绝：

- 敏感路径：`.env`、`.env.*` 和 `*.env`（例如 `api-key.env`）；私钥材料（`.pem`、`.key`、`.p12`、`.pfx`、`.ppk`、`.jks`、`.keystore`、`.kdbx`、`.gpg`、`.age`）；npm/pypi 配置（`.npmrc`、`.pypirc`）；`.netrc`；以及 `.ssh`、`.gnupg` 和 `.aws` —— 任何把其中任一项作为目录组件的路径都会被整体禁止，包括全部后代，因此这些目录内的任何内容都不可读、不可列（不仅仅是 `.aws/credentials`）；
- 符号链接、junction、reparse point、设备以及其他非普通文件。

`dynamicReview.allowFullReadAccess`（面向用户的名称是 `ALLOW_FULL_READ_ACCESS`；公开的 JSON 字段采用 camelCase 形式）默认是 `false`，此时工具只能检查：

- 命令的规范工作目录及其之下；
- 系统临时根目录——Windows 上为 `os.tmpdir()`（用户临时目录）加 `%LOCALAPPDATA%\Temp`；Linux 上为 `/tmp` 和 `os.tmpdir()`；
- 命令显式引用的确切路径（显式的文件只授权读取该文件；显式的目录只授权列出该目录）。

把它设为 `true` 后，有界只读工具可以检查整个文件系统中任何位置的普通文件和目录；敏感文件、链接、reparse point、设备和非普通文件在两种模式下都被禁止。访问范围越大，第三方端点可能收到的项目数据就越多——请审慎选择。

检查失败的处理取决于模式：LOOSE 会基于其余可见上下文并偏向善意来判断；HARD 则在已声明但未检查的脚本或目标无法被完整、可靠地检查时拒绝返回 `ALLOW`。

### 失败策略

当审阅器未配置、不可用、超时或返回无效结果时，由 `failPolicy` 决定行为：

| 策略 | 含义 |
|---|---|
| `fail_open`（默认） | 放行命令。 |
| `fail_close` | 拦截命令。 |
| `fail_ask` | 人机协同：命令被拦截，并提供一个 `bash_classifier_confirm` 工具用于请求用户批准。 |

组合建议：

- **不想使用动态审阅器**：推荐 **HARD + `fail_open`**——所有严格的静态 `DENY` 照常生效，审阅器缺席时 `ASK` 命令直接放行，完全不打扰 agent 的工作。
- **不建议使用 `fail_ask`**：审阅器每次不可用或失败都会把存疑命令转成一次人工确认，大幅干扰 agent 活动。只有当你确实需要对每条存疑命令行使人工否决权时才选择它。
- **HARD + `fail_close`** 是最严格的无人工值守配置：审阅器缺席时一切 `ASK` 命令都被拦截。
- **LOOSE + `fail_open`** 是最宽松的无人工值守配置：审阅器故障会在静默中关闭语义层，只留下静态分类器。只有在你接受相应风险时才应使用。

默认值是 `fail_open`。

### 人工批准（`fail_ask`）

由于 `before` 钩子无法自行创建原生权限提示，插件注册了一个自定义工具 `bash_classifier_confirm`，它调用 OpenCode 的 `context.ask`。被拦截的消息会告诉代理使用打印出来的 `requestId` 调用该工具；待处理的请求在 **5 分钟**后过期。在获得批准之前，代理不得重试该命令或改用其他方法；如果用户批准，则只有那条**确切**的命令——命令、工作目录和严格度指纹全部匹配——被放行**一次**；针对不同命令的过期批准会被丢弃。OpenCode 自身的权限配置仍然会在其后生效，并可能通过界面或自动批准设置来决定批准或拒绝。

### 拒绝 / 失败升级（会话级）

- **仅 HARD**：在一个会话中发生**任何**静态、动态或策略拒绝之后，该会话的下一条 bash 命令无论其静态结果如何，都会被强制进入动态审查，并附带上一次拒绝作为上下文。审阅器必须返回 `{decision, reason, bypassing}`；如果它判定新命令是对该拒绝的绕过（`bypassing: true`），则该命令会被拦截，并通过 `session.abort` 中止会话。LOOSE 从不记录拒绝，也不进行绕过检测。
- **仅 HARD**：一条 bash 命令**以非零状态退出**后，该会话中的**下一条** bash 命令会被强制进入动态审查，并附带失败上下文（命令、退出码、有界输出尾部）：静态结果为 `ALLOW` 或 `ASK` 时一律转交审阅器；静态结果为 `DENY` 时保持静态拦截，且不消耗该失败记录。普通的成功命令不会清除待处理的失败记录；只有消耗了该失败的强制审查运行才会清除。LOOSE 从不记录失败，也不进行失败升级。
- 所有状态（`lastRejected`、`lastFailed`、待处理批准、允许缓存）都是会话级的，**30 分钟**后过期，上限 **512** 个会话，并在会话被删除（`session.deleted`）时立即清除。
- 成功的动态 `ALLOW` 结果可缓存 30 分钟（上限 512 条），仅当处于 LOOSE 模式且静态上下文可完全检查时生效；动态 `DENY` 从不缓存。

## 配置

选项位于 OpenCode 的 `plugin` 元组中：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "opencode-bash-classifier",
      {
        "strictness": "LOOSE",
        "failPolicy": "fail_open",
        "dynamicReview": {
          "baseURL": "https://api.example.com/v1",
          "model": "your-model-id",
          "apiKeyEnv": "MY_REVIEW_API_KEY",
          "timeoutMs": 30000,
          "maxRounds": 1,
          "allowFullReadAccess": false,
          "pythonPath": "python",
          "auditorPath": "src/security/auditor.py"
        }
      }
    ]
  ]
}
```

元组的第一个元素是 npm 包名（自动安装）；Clone 本地安装时则改为插件文件夹的绝对路径。`pythonPath` 可以是一个裸的解释器名（在启动时通过 PATH 解析），也可以是相对于包根目录的现有解释器路径；`auditorPath` 会相对于包根目录解析。修改这些选项后需重启 OpenCode。

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `shell` | string | OpenCode 的 shell | 真实 shell 的覆盖项；同时作为分类器的方言提示。 |
| `securityEnabled` | boolean | `true` | 是否完全启用分类器钩子。 |
| `strictness` | `"LOOSE" \| "HARD"` | `"LOOSE"` | 选择静态规则集与动态 system prompt。 |
| `failPolicy` | `"fail_ask" \| "fail_open" \| "fail_close"` | `"fail_open"` | 审阅器不可用或失败时的行为。 |
| `dynamicReview.baseURL` | string | — | OpenAI-compatible 基础 URL（会追加 `/chat/completions`）。HTTP 仅限 loopback 主机；远端必须使用 HTTPS。 |
| `dynamicReview.model` | string | — | 模型 ID。 |
| `dynamicReview.apiKey` | string | — | API 密钥（`apiKey` / `apiKeyEnv` 二者选一）。 |
| `dynamicReview.apiKeyEnv` | string | — | 存放 API 密钥的环境变量名。 |
| `dynamicReview.timeoutMs` | number | `30000` | Python 审阅器超时（1–120000）。 |
| `dynamicReview.maxRounds` | number | LOOSE `1`，HARD `2` | 允许工具调用的轮数（LOOSE 1–3，HARD 1–5）。 |
| `dynamicReview.allowFullReadAccess` | boolean | `false` | 让审计器的有界只读工具检查整个文件系统（`ALLOW_FULL_READ_ACCESS`）。 |
| `dynamicReview.pythonPath` | string | PATH 查找 | Python 解释器；带路径的值会相对于包根目录解析。 |
| `dynamicReview.auditorPath` | string | 随附的 `auditor.py` | 审阅器脚本的路径。 |
| `hardTimeoutMs` | number | `120000` | 应用于没有自带超时的非下载/构建命令的默认超时；`0` 表示禁用。 |
| `detachedStartIsolation` | boolean | `true` | 在监督器未激活时，为 `start`/`Start-Process` 追加句柄隔离。 |
| `supervisorEnabled` | boolean | Windows 上为 `true` | 当原生 shell 监督器的可执行文件存在时启用它。 |
| `supervisorPath` | string | 包默认值 | 指向监督器 `bash.exe` 的路径。 |

插件还支持 `reviewCommand`，但仅用于编程式测试注入；插件本身从不挂接它。

## Windows 进程监督器

在 Windows 上，当某个后代进程继承了 stdout/stderr 管道时，OpenCode 可能在 shell 退出后一直等待。可选的本地监督器在不改变代理命令的前提下修复了这一进程边界：真实的 shell 以挂起状态启动，并在派生子进程之前进入 Windows 作业对象，继承私有的中继管道而不是 OpenCode 的管道句柄，正常的 shell 退出会获得一个有界的输出排空过程，不会等待已分离的后代进程。

真实的 shell **只**来自 OpenCode 所配置的 shell，通过 `shell.env` 钩子以 `OPENCODE_REAL_BASH` 注入。这里刻意**没有**硬编码回退（例如 `C:\msys64\usr\bin\bash.exe`）——监督器绝不静默地针对错误的 shell。如果缺少 `OPENCODE_REAL_BASH`，监督器以状态码 **125** 退出。插件使用的所有运行路径都是配置或包相对的，没有硬编码的机器路径。注入只作用于 `shell.env` 的输出，从不污染全局 `process.env`。

在重启 OpenCode 之前构建一次：

```bash
bun run build:supervisor
```

发布版可执行文件（`bash.exe`，如此命名是为了让 OpenCode 保留 Bash 特有的参数行为）在 Windows 上存在时会被自动启用；设置 `supervisorEnabled: false` 可禁用它，或设置 `supervisorPath` 指向另一个构建产物。

## 安全边界与局限性

- 本插件是**纵深防御的护栏，而非操作系统沙箱**。它无法抵御坚决的恶意负载。
- 构建、测试、安装和包管理命令可以、也确实会执行项目代码和第三方脚本。
- 静态分类和 LLM 审查都会出错；请把任何 `ALLOW` 视为降低风险而非证明安全的决定。
- `fail_open`（当前默认）意味着审阅器故障会把策略静默放宽为仅静态——这是最宽松的无人工值守形态。
- 动态审阅器会收到命令、路径和本地脚本内容；在启用第三方端点之前，请先阅读上文的外发数据一节。
- OpenCode 的原生权限系统仍会在本插件的钩子之后运行，并继续作为最终闸门。

## 开发

```bash
bun run build          # 构建插件到 ./dist
bun run check          # 构建 + 单元测试 + auditor 的 Python 测试
bun run test:auditor   # auditor 只读工具的 Python 测试
bun run test:supervisor  # 原生监督器集成测试（需要已构建的监督器）
```

说明：`test/` 目录列在 `.gitignore` 中；已经被跟踪的测试会保留在克隆中，但新增测试文件必须在提交前显式强制加入。监督器集成测试还额外需要已构建的监督器二进制。
