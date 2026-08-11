import { describe, expect, test } from "bun:test"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { resolvePluginConfig, type BashClassifierOptions } from "../src/config"

const ENV_NAME = "BASH_CLASSIFIER_TEST_KEY"
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

function withEnv(name: string, value: string | undefined, fn: () => void) {
  const saved = process.env[name]
  if (value === undefined) delete process.env[name]
  else process.env[name] = value
  try {
    fn()
  } finally {
    if (saved === undefined) delete process.env[name]
    else process.env[name] = saved
  }
}

function availableConfig(overrides: BashClassifierOptions = {}) {
  return resolvePluginConfig({
    dynamicReview: {
      baseURL: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      apiKey: "sk-test-key",
    },
    ...overrides,
  })
}

describe("resolvePluginConfig defaults", () => {
  test("applies default values when no options are provided", () => {
    const config = resolvePluginConfig()
    expect(config.securityEnabled).toBe(true)
    expect(config.detachedStartIsolation).toBe(true)
    expect(config.hardTimeoutMs).toBe(120_000)
    expect(config.strictness).toBe("LOOSE")
    expect(config.failPolicy).toBe("fail_ask")
    expect(config.shell).toBeUndefined()
    expect(config.reviewCommand).toBeUndefined()
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.timeoutMs).toBe(30_000)
    expect(config.dynamicReview.maxRounds).toBe(1)
    expect(config.dynamicReview.allowFullReadAccess).toBe(false)
    expect(config.dynamicReview.reason).toBeTruthy()
    expect(config.dynamicReview.reason).not.toContain("sk-")
  })

  test("resolves an explicit supervisorPath relative to cwd", () => {
    const config = resolvePluginConfig({ supervisorPath: "./supervisor.exe" })
    expect(config.supervisorPath).toBe(path.resolve("./supervisor.exe"))
  })
})

describe("resolvePluginConfig top-level validation", () => {
  test("passes through valid top-level fields", () => {
    const fn = async () => ({ decision: "ALLOW" as const, reason: "", bypassing: false })
    const config = resolvePluginConfig({
      shell: "/bin/bash",
      securityEnabled: false,
      hardTimeoutMs: 0,
      detachedStartIsolation: false,
      supervisorEnabled: false,
      supervisorPath: "/custom/bash.exe",
      strictness: "HARD",
      failPolicy: "fail_close",
      reviewCommand: fn as never,
    })
    expect(config.shell).toBe("/bin/bash")
    expect(config.securityEnabled).toBe(false)
    expect(config.hardTimeoutMs).toBe(0)
    expect(config.detachedStartIsolation).toBe(false)
    expect(config.supervisorEnabled).toBe(false)
    expect(config.supervisorPath).toBe(path.resolve("/custom/bash.exe"))
    expect(config.strictness).toBe("HARD")
    expect(config.failPolicy).toBe("fail_close")
    expect(config.reviewCommand).not.toBe(fn)
  })

  test("routes trusted policy and read access into review command options", async () => {
    let received: Record<string, unknown> | undefined
    const config = availableConfig({
      strictness: "HARD",
      dynamicReview: { baseURL: "https://example.com", model: "m", apiKey: "k", allowFullReadAccess: true },
      reviewCommand: async (_request, options) => {
        received = options as unknown as Record<string, unknown>
        return { decision: "ALLOW", reason: "", bypassing: false }
      },
    })
    await config.reviewCommand!({} as never, {} as never)
    expect(received?.policy).toBe("HARD")
    expect(received?.allowFullReadAccess).toBe(true)
  })

  test("throws on unknown top-level fields", () => {
    expect(() => resolvePluginConfig({ unknownField: 1 } as BashClassifierOptions)).toThrow(
      "unknown option: unknownField",
    )
  })

  test("throws on invalid non-dynamic top-level values", () => {
    expect(() => resolvePluginConfig({ strictness: "STRICT" } as BashClassifierOptions)).toThrow(
      /strictness/,
    )
    expect(() => resolvePluginConfig({ failPolicy: "fail_loud" } as BashClassifierOptions)).toThrow(
      /failPolicy/,
    )
    expect(() => resolvePluginConfig({ securityEnabled: "yes" } as BashClassifierOptions)).toThrow(
      /securityEnabled/,
    )
    expect(() =>
      resolvePluginConfig({ detachedStartIsolation: "off" } as BashClassifierOptions),
    ).toThrow(/detachedStartIsolation/)
    expect(() => resolvePluginConfig({ supervisorEnabled: 1 } as BashClassifierOptions)).toThrow(
      /supervisorEnabled/,
    )
    expect(() => resolvePluginConfig({ supervisorPath: 42 } as BashClassifierOptions)).toThrow(
      /supervisorPath/,
    )
    expect(() => resolvePluginConfig({ shell: 42 } as BashClassifierOptions)).toThrow(/shell/)
    expect(() =>
      resolvePluginConfig({ hardTimeoutMs: -1 } as BashClassifierOptions),
    ).toThrow(/hardTimeoutMs/)
    expect(() =>
      resolvePluginConfig({ hardTimeoutMs: Number.NaN } as BashClassifierOptions),
    ).toThrow(/hardTimeoutMs/)
    expect(() =>
      resolvePluginConfig({ reviewCommand: "not-a-fn" } as BashClassifierOptions),
    ).toThrow(/reviewCommand/)
  })
})

describe("resolvePluginConfig dynamic review URL handling", () => {
  test("appends /chat/completions to a bare OpenAI baseURL", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(true)
    expect(config.dynamicReview.endpoint).toBe(
      "https://api.openai.com/v1/chat/completions",
    )
  })

  test("strips a trailing slash before appending", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1/",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.endpoint).toBe(
      "https://api.openai.com/v1/chat/completions",
    )
  })

  test("preserves a baseURL that already ends with /chat/completions", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1/chat/completions",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.endpoint).toBe(
      "https://api.openai.com/v1/chat/completions",
    )
  })

  test("strips a trailing slash from an existing /chat/completions baseURL", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1/chat/completions/",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.endpoint).toBe(
      "https://api.openai.com/v1/chat/completions",
    )
  })

  test("accepts an http baseURL with a port", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "http://localhost:8080",
        model: "local-model",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(true)
    expect(config.dynamicReview.endpoint).toBe("http://localhost:8080/chat/completions")
  })

  test("rejects remote HTTP and accepts loopback IP HTTP", () => {
    const remote = availableConfig({ dynamicReview: { baseURL: "http://example.com/v1", model: "m", apiKey: "k" } })
    expect(remote.dynamicReview.available).toBe(false)
    expect(remote.dynamicReview.reason).toMatch(/loopback/)
    const local = availableConfig({ dynamicReview: { baseURL: "http://127.0.0.1:8080/v1", model: "m", apiKey: "k" } })
    expect(local.dynamicReview.available).toBe(true)
  })

  test("preserves URL query parameters", () => {
    const config = availableConfig({ dynamicReview: { baseURL: "https://example.com/v1?api-version=7", model: "m", apiKey: "k" } })
    expect(config.dynamicReview.endpoint).toBe("https://example.com/v1/chat/completions?api-version=7")
  })

  test("marks unavailable for a non-http(s) scheme", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "ftp://example.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.endpoint).toBeUndefined()
    expect(config.dynamicReview.reason).toMatch(/http or https/)
  })

  test("marks unavailable for a URL containing userinfo", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://user:pass@example.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/userinfo/)
    expect(config.dynamicReview.reason).not.toContain("pass")
  })

  test("marks unavailable for a URL containing a fragment", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1#section",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/fragment/)
  })

  test("marks unavailable for an unparseable baseURL", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "not a url",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/valid URL/)
  })

  test("marks unavailable when baseURL is missing", () => {
    const config = availableConfig({
      dynamicReview: { model: "gpt-4o-mini", apiKey: "sk-test-key" },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/baseURL/)
  })
})

describe("resolvePluginConfig api key resolution", () => {
  test("resolves the api key from apiKeyEnv", () => {
    withEnv(ENV_NAME, "env-secret-key", () => {
      const config = availableConfig({
        dynamicReview: {
          baseURL: "https://api.openai.com/v1",
          model: "gpt-4o-mini",
          apiKeyEnv: ENV_NAME,
        },
      })
      expect(config.dynamicReview.available).toBe(true)
      expect(config.dynamicReview.apiKey).toBe("env-secret-key")
    })
  })

  test("uses a directly-configured apiKey", () => {
    const config = availableConfig()
    expect(config.dynamicReview.available).toBe(true)
    expect(config.dynamicReview.apiKey).toBe("sk-test-key")
  })

  test("marks unavailable when apiKeyEnv does not resolve", () => {
    withEnv(ENV_NAME, undefined, () => {
      const config = availableConfig({
        dynamicReview: {
          baseURL: "https://api.openai.com/v1",
          model: "gpt-4o-mini",
          apiKeyEnv: ENV_NAME,
        },
      })
      expect(config.dynamicReview.available).toBe(false)
      expect(config.dynamicReview.apiKey).toBeUndefined()
      expect(config.dynamicReview.reason).toContain(ENV_NAME)
      expect(config.dynamicReview.reason).not.toContain("env-secret-key")
    })
  })

  test("marks unavailable when both apiKey and apiKeyEnv are provided", () => {
    withEnv(ENV_NAME, "env-secret-key", () => {
      const config = availableConfig({
        dynamicReview: {
          baseURL: "https://api.openai.com/v1",
          model: "gpt-4o-mini",
          apiKey: "sk-direct",
          apiKeyEnv: ENV_NAME,
        },
      })
      expect(config.dynamicReview.available).toBe(false)
      expect(config.dynamicReview.reason).toMatch(/exactly one/)
    })
  })

  test("marks unavailable when neither apiKey nor apiKeyEnv is provided", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/apiKey or apiKeyEnv/)
  })

  test("marks unavailable when the key is empty", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "   ",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/empty/)
  })

  test("marks unavailable when the key contains CR/LF/NUL", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test\nleaked",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/forbidden/)
    expect(config.dynamicReview.reason).not.toContain("leaked")
  })

  test("rejects an invalid apiKeyEnv name format as unavailable", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKeyEnv: "bad-name",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/environment variable name/)
  })

  test("does not read a generic API_KEY env implicitly", () => {
    withEnv("API_KEY", "generic-key", () => {
      withEnv(ENV_NAME, undefined, () => {
        const config = availableConfig({
          dynamicReview: {
            baseURL: "https://api.openai.com/v1",
            model: "gpt-4o-mini",
          },
        })
        expect(config.dynamicReview.available).toBe(false)
        expect(config.dynamicReview.apiKey).toBeUndefined()
      })
    })
  })
})

describe("resolvePluginConfig maxRounds and timeout", () => {
  test("uses policy defaults and accepts each policy's inclusive upper bound", () => {
    const low = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        maxRounds: 1,
      },
    })
    expect(low.dynamicReview.available).toBe(true)
    expect(low.dynamicReview.maxRounds).toBe(1)

    const looseHigh = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        maxRounds: 3,
      },
    })
    expect(looseHigh.dynamicReview.available).toBe(true)
    expect(looseHigh.dynamicReview.maxRounds).toBe(3)
    const hard = availableConfig({ strictness: "HARD", dynamicReview: { baseURL: "https://api.openai.com/v1", model: "m", apiKey: "k", maxRounds: 5 } })
    expect(hard.dynamicReview.available).toBe(true)
    expect(hard.dynamicReview.maxRounds).toBe(5)
    expect(availableConfig({ strictness: "HARD" }).dynamicReview.maxRounds).toBe(2)
  })

  test("marks unavailable for maxRounds below 1 or above 5", () => {
    const low = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        maxRounds: 0,
      },
    })
    expect(low.dynamicReview.available).toBe(false)
    expect(low.dynamicReview.maxRounds).toBe(1)
    expect(low.dynamicReview.reason).toMatch(/maxRounds/)

    const high = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        maxRounds: 4,
      },
    })
    expect(high.dynamicReview.available).toBe(false)
    expect(high.dynamicReview.maxRounds).toBe(1)
    expect(high.dynamicReview.reason).toMatch(/maxRounds/)
  })

  test("marks unavailable for a non-integer maxRounds", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        maxRounds: 1.5,
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/maxRounds/)
  })

  test("accepts timeoutMs at the inclusive bounds and defaults to 30000", () => {
    const def = availableConfig()
    expect(def.dynamicReview.timeoutMs).toBe(30_000)

    const min = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        timeoutMs: 1,
      },
    })
    expect(min.dynamicReview.available).toBe(true)
    expect(min.dynamicReview.timeoutMs).toBe(1)

    const max = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        timeoutMs: 120_000,
      },
    })
    expect(max.dynamicReview.available).toBe(true)
    expect(max.dynamicReview.timeoutMs).toBe(120_000)
  })

  test("marks unavailable for timeoutMs out of range", () => {
    const low = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        timeoutMs: 0,
      },
    })
    expect(low.dynamicReview.available).toBe(false)
    expect(low.dynamicReview.timeoutMs).toBe(30_000)
    expect(low.dynamicReview.reason).toMatch(/timeoutMs/)
  })
})

describe("resolvePluginConfig dynamicReview object shape", () => {
  test("defaults full read access off and validates its type without throwing", () => {
    expect(availableConfig().dynamicReview.allowFullReadAccess).toBe(false)
    expect(availableConfig({ dynamicReview: { baseURL: "https://example.com", model: "m", apiKey: "k", allowFullReadAccess: true } }).dynamicReview.allowFullReadAccess).toBe(true)
    const invalid = availableConfig({ dynamicReview: { baseURL: "https://example.com", model: "m", apiKey: "k", allowFullReadAccess: "yes" as never } })
    expect(invalid.dynamicReview.available).toBe(false)
  })
  test("marks unavailable for a non-object dynamicReview instead of throwing", () => {
    for (const invalid of ["not-an-object", 42, null, ["array"]] as unknown[]) {
      const config = resolvePluginConfig({ dynamicReview: invalid as BashClassifierOptions["dynamicReview"] })
      expect(config.dynamicReview.available).toBe(false)
      expect(config.dynamicReview.reason).toMatch(/must be an object/)
      expect(config.dynamicReview.reason).not.toContain("sk-")
    }
  })

  test("marks unavailable on an unknown dynamicReview sub-field instead of throwing", () => {
    const config = resolvePluginConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        bogusField: 1,
      } as BashClassifierOptions["dynamicReview"],
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/unknown field: bogusField/)
    expect(config.dynamicReview.reason).not.toContain("sk-")
  })

  test("marks unavailable when model exceeds the length limit", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "x".repeat(257),
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/length/)
  })

  test("marks unavailable when baseURL contains control characters", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com\n/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.endpoint).toBeUndefined()
    expect(config.dynamicReview.reason).toMatch(/control characters/)
  })

  test("carries a bare pythonPath command name without PATH probing", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        pythonPath: "python3",
      },
    })
    expect(config.dynamicReview.available).toBe(true)
    expect(config.dynamicReview.pythonPath).toBe("python3")
  })
})

describe("resolvePluginConfig dynamicReview path resolution", () => {
  const BUNDLED_AUDITOR_REL = "src/security/auditor.py"
  const BUNDLED_AUDITOR_ABS = path.resolve(PACKAGE_ROOT, BUNDLED_AUDITOR_REL)

  test("resolves a relative auditorPath against the package root to a regular file", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        auditorPath: BUNDLED_AUDITOR_REL,
      },
    })
    expect(config.dynamicReview.available).toBe(true)
    expect(config.dynamicReview.auditorPath).toBe(BUNDLED_AUDITOR_ABS)
  })

  test("resolves a relative pythonPath with a directory against the package root", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        pythonPath: process.execPath,
      },
    })
    expect(config.dynamicReview.available).toBe(true)
    expect(config.dynamicReview.pythonPath).toBe(path.resolve(process.execPath))
  })

  test("marks unavailable when an explicit auditorPath does not exist", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        auditorPath: "does/not/exist.py",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.auditorPath).toBeUndefined()
    expect(config.dynamicReview.reason).toMatch(/auditorPath/)
    expect(config.dynamicReview.reason).not.toContain("sk-")
  })

  test("marks unavailable when an explicit auditorPath is a directory", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        auditorPath: "src",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/auditorPath/)
  })

  test("marks unavailable when an explicit pythonPath with a directory does not exist", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        pythonPath: "./no/such/python",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.pythonPath).toBeUndefined()
    expect(config.dynamicReview.reason).toMatch(/pythonPath/)
  })

  test("marks unavailable when an explicit pythonPath with a directory is a directory", () => {
    const config = availableConfig({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        pythonPath: "src/security",
      },
    })
    expect(config.dynamicReview.available).toBe(false)
    expect(config.dynamicReview.reason).toMatch(/pythonPath/)
  })
})
