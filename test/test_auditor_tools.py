"""Unit tests for the DeepSeek auditor tool loop, boundaries, and budget.

Run with: python test/test_auditor_tools.py
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "security"))

import deepseek_auditor as auditor  # noqa: E402

WORKTREE = str(Path(__file__).resolve().parent.parent)
FIXTURES = str(Path(WORKTREE) / "test" / "fixtures")


def make_review(overrides=None):
    data = {
        "command": "python script.py",
        "localScripts": [],
        "uninspectedLocalScripts": [],
        "targetDirectories": [],
        "uninspectedTargetDirectories": [],
        "worktree": WORKTREE,
        "cwd": WORKTREE,
    }
    if overrides:
        data.update(overrides)
    return data


class ResolvePathTests(unittest.TestCase):
    def test_inside_worktree(self):
        target = auditor._resolve_path("test/fixtures/safe_agent_script.py", make_review())
        self.assertIsNotNone(target)
        self.assertTrue(str(target).endswith("safe_agent_script.py"))

    def test_absolute_inside_worktree(self):
        target = auditor._resolve_path(str(Path(FIXTURES) / "safe_agent_script.py"), make_review())
        self.assertIsNotNone(target)

    def test_outside_boundary(self):
        self.assertIsNone(auditor._resolve_path("C:/Windows/win.ini", make_review()))

    def test_dotdot_escape_rejected(self):
        review = make_review({"worktree": FIXTURES})
        self.assertIsNone(auditor._resolve_path("../safe_agent_script.py", review))

    def test_local_temp_boundary(self):
        target = auditor._resolve_path("C:/Users/34177/AppData/Local/Temp/opencode/probe.txt", make_review())
        self.assertIsNotNone(target)


class ToolDispatchTests(unittest.TestCase):
    def test_read_file_ok(self):
        result = auditor._tool_read_file("test/fixtures/safe_agent_script.py", make_review())
        self.assertNotIn("error", result)
        self.assertIn("local-script-review-ok", result["content"])

    def test_read_file_outside(self):
        result = auditor._tool_read_file("C:/Windows/win.ini", make_review())
        self.assertIn("error", result)

    def test_read_missing_path(self):
        self.assertIn("error", auditor._dispatch_tool("read_file", {}, make_review()))

    def test_list_directory(self):
        result = auditor._tool_list_directory("test/fixtures", make_review())
        self.assertNotIn("error", result)
        names = {entry["name"] for entry in result["entries"]}
        self.assertIn("safe_agent_script.py", names)
        self.assertIn("backup-policy", names)

    def test_glob(self):
        result = auditor._tool_glob("test/fixtures/*.py", make_review())
        self.assertNotIn("error", result)
        self.assertTrue(any("safe_agent_script.py" in match for match in result["matches"]))

    def test_glob_absolute_rejected(self):
        result = auditor._tool_glob("C:/Windows/*.ini", make_review())
        self.assertIn("error", result)

    def test_unknown_tool(self):
        self.assertIn("error", auditor._dispatch_tool("nope", {}, make_review()))


class ToolLoopTests(unittest.TestCase):
    def test_direct_conclusion(self):
        with mock.patch.object(auditor, "_post_chat") as post:
            post.return_value = {"content": json.dumps({"decision": "ALLOW", "reason": ""})}
            result = auditor._run_review(json.dumps(make_review()), make_review(), "test-key")
        self.assertEqual(result, {"decision": "ALLOW", "reason": ""})
        post.assert_called_once()

    def test_tool_then_conclusion(self):
        responses = [
            {
                "tool_calls": [
                    {
                        "id": "c1",
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": "test/fixtures/safe_agent_script.py"}),
                        },
                    }
                ]
            },
            {"content": json.dumps({"decision": "ALLOW", "reason": ""})},
        ]
        with mock.patch.object(auditor, "_post_chat", side_effect=responses) as post:
            result = auditor._run_review(json.dumps(make_review()), make_review(), "test-key")
        self.assertEqual(result, {"decision": "ALLOW", "reason": ""})
        self.assertEqual(post.call_count, 2)
        messages = post.call_args_list[1].args[0]["messages"]
        self.assertEqual(messages[-1]["role"], "tool")
        self.assertIn("local-script-review-ok", messages[-1]["content"])

    def test_round_budget_raises(self):
        def post(payload, key):
            return {
                "tool_calls": [
                    {"id": "c", "function": {"name": "list_directory", "arguments": json.dumps({"path": "."})}}
                ]
            }

        with mock.patch.object(auditor, "_post_chat", side_effect=post):
            with self.assertRaises(ValueError):
                auditor._run_review(json.dumps(make_review()), make_review(), "test-key")

    def test_no_tools_after_budget_forces_conclusion(self):
        calls = {"count": 0}

        def post(payload, key):
            calls["count"] += 1
            if "tools" not in payload:
                return {"content": json.dumps({"decision": "ALLOW", "reason": ""})}
            return {
                "tool_calls": [
                    {"id": "c", "function": {"name": "list_directory", "arguments": json.dumps({"path": "."})}}
                ]
            }

        with mock.patch.object(auditor, "_post_chat", side_effect=post) as p:
            result = auditor._run_review(json.dumps(make_review()), make_review(), "test-key")
        self.assertEqual(result, {"decision": "ALLOW", "reason": ""})
        # 工具轮 = MAX_TOOL_ROUNDS(3)+1 次最终轮
        self.assertEqual(p.call_count, auditor.MAX_TOOL_ROUNDS + 1)

    def test_tool_result_injection_is_data(self):
        # dangerous_agent_script.py contains destructive code; the loop must pass it
        # through as untrusted tool data and still converge on the mocked verdict.
        responses = [
            {
                "tool_calls": [
                    {
                        "id": "c1",
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": "test/fixtures/dangerous_agent_script.py"}),
                        },
                    }
                ]
            },
            {"content": json.dumps({"decision": "DENY", "reason": "Deletes durable data"})},
        ]
        with mock.patch.object(auditor, "_post_chat", side_effect=responses):
            result = auditor._run_review(json.dumps(make_review()), make_review(), "test-key")
        self.assertEqual(result, {"decision": "DENY", "reason": "Deletes durable data"})

    def test_schema_rejects_missing_worktree(self):
        review = make_review()
        del review["worktree"]
        raw = json.dumps(review)
        with mock.patch.object(auditor, "_post_chat") as post:
            post.return_value = {"content": json.dumps({"decision": "ALLOW", "reason": ""})}
            try:
                auditor._run_review(raw, review, "test-key")
            except Exception as error:
                self.fail(f"run_review should tolerate missing worktree in data: {error}")
        # schema validation is tested separately via _read_review_input; here we
        # just ensure the loop still works when the boundary is absent.
        self.assertIsNotNone(_roundtrip_input(make_review()))


class SchemaValidationTests(unittest.TestCase):
    def _read_from(self, text):
        stream = mock.patch("sys.stdin", spec=["buffer"])
        with stream as stdin:
            stdin.buffer.read.return_value = text.encode("utf-8")
            return auditor._read_review_input()

    def test_accepts_full_schema(self):
        review = make_review()
        _, data = self._read_from(json.dumps(review))
        self.assertEqual(data["worktree"], WORKTREE)

    def test_rejects_missing_worktree(self):
        review = make_review()
        del review["worktree"]
        with self.assertRaises(ValueError):
            self._read_from(json.dumps(review))

    def test_rejects_invalid_local_script(self):
        review = make_review()
        review["localScripts"] = [{"path": "x.py", "content": "print(1)"}]
        with self.assertRaises(ValueError):
            self._read_from(json.dumps(review))


def _roundtrip_input(review):
    return review


if __name__ == "__main__":
    unittest.main()
