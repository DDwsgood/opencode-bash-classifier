"""Unit tests for dynamic reviewer schemas, tool access, and round semantics."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src" / "security"))
import auditor  # noqa: E402

WORKTREE = Path(__file__).resolve().parent.parent
SAFE_SCRIPT = "test/fixtures/safe_agent_script.py"


def make_review(**overrides):
    value = {
        "command": "git status",
        "localScripts": [],
        "uninspectedLocalScripts": [],
        "targetDirectories": [],
        "uninspectedTargetDirectories": [],
        "referencedPaths": [],
        "referencedPathsTruncated": False,
        "worktree": str(WORKTREE),
        "cwd": str(WORKTREE),
    }
    value.update(overrides)
    return value


def tool_call(call_id, name, path):
    return {"id": call_id, "function": {"name": name, "arguments": json.dumps({"path": path})}}


@contextmanager
def runtime(policy="LOOSE", full=False, temp_roots=(), rounds=1):
    with mock.patch.multiple(
        auditor,
        POLICY=policy,
        ALLOW_FULL_READ=full,
        TEMP_ROOTS=[Path(item).resolve() for item in temp_roots],
        MAX_ROUNDS=rounds,
    ):
        yield


class ResultSchemaTests(unittest.TestCase):
    def test_relaxed_exact_schema(self):
        self.assertEqual(auditor._validated_result({"decision": "ALLOW", "reason": ""}, "LOOSE"), {"decision": "ALLOW", "reason": ""})
        for invalid in (
            {"decision": "ALLOW", "reason": "", "bypassing": False},
            {"decision": "DENY", "reason": ""},
            {"decision": "DENY", "reason": 1},
        ):
            with self.assertRaises(ValueError):
                auditor._validated_result(invalid, "LOOSE")

    def test_strict_exact_schema(self):
        valid = {"decision": "DENY", "reason": "Deletes durable data", "bypassing": True}
        self.assertEqual(auditor._validated_result(valid, "HARD"), valid)
        for invalid in (
            {"decision": "DENY", "reason": "x"},
            {"decision": "DENY", "reason": "x", "bypassing": "true"},
            {"decision": "DENY", "reason": "x", "bypassing": False, "extra": 1},
        ):
            with self.assertRaises(ValueError):
                auditor._validated_result(invalid, "HARD")

    def test_duplicate_result_key_rejected(self):
        with self.assertRaises(ValueError):
            auditor._parse_strict_json('{"decision":"ALLOW","decision":"DENY","reason":""}')


class InputSchemaTests(unittest.TestCase):
    def read(self, value, policy="LOOSE"):
        raw = value if isinstance(value, str) else json.dumps(value)
        stdin = mock.Mock(buffer=io.BytesIO(raw.encode()))
        with runtime(policy=policy), mock.patch("sys.stdin", stdin):
            return auditor._read_review_input()

    def test_accepts_new_schema_without_policy_or_access(self):
        raw, value = self.read(make_review(referencedPaths=["x"], referencedPathsTruncated=True))
        self.assertNotIn("strictness", value)
        self.assertNotIn("policy", value)
        self.assertNotIn("allowFullReadAccess", value)
        self.assertTrue(value["referencedPathsTruncated"])
        self.assertEqual(json.loads(raw), value)

    def test_relaxed_rejects_previous_rejection_but_accepts_previous_failure(self):
        rejected = make_review(previousRejectedCommand={"command": "rm x", "reason": "deletes", "classifier": "DYNAMIC"})
        with self.assertRaises(ValueError):
            self.read(rejected, "LOOSE")
        _, value = self.read(make_review(previousFailedCommand={"command": "python x", "exitCode": 1}), "LOOSE")
        self.assertEqual(value["previousFailedCommand"]["exitCode"], 1)

    def test_strict_accepts_structured_previous_rejection(self):
        review = make_review(previousRejectedCommand={"command": "rm x", "reason": "deletes", "classifier": "DYNAMIC"})
        _, value = self.read(review, "HARD")
        self.assertEqual(value["previousRejectedCommand"]["command"], "rm x")

    def test_rejects_extra_missing_and_duplicate_fields(self):
        with self.assertRaises(ValueError):
            self.read(make_review(extra=1))
        missing = make_review()
        del missing["referencedPaths"]
        with self.assertRaises(ValueError):
            self.read(missing)
        raw = json.dumps(make_review())
        with self.assertRaises(ValueError):
            self.read('{"command":"dup",' + raw[1:])


class AccessBoundaryTests(unittest.TestCase):
    def test_restricted_allows_any_ordinary_cwd_file_and_directory(self):
        review = make_review()
        with runtime():
            read = auditor._tool_read_file(SAFE_SCRIPT, review, {"bytes": 0})
            listed = auditor._tool_list_directory("test/fixtures", review)
        self.assertIn("local-script-review-ok", read["content"])
        self.assertIn("entries", listed)

    def test_restricted_allows_canonical_temp_root(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            file = Path(temporary) / "probe.txt"
            file.write_text("temp-ok", encoding="utf-8")
            review = make_review()
            with runtime(temp_roots=[temporary]):
                result = auditor._tool_read_file(str(file), review, {"bytes": 0})
            self.assertIn("temp-ok", result["content"])

    def test_explicit_external_file_is_exact_and_parent_not_authorized(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            file = Path(temporary) / "explicit.txt"
            sibling = Path(temporary) / "sibling.txt"
            file.write_text("explicit-ok", encoding="utf-8")
            sibling.write_text("no", encoding="utf-8")
            review = make_review(referencedPaths=[str(file)])
            with runtime():
                allowed = auditor._tool_read_file(str(file), review, {"bytes": 0})
                denied = auditor._tool_read_file(str(sibling), review, {"bytes": 0})
                parent = auditor._tool_list_directory(temporary, review)
            self.assertIn("explicit-ok", allowed["content"])
            self.assertIn("error", denied)
            self.assertIn("error", parent)

    def test_explicit_external_directory_allows_exact_listing_only(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            child = Path(temporary) / "child"
            child.mkdir()
            review = make_review(referencedPaths=[str(child)])
            with runtime():
                self.assertIn("entries", auditor._tool_list_directory(str(child), review))
                self.assertIn("error", auditor._tool_list_directory(temporary, review))

    def test_full_access_allows_external_ordinary_objects(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            file = Path(temporary) / "ordinary.txt"
            file.write_text("full-ok", encoding="utf-8")
            with runtime(full=True):
                self.assertIn("full-ok", auditor._tool_read_file(str(file), make_review(), {"bytes": 0})["content"])
                self.assertIn("entries", auditor._tool_list_directory(temporary, make_review()))

    def test_symlink_or_reparse_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            (real / "x.txt").write_text("x", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as error:
                self.skipTest(str(error))
            review = make_review(cwd=str(root))
            with runtime():
                result = auditor._tool_read_file(str(link / "x.txt"), review, {"bytes": 0})
            self.assertIn("error", result)


class SensitivePathTests(unittest.TestCase):
    def test_env_name_rules_do_not_match_environment(self):
        for name in (".env", ".env.local", "api-key.env"):
            self.assertTrue(auditor._is_sensitive_name(name))
        self.assertFalse(auditor._is_sensitive_name(".environment"))
        for name in (".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "server.pem", "server.key", "x.p12"):
            self.assertTrue(auditor._is_sensitive_name(name))

    def test_sensitive_files_rejected_in_restricted_and_full_access(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            for name in (".env", ".env.local", "api-key.env", ".npmrc", "id_rsa"):
                file = Path(temporary) / name
                file.write_text("secret", encoding="utf-8")
                review = make_review(referencedPaths=[str(file)])
                for full in (False, True):
                    with runtime(full=full):
                        self.assertIn("sensitive", auditor._tool_read_file(str(file), review, {"bytes": 0})["error"])

    def test_aws_credentials_path_rejected(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            aws = Path(temporary) / ".aws"
            aws.mkdir()
            credentials = aws / "credentials"
            credentials.write_text("secret", encoding="utf-8")
            with runtime(full=True):
                self.assertIn("sensitive", auditor._tool_read_file(str(credentials), make_review(), {"bytes": 0})["error"])

    def test_sensitive_directories_rejected_in_restricted_and_full_access(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            root = Path(temporary)
            cases = [
                (".ssh", "config"),
                (".ssh", "known_hosts"),
                (".ssh", "hosts", "known_hosts"),
                (".gnupg", "pubring.gpg"),
                (".aws", "credentials"),
                (".aws", "config"),
            ]
            for parts in cases:
                folder = root.joinpath(*parts[:-1])
                folder.mkdir(parents=True, exist_ok=True)
                (folder / parts[-1]).write_text("secret", encoding="utf-8")
            for directory, full in ((".ssh", False), (".ssh", True), (".gnupg", False), (".gnupg", True), (".aws", False), (".aws", True)):
                target = root / directory
                review = make_review(cwd=str(root))
                with runtime(full=full):
                    listed = auditor._tool_list_directory(str(target), review)
                    read = auditor._tool_read_file(str(target / "config"), review, {"bytes": 0})
                self.assertIn("sensitive", listed["error"], f"list {directory} full={full}")
                self.assertIn("sensitive", read["error"], f"read {directory}/config full={full}")
            nested = root / ".ssh" / "hosts" / "known_hosts"
            with runtime(full=True):
                self.assertIn("sensitive", auditor._tool_read_file(str(nested), make_review(), {"bytes": 0})["error"])

    def test_sensitive_directory_names_are_case_insensitive(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            root = Path(temporary)
            for directory in (".SSH", ".Aws", ".GnuPG"):
                folder = root / directory
                folder.mkdir(exist_ok=True)
                (folder / "config").write_text("secret", encoding="utf-8")
            review = make_review(cwd=str(root))
            for full in (False, True):
                with runtime(full=full):
                    for directory in (".SSH", ".Aws", ".GnuPG"):
                        target = root / directory
                        self.assertIn("sensitive", auditor._tool_list_directory(str(target), review)["error"])
                        self.assertIn("sensitive", auditor._tool_read_file(str(target / "config"), review, {"bytes": 0})["error"])

    def test_similar_directory_names_are_not_sensitive(self):
        with tempfile.TemporaryDirectory(dir=WORKTREE.parent) as temporary:
            root = Path(temporary)
            for directory in (".ssh-notes", "aws-data", ".gnupg-backup"):
                folder = root / directory
                folder.mkdir()
                file = folder / "readme.txt"
                file.write_text("ordinary", encoding="utf-8")
            review = make_review(cwd=str(root))
            for full in (False, True):
                with runtime(full=full):
                    for directory in (".ssh-notes", "aws-data", ".gnupg-backup"):
                        folder = root / directory
                        self.assertIn("entries", auditor._tool_list_directory(str(folder), review))
                        self.assertIn("ordinary", auditor._tool_read_file(str(folder / "readme.txt"), review, {"bytes": 0})["content"])


class PromptTests(unittest.TestCase):
    def test_runtime_prompts_hide_internal_labels(self):
        for prompt in (auditor.LOOSE_PROMPT, auditor.HARD_PROMPT):
            self.assertNotIn("LOOSE", prompt)
            self.assertNotIn("HARD", prompt)
            self.assertNotIn("allowFullReadAccess", prompt)

    def test_relaxed_prompt_has_no_rejection_or_bypass_protocol(self):
        with runtime("LOOSE"):
            prompt = auditor._build_system_prompt(make_review(previousRejectedCommand={"command": "x", "reason": "y", "classifier": "DYNAMIC"}))
        self.assertNotIn("previousRejectedCommand", prompt)
        self.assertNotIn("bypassing", prompt)

    def test_strict_prompt_distinguishes_equivalent_bypass_and_safe_alternative(self):
        review = make_review(previousRejectedCommand={"command": "rm x", "reason": "deletes", "classifier": "DYNAMIC"})
        with runtime("HARD"):
            prompt = auditor._build_system_prompt(review)
        self.assertIn("equivalent", prompt)
        self.assertIn("bypassing MUST be true", prompt)
        self.assertIn('bash -c "rm -rf ./src"', prompt)
        self.assertIn("safe alternative", prompt)
        self.assertIn('"command":"rm x"', prompt)

    def test_access_and_truncation_are_system_only_rules(self):
        with runtime("LOOSE", full=False, temp_roots=[Path(tempfile.gettempdir())]):
            prompt = auditor._build_system_prompt(make_review(referencedPathsTruncated=True))
        self.assertIn("exact objects", prompt)
        self.assertIn("never expands tool access", prompt)

    def test_assembled_system_prompt_has_no_mode_labels(self):
        for policy in ("LOOSE", "HARD"):
            for full in (False, True):
                with runtime(policy, full=full):
                    prompt = auditor._build_system_prompt(make_review())
                for label in ("LOOSE", "HARD", "strictness", "allowFullReadAccess"):
                    self.assertNotIn(label, prompt)
        with runtime("LOOSE"):
            loose_prompt = auditor._build_system_prompt(make_review())
        with runtime("HARD"):
            hard_prompt = auditor._build_system_prompt(make_review())
        self.assertNotIn("bypassing", loose_prompt)
        self.assertIn("bypassing", hard_prompt)
        self.assertEqual(set(auditor._validated_result({"decision": "ALLOW", "reason": ""}, "LOOSE")), {"decision", "reason"})
        self.assertEqual(set(auditor._validated_result({"decision": "ALLOW", "reason": "", "bypassing": False}, "HARD")), {"decision", "reason", "bypassing"})


class ToolLoopTests(unittest.TestCase):
    def result(self, policy):
        return {"decision": "ALLOW", "reason": "", **({"bypassing": False} if policy == "HARD" else {})}

    def test_direct_conclusion_is_one_api_request(self):
        with runtime("LOOSE", rounds=1), mock.patch.object(auditor, "_post_chat", return_value={"content": json.dumps(self.result("LOOSE"))}) as post:
            result = auditor._run_review(json.dumps(make_review()), make_review(), "key")
        self.assertEqual(result, self.result("LOOSE"))
        post.assert_called_once()

    def test_one_tool_round_gets_extra_toolless_final_request(self):
        responses = [
            {"tool_calls": [tool_call("c1", "read_file", SAFE_SCRIPT)]},
            {"content": json.dumps(self.result("LOOSE"))},
        ]
        review = make_review(uninspectedLocalScripts=[SAFE_SCRIPT])
        with runtime("LOOSE", rounds=1), mock.patch.object(auditor, "_post_chat", side_effect=responses) as post:
            auditor._run_review(json.dumps(review), review, "key")
        self.assertEqual(post.call_count, 2)
        self.assertIn("tools", post.call_args_list[0].args[0])
        self.assertNotIn("tools", post.call_args_list[1].args[0])

    def test_five_tool_rounds_get_sixth_final_request(self):
        def post(payload, _key):
            if "tools" in payload:
                return {"tool_calls": [tool_call(f"c{len(payload['messages'])}", "read_file", SAFE_SCRIPT)]}
            return {"content": json.dumps(self.result("HARD"))}
        review = make_review(uninspectedLocalScripts=[SAFE_SCRIPT])
        with runtime("HARD", rounds=5), mock.patch.object(auditor, "_post_chat", side_effect=post) as mocked:
            auditor._run_review(json.dumps(review), review, "key")
        self.assertEqual(mocked.call_count, 6)

    def test_strict_allow_requires_complete_inspection_but_relaxed_does_not(self):
        review = make_review(uninspectedLocalScripts=[SAFE_SCRIPT])
        with runtime("HARD", rounds=1), mock.patch.object(auditor, "_post_chat", return_value={"content": json.dumps(self.result("HARD"))}):
            with self.assertRaisesRegex(ValueError, "mandatory inspection"):
                auditor._run_review(json.dumps(review), review, "key")
        with runtime("LOOSE", rounds=1), mock.patch.object(auditor, "_post_chat", return_value={"content": json.dumps(self.result("LOOSE"))}):
            self.assertEqual(auditor._run_review(json.dumps(review), review, "key"), self.result("LOOSE"))

    def test_failed_or_truncated_required_tool_cannot_enable_strict_allow(self):
        review = make_review(uninspectedLocalScripts=[SAFE_SCRIPT])
        responses = [{"tool_calls": [tool_call("c1", "read_file", SAFE_SCRIPT)]}, {"content": json.dumps(self.result("HARD"))}]
        with runtime("HARD", rounds=1), mock.patch.object(auditor, "_post_chat", side_effect=responses), mock.patch.object(auditor, "_dispatch_tool", return_value={"path": SAFE_SCRIPT, "content": "partial", "truncated": True}):
            with self.assertRaisesRegex(ValueError, "mandatory inspection"):
                auditor._run_review(json.dumps(review), review, "key")

    def test_tool_call_cap_remains_eight(self):
        def post(payload, _key):
            if "tools" not in payload:
                return {"content": json.dumps(self.result("HARD"))}
            return {"tool_calls": [tool_call(f"a{len(payload['messages'])}", "read_file", SAFE_SCRIPT), tool_call(f"b{len(payload['messages'])}", "read_file", SAFE_SCRIPT), tool_call(f"c{len(payload['messages'])}", "read_file", SAFE_SCRIPT)]}
        review = make_review(uninspectedLocalScripts=[SAFE_SCRIPT])
        with runtime("HARD", rounds=5), mock.patch.object(auditor, "_post_chat", side_effect=post) as mocked:
            auditor._run_review(json.dumps(review), review, "key")
        self.assertEqual(mocked.call_count, 4)


class ConfigTests(unittest.TestCase):
    def load(self, policy, rounds=None):
        env = {
            auditor.ENV_ENDPOINT: "https://example.com/v1/chat/completions",
            auditor.ENV_MODEL: "m",
            auditor.ENV_API_KEY: "k",
            auditor.ENV_POLICY: policy,
            auditor.ENV_FULL_READ: "0",
            auditor.ENV_TEMP_ROOTS: "[]",
        }
        if rounds is not None:
            env[auditor.ENV_MAX_ROUNDS] = str(rounds)
        with mock.patch.dict(os.environ, env, clear=True):
            return auditor._load_config()

    def test_defaults_are_one_and_two(self):
        self.assertEqual(self.load("LOOSE")[3], 1)
        self.assertEqual(self.load("HARD")[3], 2)

    def test_policy_round_limits_are_three_and_five(self):
        self.assertEqual(self.load("LOOSE", 3)[3], 3)
        self.assertEqual(self.load("HARD", 5)[3], 5)
        with self.assertRaises(ValueError):
            self.load("LOOSE", 4)
        with self.assertRaises(ValueError):
            self.load("HARD", 6)


if __name__ == "__main__":
    unittest.main()
