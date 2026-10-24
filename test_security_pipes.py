#!/usr/bin/env python3
"""
test_security_pipes.py - unit and integration tests for Deliverable 4.

Run:  python3 -m unittest -v test_security_pipes.py
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import pipeline
from security import (MAX_FAILURES, R, W, X, AccessDenied, SecureFS, UserDB,
                      apply_chmod, mode_string)


class TempHome(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="myshell_test_")
        os.makedirs(os.path.join(self.home, "myshell_data"))
        self.db = UserDB(os.path.join(self.home, "myshell_data", "users.json"))
        self.fs = SecureFS(os.path.join(self.home, "myshell_fs"),
                           os.path.join(self.home, "myshell_data", "meta.json"), self.db)
        self.fs.seed()

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def u(self, name):
        return self.db.users[name]


class AuthenticationTests(TempHome):
    def test_passwords_are_salted_hashes(self):
        with open(self.db.path) as f:
            raw = f.read()
        self.assertNotIn("Alice@MSCS630", raw)
        with open(self.db.path) as f:
            recs = json.load(f)
        self.assertEqual(len({r["salt"] for r in recs}), len(recs))   # unique salts

    def test_login_success_and_failure(self):
        self.assertIsNotNone(self.db.authenticate("alice", "Alice@MSCS630")[0])
        self.assertIsNone(self.db.authenticate("alice", "wrong-pass1")[0])

    def test_unknown_user_gets_generic_message(self):
        user, msg = self.db.authenticate("mallory", "whatever1")
        self.assertIsNone(user)
        self.assertEqual(msg, "Login incorrect")

    def test_lockout_after_repeated_failures(self):
        for _ in range(MAX_FAILURES):
            self.db.authenticate("bob", "bad-guess1", now=1000)
        user, msg = self.db.authenticate("bob", "Bob@MSCS630", now=1001)
        self.assertIsNone(user)                   # correct password still refused
        self.assertIn("locked", msg)
        self.assertIsNotNone(self.db.authenticate("bob", "Bob@MSCS630", now=1100)[0])

    def test_password_strength(self):
        with self.assertRaises(ValueError):
            self.db.add_user("carol", "standard", "short")
        with self.assertRaises(ValueError):
            self.db.add_user("carol", "standard", "lettersonly")

    def test_roles(self):
        self.assertTrue(self.u("admin").is_admin)
        self.assertFalse(self.u("alice").is_admin)


class PermissionTests(TempHome):
    def allowed(self, user, path, need):
        try:
            self.fs.check(self.u(user), path, need)
            return True
        except AccessDenied:
            return False

    def test_chmod_parsing(self):
        self.assertEqual(apply_chmod("750", 0), 0o750)
        self.assertEqual(apply_chmod("u+x", 0o644), 0o744)
        self.assertEqual(apply_chmod("g-w,o=r", 0o664), 0o644)
        self.assertEqual(apply_chmod("+x", 0o644), 0o755)
        self.assertEqual(mode_string(0o750, True), "drwxr-x---")
        with self.assertRaises(ValueError):
            apply_chmod("u+z", 0o644)

    def test_owner_group_other(self):
        # /shared/notes.txt  alice:staff rw-rw-r--
        self.assertTrue(self.allowed("alice", "/shared/notes.txt", W))   # owner
        self.assertTrue(self.allowed("bob", "/shared/notes.txt", W))     # group staff
        self.assertFalse(self.allowed("guest", "/shared/notes.txt", W))  # other
        self.assertTrue(self.allowed("guest", "/shared/notes.txt", R))

    def test_standard_user_cannot_modify_system_files(self):
        self.assertTrue(self.allowed("alice", "/system/config", R))
        self.assertFalse(self.allowed("alice", "/system/config", W))
        self.assertFalse(self.allowed("alice", "/system/secret.key", R))
        with self.assertRaises(AccessDenied):
            self.fs.check_parent_write(self.u("alice"), "/system/config", "rm")

    def test_directory_traversal_needs_execute(self):
        self.assertFalse(self.allowed("bob", "/home/alice/todo.txt", R))  # /home/alice 700
        self.assertTrue(self.allowed("alice", "/home/alice/todo.txt", R))

    def test_execute_permission(self):
        # /bin/report.sh admin:staff rwxr-x---
        self.assertTrue(self.allowed("alice", "/bin/report.sh", X))
        self.assertFalse(self.allowed("guest", "/bin/report.sh", X))

    def test_admin_bypasses_rw_but_needs_an_execute_bit(self):
        self.assertTrue(self.allowed("admin", "/home/alice/notes.txt", R))
        self.assertFalse(self.allowed("admin", "/home/admin/hello.sh", X))

    def test_paths_cannot_escape_sandbox(self):
        self.assertEqual(SecureFS.normalize("../../../etc/passwd", "/home/alice"),
                         "/etc/passwd")
        os.symlink("/etc", os.path.join(self.fs.root, "tmp", "escape"))
        with self.assertRaises(AccessDenied):
            self.fs.real("/tmp/escape/passwd")


class PipelineParsingTests(unittest.TestCase):
    def test_stages_and_redirection(self):
        p = pipeline.parse("cat file | grep error | sort > out.txt")
        self.assertEqual(p.stages, [["cat", "file"], ["grep", "error"], ["sort"]])
        self.assertEqual(p.stdout_file, "out.txt")

    def test_quoted_bar_is_an_argument(self):
        self.assertEqual(pipeline.parse('grep "|" f').stages, [["grep", "|", "f"]])

    def test_syntax_errors(self):
        for bad in ("ls |", "| ls", "ls | | wc", "a > ", "ls | sort &"):
            with self.assertRaises(pipeline.PipelineSyntaxError):
                pipeline.parse(bad)

    def test_filters(self):
        text = "b error\na ok\nc ERROR\nb error\n"
        self.assertEqual(pipeline.grep(["-i", "error"], text)[0], "b error\nc ERROR\nb error\n")
        self.assertEqual(pipeline.grep(["-v", "error"], text)[0], "a ok\nc ERROR\n")
        self.assertEqual(pipeline.sort([], text)[0].splitlines()[0], "a ok")
        self.assertEqual(pipeline.uniq(["-c"], "x\nx\ny\n")[0], "      2 x\n      1 y\n")
        self.assertEqual(pipeline.wc(["-l"], text)[0], "4\n")
        self.assertEqual(pipeline.head(["-n", "1"], text)[0], "b error\n")
        self.assertEqual(pipeline.tail(["-n", "1"], text)[0], "b error\n")


class ShellIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cwd = os.getcwd()

    def setUp(self):
        from myshell import Shell
        self.home = tempfile.mkdtemp(prefix="myshell_shell_")
        self.sh = Shell(home=self.home)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.home, ignore_errors=True)

    def as_user(self, name):
        self.sh.start_session(self.sh.users.users[name])

    def run_cmd(self, line):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.sh.execute_line(line)
        return out.getvalue(), err.getvalue()

    def test_two_stage_and_multi_stage_pipes(self):
        self.as_user("alice")
        out, _ = self.run_cmd("ls /shared | grep txt")
        self.assertEqual(out.split(), ["notes.txt", "tasks.txt"])
        out, _ = self.run_cmd("cat /shared/server.log | grep ERROR | sort | head -n 1")
        self.assertIn("disk quota", out)
        out, _ = self.run_cmd("cat /shared/tasks.txt | sort | uniq -c | sort -r | head -n 1")
        self.assertEqual(out.split(), ["2", "pipes"])

    def test_builtin_output_of_earlier_modules_can_be_piped(self):
        self.as_user("alice")
        self.run_cmd("proc demo")
        out, _ = self.run_cmd("sched rr 2 --tick 0 | grep COMPLETE | wc -l")
        self.assertEqual(out.strip(), "5")

    def test_redirection_respects_permissions(self):
        self.as_user("alice")
        _, err = self.run_cmd("echo hacked > /system/config")
        self.assertIn("permission denied", err)
        with open(self.sh.fs.real("/system/config")) as f:
            self.assertNotIn("hacked", f.read())
        self.run_cmd("echo hello > /home/alice/new.txt")
        self.assertEqual(self.sh.fs.get("/home/alice/new.txt").owner, "alice")

    def test_denials_are_audited(self):
        self.as_user("alice")
        self.run_cmd("cat /system/secret.key")
        with open(self.sh.fs.real("/var/log/auth.log")) as f:
            self.assertIn("DENIED user=alice", f.read())

    def test_resource_ownership_across_modules(self):
        self.as_user("alice")
        self.run_cmd("proc add AJOB 3")
        self.run_cmd("mem alloc A 2")
        self.as_user("bob")
        _, err = self.run_cmd("proc rm AJOB")
        self.assertIn("belongs to alice", err)
        _, err = self.run_cmd("mem access A 0")
        self.assertIn("belongs to alice", err)
        _, err = self.run_cmd("mem init 8")
        self.assertIn("only an admin", err)
        self.as_user("admin")
        _, err = self.run_cmd("proc rm AJOB")
        self.assertEqual(err, "")

    def test_standard_users_limited_to_allowed_host_programs(self):
        self.as_user("guest")
        _, err = self.run_cmd("python3 -c 1")
        self.assertIn("permission denied", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
