#!/usr/bin/env python3
"""
security.py - Advanced Shell Simulation, Deliverable 4: Security

Authentication
  * Users have a username, a role (admin or standard), and groups.
  * Passwords are never stored: each user has a random 16-byte salt and a
    PBKDF2-HMAC-SHA256 hash (200,000 iterations). Verification uses a
    constant-time comparison (hmac.compare_digest).
  * After MAX_FAILURES consecutive failed logins an account is locked for
    LOCKOUT_SECONDS. Unknown users and wrong passwords get the same message
    so an attacker cannot learn which usernames exist.

Authorization (file permissions)
  * The shell works inside a sandboxed virtual file system: "/" is the
    directory myshell_fs/, and paths can never resolve outside it.
  * Every file and directory has an owner, a group, and Unix-style mode bits
    (rwx for owner, group, other), stored in a metadata table.
  * Access is decided like Unix: the owner bits apply to the owner, the group
    bits to members of the file's group, and the other bits to everyone else.
    Every directory on the path needs execute (search) permission.
  * The admin role behaves like root: it bypasses read and write checks, but
    can execute a file only if at least one execute bit is set.
"""

import hashlib
import hmac
import json
import os
import posixpath
import secrets
import shutil
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

R, W, X = 4, 2, 1
NEED_NAME = {R: "read", W: "write", X: "execute"}


def need_name(need):
    return "+".join(NEED_NAME[b] for b in (R, W, X) if need & b)
MAX_FAILURES = 3
LOCKOUT_SECONDS = 60
PBKDF2_ITERATIONS = 200_000
ROLES = ("admin", "standard")


class AccessDenied(Exception):
    """Raised when an authorization check fails; the message explains why."""


# ----------------------------------------------------------------------
# Users and authentication
# ----------------------------------------------------------------------
@dataclass
class User:
    name: str
    role: str
    groups: List[str]
    salt: str
    pw_hash: str
    failed: int = 0
    locked_until: float = 0.0

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def primary_group(self):
        return self.groups[0] if self.groups else self.name


def hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex),
                               PBKDF2_ITERATIONS).hex()


# Demonstration accounts created on first run (documented in the README).
DEFAULT_USERS = [
    ("admin", "admin", ["admin", "staff"], "Admin@MSCS630"),
    ("alice", "standard", ["staff"], "Alice@MSCS630"),
    ("bob", "standard", ["staff"], "Bob@MSCS630"),
    ("guest", "standard", ["guests"], "Guest@MSCS630"),
]


class UserDB:
    def __init__(self, path):
        self.path = path
        self.users: Dict[str, User] = {}
        if os.path.exists(path):
            with open(path) as f:
                for rec in json.load(f):
                    self.users[rec["name"]] = User(**rec)
        else:
            for name, role, groups, pw in DEFAULT_USERS:
                self.add_user(name, role, pw, groups, save=False)
            self.save()

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump([asdict(u) for u in self.users.values()], f, indent=1)
        os.replace(tmp, self.path)              # atomic update
        os.chmod(self.path, 0o600)

    def add_user(self, name, role, password, groups=None, save=True):
        if not name.isidentifier() or len(name) > 32:
            raise ValueError("user names must be letters, digits, or _ (max 32)")
        if name in self.users:
            raise ValueError(f"user '{name}' already exists")
        if role not in ROLES:
            raise ValueError("role must be admin or standard")
        check_password_strength(password)
        salt = secrets.token_hex(16)
        groups = groups or (["admin", "staff"] if role == "admin" else ["staff"])
        self.users[name] = User(name, role, groups, salt, hash_password(password, salt))
        if save:
            self.save()
        return self.users[name]

    def delete_user(self, name):
        if name not in self.users:
            raise ValueError(f"no such user '{name}'")
        del self.users[name]
        self.save()

    def set_password(self, name, password):
        check_password_strength(password)
        u = self.users[name]
        u.salt = secrets.token_hex(16)
        u.pw_hash = hash_password(password, u.salt)
        u.failed, u.locked_until = 0, 0.0
        self.save()

    def authenticate(self, name, password, now=None):
        """Return (user or None, message)."""
        now = time.time() if now is None else now
        user = self.users.get(name)
        if user is None:
            hash_password(password, "00" * 16)  # same cost: no timing hint
            return None, "Login incorrect"
        if user.locked_until > now:
            return None, (f"Account '{name}' is locked; try again in "
                          f"{int(user.locked_until - now) + 1} s")
        if hmac.compare_digest(hash_password(password, user.salt), user.pw_hash):
            user.failed, user.locked_until = 0, 0.0
            self.save()
            return user, f"Welcome, {name} (role: {user.role})"
        user.failed += 1
        if user.failed >= MAX_FAILURES:
            user.locked_until = now + LOCKOUT_SECONDS
            user.failed = 0
            self.save()
            return None, (f"Login incorrect. Too many failures: account '{name}' "
                          f"locked for {LOCKOUT_SECONDS} s")
        self.save()
        return None, (f"Login incorrect ({MAX_FAILURES - user.failed} attempt(s) "
                      f"left before lockout)")


def check_password_strength(password):
    if len(password) < 8 or password.isalpha() or password.isdigit():
        raise ValueError("password must be at least 8 characters and mix letters "
                         "with digits or symbols")


# ----------------------------------------------------------------------
# Permission bits
# ----------------------------------------------------------------------
def mode_string(mode, is_dir=False):
    out = "d" if is_dir else "-"
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 7
        out += ("r" if bits & R else "-") + ("w" if bits & W else "-") + \
               ("x" if bits & X else "-")
    return out


def apply_chmod(spec, mode):
    """Apply an octal ("750") or symbolic ("u+x,g-w,o=r", "+x") mode change."""
    if spec.isdigit():
        if len(spec) > 4 or any(c not in "01234567" for c in spec):
            raise ValueError(f"invalid mode '{spec}'")
        return int(spec, 8) & 0o777
    for clause in spec.split(","):
        i = 0
        who = ""
        while i < len(clause) and clause[i] in "ugoa":
            who += clause[i]
            i += 1
        if i >= len(clause) or clause[i] not in "+-=":
            raise ValueError(f"invalid mode '{spec}'")
        op, perms = clause[i], clause[i + 1:]
        if any(c not in "rwx" for c in perms):
            raise ValueError(f"invalid mode '{spec}'")
        bits = (R if "r" in perms else 0) | (W if "w" in perms else 0) | \
               (X if "x" in perms else 0)
        shifts = {"u": [6], "g": [3], "o": [0], "a": [6, 3, 0]}
        targets = sorted({s for w in (who or "a") for s in shifts[w]})
        for s in targets:
            if op == "+":
                mode |= bits << s
            elif op == "-":
                mode &= ~(bits << s)
            else:
                mode = (mode & ~(7 << s)) | (bits << s)
    return mode & 0o777


# ----------------------------------------------------------------------
# Sandboxed virtual file system with permission metadata
# ----------------------------------------------------------------------
@dataclass
class Meta:
    owner: str
    group: str
    mode: int


class SecureFS:
    def __init__(self, root, meta_path, users: UserDB):
        self.root = os.path.realpath(root)
        self.meta_path = meta_path
        self.users = users
        self.meta: Dict[str, Meta] = {}
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                self.meta = {k: Meta(**v) for k, v in json.load(f).items()}

    # Paths ---------------------------------------------------------------
    @staticmethod
    def normalize(path, cwd="/"):
        """Resolve `path` against the virtual cwd. '..' never goes above '/'."""
        joined = path if path.startswith("/") else posixpath.join(cwd, path)
        parts = []
        for part in joined.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts)

    def real(self, vpath):
        real = os.path.join(self.root, vpath.lstrip("/"))
        resolved = os.path.realpath(real)
        if resolved != self.root and not resolved.startswith(self.root + os.sep):
            raise AccessDenied(f"{vpath}: path escapes the shell's file system")
        return real

    def exists(self, vpath):
        return os.path.lexists(self.real(vpath))

    def is_dir(self, vpath):
        return os.path.isdir(self.real(vpath))

    # Metadata ------------------------------------------------------------
    def save(self):
        tmp = self.meta_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({k: asdict(v) for k, v in sorted(self.meta.items())}, f, indent=1)
        os.replace(tmp, self.meta_path)

    def get(self, vpath):
        m = self.meta.get(vpath)
        if m is not None:
            return m
        # Files created outside the shell default to admin-owned.
        return Meta("admin", "admin", 0o755 if self.is_dir(vpath) else 0o644)

    def set(self, vpath, owner, group, mode, save=True):
        self.meta[vpath] = Meta(owner, group, mode)
        if save:
            self.save()

    def forget(self, vpath):
        for key in [k for k in self.meta if k == vpath or k.startswith(vpath + "/")]:
            del self.meta[key]
        self.save()

    # Authorization -------------------------------------------------------
    def bits_for(self, user: User, meta: Meta):
        if user.name == meta.owner:
            return (meta.mode >> 6) & 7, "owner"
        if meta.group in user.groups:
            return (meta.mode >> 3) & 7, f"group '{meta.group}'"
        return meta.mode & 7, "other"

    def decide(self, user: User, vpath, need):
        """Return None if allowed, otherwise the reason it is denied."""
        meta = self.get(vpath)
        if user.is_admin:
            if need & X and not meta.mode & 0o111:
                return (f"{vpath}: no execute bit is set "
                        f"({mode_string(meta.mode, self.is_dir(vpath))})")
            return None
        bits, cls = self.bits_for(user, meta)
        if bits & need == need:
            return None
        return (f"{need_name(need)} permission required on {vpath} "
                f"({meta.owner}:{meta.group} {mode_string(meta.mode, self.is_dir(vpath))}; "
                f"{user.name} is {cls})")

    def check(self, user: User, vpath, need, purpose=None):
        """Raise AccessDenied unless `user` may access `vpath` with `need`.
        Every ancestor directory must grant execute (search) permission."""
        parts = [p for p in vpath.split("/") if p]
        cur = "/"
        for part in parts[:-1]:
            cur = posixpath.join(cur, part)
            reason = self.decide(user, cur, X)
            if reason:
                raise AccessDenied(reason)
        reason = self.decide(user, vpath, need)
        if reason:
            raise AccessDenied(reason)

    def check_parent_write(self, user, vpath, purpose):
        """Creating or deleting an entry needs write+execute on its directory."""
        parent = posixpath.dirname(vpath) or "/"
        self.check(user, parent, W | X if not user.is_admin else W, purpose)

    # Seeding -------------------------------------------------------------
    def seed(self):
        """Create the demonstration file system (first run or 'fsreset')."""
        if os.path.exists(self.root):
            shutil.rmtree(self.root)
        os.makedirs(self.root)
        self.meta = {}
        dirs = [
            ("/", "admin", "admin", 0o755), ("/system", "admin", "admin", 0o755),
            ("/bin", "admin", "admin", 0o755), ("/home", "admin", "admin", 0o755),
            ("/shared", "admin", "staff", 0o775), ("/tmp", "admin", "admin", 0o777),
            ("/var", "admin", "admin", 0o755), ("/var/log", "admin", "admin", 0o750),
        ]
        for name in self.users.users:
            u = self.users.users[name]
            dirs.append((f"/home/{name}", name, u.primary_group, 0o700))
        for vpath, owner, group, mode in dirs:
            os.makedirs(self.real(vpath), exist_ok=True)
            self.meta[vpath] = Meta(owner, group, mode)
        files = [
            ("/system/config", "admin", "admin", 0o644,
             "hostname=myshell\nmax_users=16\nfs_root=/\naudit_log=/var/log/auth.log\n"),
            ("/system/secret.key", "admin", "admin", 0o600,
             "API_KEY=7f3a9c2e-demo-secret-0001\n"),
            ("/bin/report.sh", "admin", "staff", 0o750,
             "# System report (runs as the calling user)\necho === myshell report ===\n"
             "whoami\nls /shared\ncat /shared/server.log | grep -c ERROR\n"),
            ("/shared/server.log", "admin", "staff", 0o664,
             "2026-10-24 09:00:01 INFO  service started\n"
             "2026-10-24 09:02:13 ERROR disk quota exceeded on /tmp\n"
             "2026-10-24 09:05:40 WARN  slow response 2300ms\n"
             "2026-10-24 09:07:02 ERROR authentication timeout for bob\n"
             "2026-10-24 09:09:11 INFO  backup completed\n"
             "2026-10-24 09:12:55 ERROR connection refused by db01\n"
             "2026-10-24 09:15:30 INFO  user alice logged in\n"
             "2026-10-24 09:18:42 WARN  cache miss ratio 0.41\n"
             "2026-10-24 09:20:05 ERROR authentication timeout for alice\n"),
            ("/shared/notes.txt", "alice", "staff", 0o664,
             "Team meeting notes\n- finalize scheduler report\n- review page faults\n"),
            ("/shared/tasks.txt", "bob", "staff", 0o644,
             "pipes\nsecurity\nscheduling\nmemory\nsync\npipes\n"),
            ("/shared/budget.csv", "admin", "staff", 0o640,
             "item,cost\nservers,1200\nlicenses,300\n"),
            ("/shared/diagram.png", "admin", "staff", 0o644, "PNG placeholder\n"),
            ("/home/alice/notes.txt", "alice", "staff", 0o600,
             "alice's private notes\nmeeting notes: deliverable 4 due Sunday\n"),
            ("/home/alice/todo.txt", "alice", "staff", 0o644, "write report\nrun tests\n"),
            ("/home/bob/plan.txt", "bob", "staff", 0o600, "bob's plan\n"),
            ("/home/admin/hello.sh", "admin", "admin", 0o644,
             "echo Hello from a script\nwhoami\n"),
            ("/var/log/auth.log", "admin", "admin", 0o600, ""),
        ]
        for vpath, owner, group, mode, content in files:
            with open(self.real(vpath), "w") as f:
                f.write(content)
            self.meta[vpath] = Meta(owner, group, mode)
        self.save()

    def audit(self, event):
        """Append a security event to /var/log/auth.log (system write)."""
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.real("/var/log/auth.log"), "a") as f:
                f.write(f"{stamp} {event}\n")
        except OSError:
            pass
