#!/usr/bin/env python3
"""
myshell.py - Advanced Shell Simulation (final integrated shell, Deliverables 1-4)

Deliverable 1: built-in commands, foreground/background process execution,
and job control (jobs, fg, bg, stop, kill).

Deliverable 2: an internal process scheduler (see scheduler.py). The shell
keeps a table of simulated processes (`proc`) and schedules them with
Round-Robin (configurable time slice) or preemptive Priority scheduling
(`sched`), reporting waiting, turnaround, and response time.

Deliverable 3: memory management and process synchronization. `mem` manages
a simulated paging system with fixed-size frames, demand paging, page faults,
and FIFO or LRU page replacement (see memory.py). `sync` demonstrates mutexes
and semaphores: a race condition on shared memory, the Producer-Consumer
bounded buffer, and the Dining Philosophers problem (see sync.py).

Deliverable 4: integration and security. Users must log in (see security.py);
every file operation is authorized against owner/group/other rwx permission
bits in a sandboxed file system; jobs, simulated processes, and memory
allocations are owned by the user who created them. Commands can be chained
with pipes and redirected with <, >, and >> (see pipeline.py).

Requires a Unix-like OS (Linux, macOS, or WSL on Windows) because it uses
POSIX process groups and signals (SIGSTOP, SIGCONT, SIGTSTP).

Run:  python3 myshell.py
"""

import contextlib
import getpass
import io
import os
import posixpath
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime

from scheduler import (BackgroundRun, PriorityScheduler, RoundRobinScheduler,
                       SimProcess, compare, format_comparison, format_gantt,
                       format_metrics)
from memory import MemoryError_, MemoryManager, format_comparison as mem_comparison
from memory import format_trace
from sync import dining_philosophers, producer_consumer, race_demo
from security import (R, W, X, AccessDenied, SecureFS, UserDB, apply_chmod,
                      mode_string)
import pipeline
from pipeline import FilterError, PipelineSyntaxError

# Deliverable 3 demo: three processes whose combined virtual size (9 pages)
# exceeds physical memory (4 frames), so replacement is required.
MEM_DEMO_PROCS = [("A", 3), ("B", 4), ("C", 2)]
MEM_DEMO_TRACE = ("A:0 A:1 B:0 A:0 B:1 C:0 A:0 B:2 A:1 C:1 "
                  "A:0 B:0 C:0 A:2 A:0 B:1").split()
# Classic reference string (Silberschatz et al.)
TEXTBOOK_REFS = [7, 0, 1, 2, 0, 3, 0, 4, 2, 3, 0, 3, 2, 1, 2, 0, 1, 7, 0, 1]

# Canned, repeatable workload for demonstrations:
# (name, burst ticks, priority [lower = higher], arrival tick)
DEMO_WORKLOAD = [
    ("P1", 5, 2, 0),
    ("P2", 3, 1, 1),
    ("P3", 8, 4, 2),
    ("P4", 2, 1, 3),
    ("P5", 6, 2, 4),
]

# Where the shell keeps its user database, permission metadata, and sandbox.
SHELL_HOME = os.environ.get("MYSHELL_HOME", os.path.dirname(os.path.abspath(__file__)))

# External (host) programs a standard user may run. Admins may run any.
STANDARD_EXTERNAL = {"sleep", "date", "seq", "uname", "true", "false"}
# Built-ins that change session state cannot run inside a pipeline.
NOT_IN_PIPELINE = {"exit", "logout", "su", "passwd", "useradd", "userdel", "cd",
                   "clear", "fg", "bg", "stop"}
MAX_SCRIPT_DEPTH = 5

# Job states
RUNNING = "Running"
STOPPED = "Stopped"
DONE = "Done"


class ShellError(Exception):
    """An ordinary command error (bad argument, missing file, ...)."""


class Job:
    """A process launched by the shell and tracked for job control."""

    def __init__(self, job_id, process, command, owner):
        self.job_id = job_id
        self.process = process          # subprocess.Popen object
        self.pid = process.pid
        self.command = command
        self.owner = owner              # user who started the job
        self.status = RUNNING
        self.exit_code = None
        self.started = time.time()

    def __str__(self):
        return f"[{self.job_id}] {self.pid:<7} {self.status:<8} {self.command}"


class Shell:
    def __init__(self, home=SHELL_HOME):
        self.jobs = {}               # job_id -> Job
        self.fg_job = None           # job currently in the foreground
        self.running = True
        self.last_status = 0

        # Deliverable 2: simulated process table and scheduler state
        self.workload = {}           # name -> SimProcess (insertion = FCFS order)
        self.next_sim_pid = 101
        self.tick_seconds = 0.1      # real seconds per simulated tick
        self.last_result = None
        self.active_run = None       # BackgroundRun while `sched ... &` runs
        self._background_builtin = False

        # Deliverable 3: simulated physical memory (4 frames x 4 KB, FIFO)
        self.memory = MemoryManager(4, 4096, "fifo")

        # Deliverable 4: security state
        data_dir = os.path.join(home, "myshell_data")
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self.users = UserDB(os.path.join(data_dir, "users.json"))
        self.fs = SecureFS(os.path.join(home, "myshell_fs"),
                           os.path.join(data_dir, "fs_meta.json"), self.users)
        if not os.path.isdir(self.fs.root) or not self.fs.meta:
            self.fs.seed()
        self.user = None             # authenticated User, or None at login
        self.su_stack = []           # users to return to after 'su'
        self.vcwd = "/"              # current directory inside the sandbox
        self.stdin_data = None       # text piped into the running built-in
        self.script_depth = 0
        self.owners = {"proc": {}, "mem": {}}   # resource name -> owner

        self.builtins = {
            "cd": self.cmd_cd, "pwd": self.cmd_pwd, "exit": self.cmd_exit,
            "echo": self.cmd_echo, "clear": self.cmd_clear, "ls": self.cmd_ls,
            "cat": self.cmd_cat, "mkdir": self.cmd_mkdir, "rmdir": self.cmd_rmdir,
            "rm": self.cmd_rm, "touch": self.cmd_touch, "kill": self.cmd_kill,
            "jobs": self.cmd_jobs, "fg": self.cmd_fg, "bg": self.cmd_bg,
            "stop": self.cmd_stop, "help": self.cmd_help,
            "proc": self.cmd_proc, "sched": self.cmd_sched,
            "mem": self.cmd_mem, "sync": self.cmd_sync,
            # Deliverable 4
            "whoami": self.cmd_whoami, "id": self.cmd_id, "users": self.cmd_users,
            "useradd": self.cmd_useradd, "userdel": self.cmd_userdel,
            "passwd": self.cmd_passwd, "su": self.cmd_su, "logout": self.cmd_logout,
            "chmod": self.cmd_chmod, "chown": self.cmd_chown, "run": self.cmd_run,
        }
        for name in pipeline.FILTERS:
            self.builtins[name] = (lambda n: lambda args: self.cmd_filter(n, args))(name)

        # The shell itself ignores Ctrl+C and Ctrl+Z; they are forwarded
        # to the foreground job instead, so the shell keeps running.
        signal.signal(signal.SIGINT, self.handle_sigint)
        signal.signal(signal.SIGTSTP, self.handle_sigtstp)

    # ------------------------------------------------------------------
    # Login and session
    # ------------------------------------------------------------------
    def login(self):
        """One login attempt. Returns False when input has ended."""
        try:
            name = input("login: ").strip()
        except EOFError:
            print()
            return False
        except KeyboardInterrupt:
            print()
            return True
        if not name:
            return True
        try:
            password = getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return True
        user, message = self.users.authenticate(name, password)
        if user is None:
            print(message)
            self.fs.audit(f"LOGIN_FAIL user={name} ({message})")
            time.sleep(0.5)                  # slow down password guessing
            return True
        self.fs.audit(f"LOGIN_OK user={name} role={user.role}")
        print(message)
        self.start_session(user)
        return True

    def start_session(self, user):
        self.user = user
        home = f"/home/{user.name}"
        self.vcwd = home if self.fs.is_dir(home) else "/"
        os.chdir(self.fs.real(self.vcwd))

    def end_session(self, reason="LOGOUT"):
        """Hang up the user's jobs, as a terminal hang-up (SIGHUP) would."""
        mine = [j for j in self.jobs.values() if j.owner == self.user.name]
        for job in mine:
            try:
                os.killpg(job.pid, signal.SIGCONT)
                os.killpg(job.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
        if mine:
            print(f"Hung up {len(mine)} job(s) owned by {self.user.name}.")
            time.sleep(0.1)
            self.reap_jobs()
        self.fs.audit(f"{reason} user={self.user.name}")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def display(self, vpath):
        home = f"/home/{self.user.name}"
        if vpath == home or vpath.startswith(home + "/"):
            return "~" + vpath[len(home):]
        return vpath

    def prompt(self):
        mark = "#" if self.user.is_admin else "$"
        return f"{self.user.name}@myshell:{self.display(self.vcwd)}{mark} "

    def run(self):
        print("myshell - integrated OS simulation shell. Please log in.")
        while self.running:
            if self.user is None:
                if not self.login():
                    break
                if self.user:
                    print("Type 'help' for a list of commands.")
                continue
            self.reap_jobs()
            try:
                line = input(self.prompt())
            except EOFError:
                print()
                self.cmd_exit([])
                break
            except KeyboardInterrupt:
                print()
                continue
            try:
                self.execute_line(line)
            except KeyboardInterrupt:
                print("\nmyshell: interrupted")
                self.last_status = 130

    def execute_line(self, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return
        try:
            pipe = pipeline.parse(line)
        except PipelineSyntaxError as e:
            self.error(str(e))
            self.last_status = 2
            return
        if pipe is None:
            return
        if pipe.is_simple:
            self.run_simple(pipe.stages[0], pipe.text, pipe.background)
        else:
            self.run_pipeline(pipe)

    def run_simple(self, args, text, background):
        name = args[0]
        if name in self.builtins:
            # Only the scheduler may run in the background (in a thread), so
            # that processes can be added while it is running.
            if background and name != "sched":
                self.error(f"{name}: built-in commands cannot run in the background")
                return
            self._background_builtin = background
            try:
                self.last_status = self.call_builtin(name, args[1:], text)
            finally:
                self._background_builtin = False
        elif "/" in name and self.fs.exists(self.resolve(name)):
            # ./script or /bin/script inside the sandbox: run it as a script
            self.last_status = self.call_builtin("run", [name] + args[1:], text)
        else:
            self.launch(args, text, background)

    def call_builtin(self, name, args, text):
        try:
            return self.builtins[name](args) or 0
        except AccessDenied as e:
            self.error(f"{name}: permission denied: {e}")
            self.fs.audit(f"DENIED user={self.user.name} cmd='{text}' reason={e}")
            return 1
        except ShellError as e:
            self.error(f"{name}: {e}")
            return 1
        except Exception as e:  # last line of defence: never crash the shell
            self.error(f"{name}: {e}")
            return 1

    # ------------------------------------------------------------------
    # Pipelines and redirection
    # ------------------------------------------------------------------
    def run_pipeline(self, pipe):
        """Run each stage in order; stage i's standard output becomes stage
        i+1's standard input. Errors go to standard error, not down the pipe."""
        data = None
        if pipe.stdin_file:
            try:
                _, data = self.read_file(pipe.stdin_file, "<")
            except (AccessDenied, ShellError) as e:
                self.report_redirect_error(e, pipe.text)
                return
        status = 0
        for i, args in enumerate(pipe.stages):
            last = i == len(pipe.stages) - 1
            capture = not last or pipe.stdout_file is not None
            data, status = self.run_stage(args, data, capture, pipe.text)
        if pipe.stdout_file is not None:
            try:
                self.write_file(pipe.stdout_file, data or "", pipe.append, ">")
            except (AccessDenied, ShellError) as e:
                self.report_redirect_error(e, pipe.text)
                status = 1
        self.last_status = status

    def report_redirect_error(self, e, text):
        if isinstance(e, AccessDenied):
            self.error(f"redirection: permission denied: {e}")
            self.fs.audit(f"DENIED user={self.user.name} cmd='{text}' reason={e}")
        else:
            self.error(str(e))
        self.last_status = 1

    def run_stage(self, args, data, capture, text):
        """Run one stage with `data` as standard input. Returns (output, status);
        output is None when the stage wrote straight to the terminal."""
        name = args[0]
        if name in NOT_IN_PIPELINE:
            self.error(f"{name}: cannot be used in a pipeline or with redirection")
            return ("" if capture else None), 1
        if name in self.builtins or ("/" in name and self.fs.exists(self.resolve(name))):
            if name not in self.builtins:
                name, args = "run", ["run"] + args
            buf = io.StringIO()
            self.stdin_data = data
            try:
                if capture:
                    with contextlib.redirect_stdout(buf):
                        status = self.call_builtin(name, args[1:], text)
                else:
                    status = self.call_builtin(name, args[1:], text)
            finally:
                self.stdin_data = None
            return (buf.getvalue() if capture else None), status
        if not self.external_allowed(name):
            return ("" if capture else None), 127 if shutil.which(name) is None else 126
        try:
            result = subprocess.run(args, input=data, text=True,
                                    stdout=subprocess.PIPE if capture else None,
                                    cwd=self.fs.real(self.vcwd))
        except FileNotFoundError:
            self.error(f"{name}: command not found")
            return ("" if capture else None), 127
        except PermissionError:
            self.error(f"{name}: permission denied")
            return ("" if capture else None), 126
        return (result.stdout if capture else None), result.returncode

    def external_allowed(self, name):
        if shutil.which(name) is None:
            self.error(f"{name}: command not found")
            return False
        if self.user.is_admin or name in STANDARD_EXTERNAL:
            return True
        self.error(f"{name}: permission denied: standard users may only run the "
                   f"host programs {', '.join(sorted(STANDARD_EXTERNAL))}")
        self.fs.audit(f"DENIED user={self.user.name} external='{name}'")
        return False

    # ------------------------------------------------------------------
    # Permission-checked file access (used by every file built-in)
    # ------------------------------------------------------------------
    def resolve(self, path):
        if path == "~" or path.startswith("~/"):
            path = f"/home/{self.user.name}" + path[1:]
        return SecureFS.normalize(path, self.vcwd)

    def read_file(self, path, purpose):
        vpath = self.resolve(path)
        if not self.fs.exists(vpath):
            raise ShellError(f"{path}: no such file")
        if self.fs.is_dir(vpath):
            raise ShellError(f"{path}: is a directory")
        self.fs.check(self.user, vpath, R, purpose)
        with open(self.fs.real(vpath), errors="replace") as f:
            return vpath, f.read()

    def write_file(self, path, text, append, purpose):
        vpath = self.resolve(path)
        if self.fs.exists(vpath):
            if self.fs.is_dir(vpath):
                raise ShellError(f"{path}: is a directory")
            self.fs.check(self.user, vpath, W, purpose)
            new = False
        else:
            if not self.fs.is_dir(posixpath.dirname(vpath)):
                raise ShellError(f"{path}: no such directory")
            self.fs.check_parent_write(self.user, vpath, purpose)
            new = True
        with open(self.fs.real(vpath), "a" if append else "w") as f:
            f.write(text)
        if new:
            self.fs.set(vpath, self.user.name, self.user.primary_group, 0o644)

    def input_text(self, files, command):
        """Text from the named files, or from the pipe when no file is named."""
        if files:
            return "".join(self.read_file(f, command)[1] for f in files)
        if self.stdin_data is None:
            raise ShellError("no input: name a file or pipe data into the command")
        return self.stdin_data

    def owns_or_admin(self, owner):
        return self.user.is_admin or owner == self.user.name

    def require_admin(self, action):
        if not self.user.is_admin:
            raise AccessDenied(f"only an admin may {action} (you are "
                               f"{self.user.name}, role {self.user.role})")

    # ------------------------------------------------------------------
    # Process creation and job control
    # ------------------------------------------------------------------
    def launch(self, args, command_text, background):
        """Create a new process for an external command (fork + exec)."""
        if not self.external_allowed(args[0]):
            self.last_status = 127 if shutil.which(args[0]) is None else 126
            return
        try:
            # Popen performs fork() + exec() internally. start_new_session
            # places the child in its own process group so job-control
            # signals reach it without affecting the shell.
            proc = subprocess.Popen(args, start_new_session=True,
                                    cwd=self.fs.real(self.vcwd))
        except FileNotFoundError:
            self.error(f"{args[0]}: command not found")
            self.last_status = 127
            return
        except PermissionError:
            self.error(f"{args[0]}: permission denied")
            self.last_status = 126
            return
        except OSError as e:
            self.error(f"{args[0]}: {e.strerror}")
            self.last_status = 1
            return

        # Like bash, job numbers restart from 1 when no jobs are active.
        job_id = max(self.jobs) + 1 if self.jobs else 1
        job = Job(job_id, proc, command_text.rstrip("&").strip(), self.user.name)
        self.jobs[job.job_id] = job

        if background:
            print(f"[{job.job_id}] {job.pid}")
        else:
            self.wait_foreground(job)

    def wait_foreground(self, job):
        """Wait for a foreground job to finish or stop (like wait())."""
        self.fg_job = job
        while True:
            try:
                pid, status = os.waitpid(job.pid, os.WUNTRACED)
            except ChildProcessError:
                job.status = DONE
                break
            except InterruptedError:
                continue
            if os.WIFSTOPPED(status):
                job.status = STOPPED
                print(f"\n{job}")
                break
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                job.status = DONE
                job.exit_code = (os.WEXITSTATUS(status) if os.WIFEXITED(status)
                                 else -os.WTERMSIG(status))
                job.process.returncode = job.exit_code
                self.last_status = job.exit_code
                if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGINT:
                    print()   # move the prompt off the ^C line
                break
        self.fg_job = None
        if job.status == DONE:
            del self.jobs[job.job_id]

    def reap_jobs(self):
        """Check background jobs without blocking and report changes."""
        for job in list(self.jobs.values()):
            try:
                pid, status = os.waitpid(job.pid, os.WNOHANG | os.WUNTRACED
                                         | os.WCONTINUED)
            except ChildProcessError:
                pid, status = job.pid, 0
                job.status = DONE
            if pid == 0:
                continue
            if os.WIFSTOPPED(status):
                job.status = STOPPED
            elif os.WIFCONTINUED(status):
                job.status = RUNNING
            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                job.status = DONE
                job.exit_code = (os.WEXITSTATUS(status) if os.WIFEXITED(status)
                                 else -os.WTERMSIG(status))
                job.process.returncode = job.exit_code
            if job.status == DONE:
                print(f"{job}  (exit code {job.exit_code})")
                del self.jobs[job.job_id]

    def get_job(self, args, command):
        """Find a job the current user may control (own job, or any for admin)."""
        visible = {k: j for k, j in self.jobs.items() if self.owns_or_admin(j.owner)}
        if not args:
            if not visible:
                self.error(f"{command}: no current jobs")
                return None
            return visible[max(visible)]
        ref = args[0].lstrip("%")
        if not ref.isdigit():
            self.error(f"{command}: invalid job id '{args[0]}'")
            return None
        job = self.jobs.get(int(ref))
        if job is None:
            self.error(f"{command}: job {ref} not found")
            return None
        if not self.owns_or_admin(job.owner):
            raise AccessDenied(f"job {ref} belongs to {job.owner}")
        return job

    def handle_sigint(self, signum, frame):
        if self.fg_job:
            os.killpg(self.fg_job.pid, signal.SIGINT)
        else:
            raise KeyboardInterrupt

    def handle_sigtstp(self, signum, frame):
        # The child runs in its own session, so the kernel would discard a
        # forwarded SIGTSTP (orphaned process group). SIGSTOP cannot be
        # ignored or discarded, so it reliably suspends the job.
        if self.fg_job:
            os.killpg(self.fg_job.pid, signal.SIGSTOP)

    # ------------------------------------------------------------------
    # Built-in commands (file system built-ins check permissions)
    # ------------------------------------------------------------------
    def error(self, message):
        print(f"myshell: {message}", file=sys.stderr)

    def cmd_cd(self, args):
        target = self.resolve(args[0] if args else "~")
        if not self.fs.exists(target):
            raise ShellError(f"{args[0]}: no such directory")
        if not self.fs.is_dir(target):
            raise ShellError(f"{args[0]}: not a directory")
        self.fs.check(self.user, target, X, "cd")
        self.vcwd = target
        os.chdir(self.fs.real(target))
        return 0

    def cmd_pwd(self, args):
        print(self.vcwd)
        return 0

    def cmd_exit(self, args):
        if self.user is not None:
            self.end_session("EXIT")
        if self.jobs:
            print(f"Terminating {len(self.jobs)} remaining job(s)...")
            for job in self.jobs.values():
                try:
                    os.killpg(job.pid, signal.SIGCONT)
                    os.killpg(job.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        print("Goodbye.")
        self.running = False
        return 0

    def cmd_echo(self, args):
        print(" ".join(args))
        return 0

    def cmd_clear(self, args):
        os.system("cls" if os.name == "nt" else "clear")
        return 0

    def cmd_ls(self, args):
        show_all = any(a.startswith("-") and "a" in a for a in args)
        long = any(a.startswith("-") and "l" in a for a in args)
        paths = [a for a in args if not a.startswith("-")] or ["."]
        status = 0
        for path in paths:
            vpath = self.resolve(path)
            if not self.fs.exists(vpath):
                self.error(f"ls: {path}: no such file or directory")
                status = 1
                continue
            if len(paths) > 1:
                print(f"{path}:")
            if self.fs.is_dir(vpath):
                self.fs.check(self.user, vpath, R | X if long else R, "ls")
                entries = sorted(os.listdir(self.fs.real(vpath)))
                if not show_all:
                    entries = [e for e in entries if not e.startswith(".")]
                targets = [(e, posixpath.join(vpath, e)) for e in entries]
            else:
                parent = posixpath.dirname(vpath)
                self.fs.check(self.user, parent, X, "ls")
                targets = [(path, vpath)]
            for name, full in targets:
                if long:
                    print(self.long_entry(name, full))
                else:
                    print(name + ("/" if self.fs.is_dir(full) else ""))
        return status

    def long_entry(self, name, vpath):
        meta = self.fs.get(vpath)
        info = os.lstat(self.fs.real(vpath))
        mtime = datetime.fromtimestamp(info.st_mtime).strftime("%b %d %H:%M")
        is_dir = self.fs.is_dir(vpath)
        return (f"{mode_string(meta.mode, is_dir)} {meta.owner:<6} {meta.group:<7} "
                f"{info.st_size:>6} {mtime} {name}{'/' if is_dir else ''}")

    def cmd_cat(self, args):
        sys.stdout.write(self.input_text(args, "cat"))
        sys.stdout.flush()
        return 0

    def cmd_mkdir(self, args):
        if not args:
            raise ShellError("missing directory operand")
        for name in args:
            vpath = self.resolve(name)
            if self.fs.exists(vpath):
                raise ShellError(f"{name}: already exists")
            if not self.fs.is_dir(posixpath.dirname(vpath)):
                raise ShellError(f"{name}: parent directory does not exist")
            self.fs.check_parent_write(self.user, vpath, "mkdir")
            os.mkdir(self.fs.real(vpath))
            self.fs.set(vpath, self.user.name, self.user.primary_group, 0o755)
        return 0

    def cmd_rmdir(self, args):
        if not args:
            raise ShellError("missing directory operand")
        for name in args:
            vpath = self.resolve(name)
            if vpath == "/" or not self.fs.exists(vpath):
                raise ShellError(f"{name}: no such directory")
            if not self.fs.is_dir(vpath):
                raise ShellError(f"{name}: not a directory")
            self.fs.check_parent_write(self.user, vpath, "rmdir")
            if os.listdir(self.fs.real(vpath)):
                raise ShellError(f"{name}: directory not empty")
            os.rmdir(self.fs.real(vpath))
            self.fs.forget(vpath)
        return 0

    def cmd_rm(self, args):
        if not args:
            raise ShellError("missing file operand")
        for name in args:
            vpath = self.resolve(name)
            if not self.fs.exists(vpath):
                raise ShellError(f"{name}: no such file")
            if self.fs.is_dir(vpath):
                raise ShellError(f"{name}: is a directory (use rmdir)")
            # Unix rule: deleting a name needs write permission on the directory
            self.fs.check_parent_write(self.user, vpath, "rm")
            os.remove(self.fs.real(vpath))
            self.fs.forget(vpath)
        return 0

    def cmd_touch(self, args):
        if not args:
            raise ShellError("missing file operand")
        for name in args:
            vpath = self.resolve(name)
            if self.fs.exists(vpath):
                self.fs.check(self.user, vpath, W, "touch")
                os.utime(self.fs.real(vpath), None)
            else:
                self.write_file(name, "", True, "touch")
        return 0

    def cmd_kill(self, args):
        if not args:
            raise ShellError("usage: kill [pid | %job_id]")
        status = 0
        for target in args:
            if target.startswith("%"):
                job = self.get_job([target], "kill")
                if job is None:
                    status = 1
                    continue
                pid = job.pid
            elif target.isdigit():
                pid = int(target)
                job = next((j for j in self.jobs.values() if j.pid == pid), None)
                if not self.user.is_admin and (job is None or job.owner != self.user.name):
                    raise AccessDenied(f"process {pid} was not started by {self.user.name}")
            else:
                self.error(f"kill: {target}: invalid process id")
                status = 1
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                # Wake a stopped process so it can receive SIGTERM.
                os.kill(pid, signal.SIGCONT)
                print(f"Sent SIGTERM to process {pid}")
            except ProcessLookupError:
                self.error(f"kill: ({pid}) - no such process")
                status = 1
            except PermissionError:
                self.error(f"kill: ({pid}) - operation not permitted")
                status = 1
        time.sleep(0.1)
        self.reap_jobs()
        return status

    def cmd_jobs(self, args):
        self.reap_jobs()
        visible = [j for j in self.jobs.values() if self.owns_or_admin(j.owner)]
        if not visible:
            print("No background jobs.")
            return 0
        print(f"{'JOB':<4}{'PID':<8}{'STATUS':<9}{'OWNER':<7}COMMAND")
        for job in sorted(visible, key=lambda j: j.job_id):
            print(f"[{job.job_id}] {job.pid:<7} {job.status:<8} {job.owner:<6} "
                  f"{job.command}")
        return 0

    def cmd_fg(self, args):
        job = self.get_job(args, "fg")
        if job is None:
            return 1
        print(job.command)
        if job.status == STOPPED:
            os.killpg(job.pid, signal.SIGCONT)
        job.status = RUNNING
        self.wait_foreground(job)
        return 0

    def cmd_bg(self, args):
        job = self.get_job(args, "bg")
        if job is None:
            return 1
        if job.status == RUNNING:
            self.error(f"bg: job {job.job_id} is already running in the background")
            return 1
        os.killpg(job.pid, signal.SIGCONT)
        job.status = RUNNING
        print(f"[{job.job_id}] {job.command} &")
        return 0

    def cmd_stop(self, args):
        """Stop (suspend) a background job, same effect as Ctrl+Z."""
        job = self.get_job(args, "stop")
        if job is None:
            return 1
        if job.status == STOPPED:
            self.error(f"stop: job {job.job_id} is already stopped")
            return 1
        os.killpg(job.pid, signal.SIGSTOP)
        job.status = STOPPED
        print(job)
        return 0

    # ------------------------------------------------------------------
    # Deliverable 4: text filters for pipelines
    # ------------------------------------------------------------------
    FILTER_SPEC = {"grep": ("ivcn", "", 1), "sort": ("rnu", "", 0), "uniq": ("c", "", 0),
                   "wc": ("lwc", "", 0), "head": ("", "n", 0), "tail": ("", "n", 0)}

    def cmd_filter(self, name, args):
        allowed, with_value, skip = self.FILTER_SPEC[name]
        try:
            _flags, operands = pipeline.take_flags(args, allowed, with_value)
            files = operands[skip:]
            filter_args = args[:len(args) - len(files)] if files else args
            text = self.input_text(files, name)
            out, status = pipeline.FILTERS[name](filter_args, text)
        except FilterError as e:
            raise ShellError(str(e))
        sys.stdout.write(out)
        sys.stdout.flush()
        return status

    # ------------------------------------------------------------------
    # Deliverable 4: users, authentication, and permissions
    # ------------------------------------------------------------------
    def cmd_whoami(self, args):
        print(self.user.name)
        return 0

    def cmd_id(self, args):
        name = args[0] if args else self.user.name
        u = self.users.users.get(name)
        if u is None:
            raise ShellError(f"{name}: no such user")
        print(f"user={u.name} role={u.role} groups={','.join(u.groups)}")
        return 0

    def cmd_users(self, args):
        print(f"{'USER':<8}{'ROLE':<10}{'GROUPS':<14}STATUS")
        for u in self.users.users.values():
            status = ("locked" if u.locked_until > time.time() else "active") \
                if self.user.is_admin else "-"
            print(f"{u.name:<8}{u.role:<10}{','.join(u.groups):<14}{status}")
        return 0

    def ask_new_password(self):
        first = getpass.getpass("New password: ")
        if getpass.getpass("Retype new password: ") != first:
            raise ShellError("passwords do not match")
        return first

    def cmd_useradd(self, args):
        self.require_admin("add users")
        if len(args) != 2:
            raise ShellError("usage: useradd NAME admin|standard")
        name, role = args
        try:
            user = self.users.add_user(name, role, self.ask_new_password())
        except ValueError as e:
            raise ShellError(str(e))
        home = f"/home/{name}"
        if not self.fs.exists(home):
            os.makedirs(self.fs.real(home))
        self.fs.set(home, name, user.primary_group, 0o700)
        self.fs.audit(f"USERADD by={self.user.name} user={name} role={role}")
        print(f"Created user {name} (role {role}, groups {','.join(user.groups)}, "
              f"home {home})")
        return 0

    def cmd_userdel(self, args):
        self.require_admin("delete users")
        if len(args) != 1:
            raise ShellError("usage: userdel NAME")
        if args[0] == self.user.name:
            raise ShellError("you cannot delete your own account")
        try:
            self.users.delete_user(args[0])
        except ValueError as e:
            raise ShellError(str(e))
        self.fs.audit(f"USERDEL by={self.user.name} user={args[0]}")
        print(f"Deleted user {args[0]} (home directory kept)")
        return 0

    def cmd_passwd(self, args):
        target = args[0] if args else self.user.name
        if target not in self.users.users:
            raise ShellError(f"{target}: no such user")
        if target != self.user.name:
            self.require_admin("change another user's password")
        else:
            current = getpass.getpass("Current password: ")
            if self.users.authenticate(target, current)[0] is None:
                self.fs.audit(f"PASSWD_FAIL user={target}")
                raise ShellError("authentication failed")
        try:
            self.users.set_password(target, self.ask_new_password())
        except ValueError as e:
            raise ShellError(str(e))
        self.fs.audit(f"PASSWD by={self.user.name} user={target}")
        print(f"Password updated for {target}")
        return 0

    def cmd_su(self, args):
        if len(args) != 1:
            raise ShellError("usage: su USER")
        name = args[0]
        if not self.user.is_admin:            # admins may switch without a password
            password = getpass.getpass("Password: ")
            user, message = self.users.authenticate(name, password)
            if user is None:
                self.fs.audit(f"SU_FAIL from={self.user.name} to={name}")
                raise ShellError(message)
        else:
            user = self.users.users.get(name)
            if user is None:
                raise ShellError(f"{name}: no such user")
        self.fs.audit(f"SU from={self.user.name} to={name}")
        self.su_stack.append((self.user, self.vcwd))
        self.start_session(user)
        print(f"Switched to {name} (role {user.role}); 'logout' returns to "
              f"{self.su_stack[-1][0].name}")
        return 0

    def cmd_logout(self, args):
        self.end_session()
        if self.su_stack:
            user, cwd = self.su_stack.pop()
            self.user, self.vcwd = user, cwd
            os.chdir(self.fs.real(cwd))
            print(f"Returned to {user.name}")
        else:
            print(f"{self.user.name} logged out.")
            self.user = None
        return 0

    def cmd_chmod(self, args):
        if len(args) < 2:
            raise ShellError("usage: chmod MODE FILE... (e.g. 640, u+x, g-w,o=r)")
        for name in args[1:]:
            vpath = self.resolve(name)
            if not self.fs.exists(vpath):
                raise ShellError(f"{name}: no such file or directory")
            self.fs.check(self.user, vpath, 0, "chmod")        # path must be reachable
            meta = self.fs.get(vpath)
            if not self.owns_or_admin(meta.owner):
                raise AccessDenied(f"only the owner ({meta.owner}) or an admin may "
                                   f"change the mode of {vpath}")
            try:
                new_mode = apply_chmod(args[0], meta.mode)
            except ValueError as e:
                raise ShellError(str(e))
            self.fs.set(vpath, meta.owner, meta.group, new_mode)
            self.fs.audit(f"CHMOD by={self.user.name} {vpath} "
                          f"{mode_string(meta.mode)} to {mode_string(new_mode)}")
            print(f"{vpath}: {mode_string(meta.mode, self.fs.is_dir(vpath))} -> "
                  f"{mode_string(new_mode, self.fs.is_dir(vpath))}")
        return 0

    def cmd_chown(self, args):
        self.require_admin("change file ownership")
        if len(args) < 2:
            raise ShellError("usage: chown USER[:GROUP] FILE...")
        owner, _, group = args[0].partition(":")
        if owner not in self.users.users:
            raise ShellError(f"{owner}: no such user")
        for name in args[1:]:
            vpath = self.resolve(name)
            if not self.fs.exists(vpath):
                raise ShellError(f"{name}: no such file or directory")
            meta = self.fs.get(vpath)
            self.fs.set(vpath, owner, group or meta.group, meta.mode)
            self.fs.audit(f"CHOWN by={self.user.name} {vpath} {owner}:{group or meta.group}")
            print(f"{vpath}: owner {owner}, group {group or meta.group}")
        return 0

    def cmd_run(self, args):
        """Execute a script of shell commands; needs read and execute permission."""
        if not args:
            raise ShellError("usage: run SCRIPT  (or ./SCRIPT)")
        vpath = self.resolve(args[0])
        if not self.fs.exists(vpath) or self.fs.is_dir(vpath):
            raise ShellError(f"{args[0]}: no such file")
        self.fs.check(self.user, vpath, X, "execute")
        self.fs.check(self.user, vpath, R, "execute")
        if self.script_depth >= MAX_SCRIPT_DEPTH:
            raise ShellError("scripts nested too deeply")
        with open(self.fs.real(vpath)) as f:
            lines = f.read().splitlines()
        self.script_depth += 1
        try:
            for line in lines:
                self.execute_line(line)
        finally:
            self.script_depth -= 1
        return self.last_status

    def cmd_help(self, args):
        print("""Files (permission-checked; '/' is the shell's sandboxed file system):
  cd [dir]  pwd  ls [-a] [-l] [path]  cat [file...]  mkdir dir  rmdir dir
  rm file  touch file  echo text  clear  chmod MODE file  chown USER[:GROUP] file
Pipes and redirection:
  cmd1 | cmd2 | ...     cmd < infile     cmd > outfile     cmd >> outfile
  filters: grep [-i -v -c -n] PATTERN | sort [-r -n -u] | uniq [-c] | wc [-l -w -c]
           head [-n N] | tail [-n N]
Users and security:
  whoami  id [user]  users  passwd [user]  su USER  logout  exit
  useradd NAME admin|standard  userdel NAME      (admin only)
  run SCRIPT  or  ./SCRIPT                       (needs read + execute permission)
Processes and job control:
  command &  jobs  fg [id]  bg [id]  stop [id]  kill [pid|%id]  Ctrl+Z
Process scheduling (simulated CPU):
  proc add NAME BURST [PRIORITY] [ARRIVAL] | proc list | proc rm NAME | proc clear | proc demo
  sched rr QUANTUM [--tick S] | sched priority [--tick S] | sched ... & | sched ... --quiet
  sched tick S | sched metrics | sched compare [Q ...] | sched status
Memory management (paging):
  mem init FRAMES [PAGE_KB] [--policy fifo|lru] | mem policy fifo|lru | mem demo [fifo|lru]
  mem alloc NAME PAGES | mem free NAME | mem access NAME PAGE... | mem trace NAME:PAGE...
  mem status | mem refs FRAMES fifo|lru|opt PAGE... | mem compare [--frames A-B] PAGE...
Process synchronization:
  sync race [THREADS] [ITERATIONS] | sync pc [options] | sync dining [--naive] [options]
Host programs: admins may run any; standard users may run """ +
              ", ".join(sorted(STANDARD_EXTERNAL)) + ".")
        return 0

    # ------------------------------------------------------------------
    # Deliverable 2: simulated process table (proc)
    # ------------------------------------------------------------------
    @staticmethod
    def parse_int(text, label, minimum):
        try:
            value = int(text)
        except ValueError:
            raise ValueError(f"{label} must be an integer, got '{text}'")
        if value < minimum:
            raise ValueError(f"{label} must be >= {minimum}, got {value}")
        return value

    def add_process(self, name, burst, priority=5, arrival=0):
        proc = SimProcess(name, burst, priority, arrival,
                          pid=self.next_sim_pid, seq=self.next_sim_pid)
        self.next_sim_pid += 1
        self.workload[name] = proc
        return proc

    def clear_own_processes(self):
        """Admins clear the whole table; standard users only their own entries."""
        for name in list(self.workload):
            if self.owns_or_admin(self.owners["proc"].get(name)):
                del self.workload[name]
                self.owners["proc"].pop(name, None)

    def cmd_proc(self, args):
        usage = "usage: proc add NAME BURST [PRIORITY] [ARRIVAL] | list | rm NAME | clear | demo"
        if not args:
            self.error(f"proc: {usage}")
            return 1
        sub, rest = args[0], args[1:]

        if sub == "add":
            if not 2 <= len(rest) <= 4:
                self.error(f"proc: {usage}")
                return 1
            name = rest[0]
            if name in self.workload:
                self.error(f"proc: a process named '{name}' already exists")
                return 1
            try:
                burst = self.parse_int(rest[1], "burst time", 1)
                priority = self.parse_int(rest[2], "priority", 0) if len(rest) > 2 else 5
                arrival = self.parse_int(rest[3], "arrival time", 0) if len(rest) > 3 else 0
            except ValueError as e:
                self.error(f"proc: {e}")
                return 1
            proc = self.add_process(name, burst, priority, arrival)
            self.owners["proc"][name] = self.user.name
            run = self.active_run
            if run is not None and run.is_alive():
                # A scheduler is running in the background: the new process
                # arrives now and may preempt the running process.
                run.scheduler.inject(proc)
                print(f"Added {name} (pid {proc.pid}, burst {burst}, priority "
                      f"{priority}) to the running scheduler")
            else:
                print(f"Added {name} (pid {proc.pid}, burst {burst}, "
                      f"priority {priority}, arrival {arrival})")
            return 0

        if sub == "list":
            if not self.workload:
                print("Process table is empty. Use 'proc add' or 'proc demo'.")
                return 0
            print(f"{'PID':<5}{'NAME':<6}{'BURST':>6}{'PRIORITY':>9}{'ARRIVAL':>8}  OWNER")
            for p in self.workload.values():
                print(f"{p.pid:<5}{p.name:<6}{p.burst:>6}{p.priority:>9}{p.arrival:>8}  "
                      f"{self.owners['proc'].get(p.name, '-')}")
            return 0

        if sub == "rm":
            if len(rest) != 1:
                self.error("proc: usage: proc rm NAME")
                return 1
            if rest[0] not in self.workload:
                self.error(f"proc: no process named '{rest[0]}'")
                return 1
            owner = self.owners["proc"].get(rest[0])
            if not self.owns_or_admin(owner):
                raise AccessDenied(f"process {rest[0]} belongs to {owner}")
            del self.workload[rest[0]]
            self.owners["proc"].pop(rest[0], None)
            print(f"Removed {rest[0]}")
            return 0

        if sub == "clear":
            self.clear_own_processes()
            print("Process table cleared." if self.user.is_admin
                  else f"Removed all processes owned by {self.user.name}.")
            return 0

        if sub == "demo":
            self.clear_own_processes()
            taken = [n for n, *_ in DEMO_WORKLOAD if n in self.workload]
            if taken:
                raise ShellError(f"demo names {', '.join(taken)} are used by another "
                                 f"user's processes")
            for name, burst, priority, arrival in DEMO_WORKLOAD:
                self.add_process(name, burst, priority, arrival)
                self.owners["proc"][name] = self.user.name
            print(f"Loaded demo workload ({len(DEMO_WORKLOAD)} processes).")
            return self.cmd_proc(["list"])

        self.error(f"proc: unknown subcommand '{sub}'. {usage}")
        return 1

    # ------------------------------------------------------------------
    # Deliverable 2: scheduling (sched)
    # ------------------------------------------------------------------
    def scheduler_busy(self):
        return self.active_run is not None and self.active_run.is_alive()

    def cmd_sched(self, args):
        usage = ("usage: sched rr QUANTUM [--tick S] | priority [--tick S] | "
                 "tick S | metrics | compare [Q ...] | status")
        if not args:
            self.error(f"sched: {usage}")
            return 1
        sub, rest = args[0], list(args[1:])

        # Optional --tick override for this run only
        tick = self.tick_seconds
        if "--tick" in rest:
            i = rest.index("--tick")
            try:
                tick = float(rest[i + 1])
                if tick < 0:
                    raise ValueError
            except (IndexError, ValueError):
                self.error("sched: --tick needs a non-negative number of seconds")
                return 1
            del rest[i:i + 2]
        # Optional --quiet: suppress the per-event log, show only the results
        log = print
        if "--quiet" in rest:
            rest.remove("--quiet")
            log = lambda _msg: None  # noqa: E731

        if sub == "tick":
            try:
                value = float(rest[0])
                if value < 0:
                    raise ValueError
            except (IndexError, ValueError):
                self.error("sched: usage: sched tick SECONDS (non-negative)")
                return 1
            self.tick_seconds = value
            print(f"One simulated tick now lasts {value:g} second(s).")
            return 0

        if sub == "status":
            if self.scheduler_busy():
                s = self.active_run.scheduler
                print(f"{s.name} running in background, clock t={s.clock}")
            else:
                print("No scheduler is running.")
            return 0

        if sub == "metrics":
            if self.last_result is None:
                self.error("sched: no completed scheduling run yet")
                return 1
            print(format_gantt(self.last_result))
            print(format_metrics(self.last_result))
            return 0

        if sub in ("rr", "priority", "compare"):
            if not self.workload:
                self.error("sched: process table is empty (use 'proc add' or 'proc demo')")
                return 1
            if self.scheduler_busy():
                self.error("sched: a scheduler is already running (see 'sched status')")
                return 1

        if sub == "compare":
            try:
                quanta = [self.parse_int(q, "time slice", 1) for q in rest] or [1, 2, 4, 8]
            except ValueError as e:
                self.error(f"sched: {e}")
                return 1
            print(format_comparison(compare(list(self.workload.values()), quanta)))
            return 0

        if sub == "rr":
            if len(rest) != 1:
                self.error("sched: usage: sched rr QUANTUM [--tick SECONDS]")
                return 1
            try:
                quantum = self.parse_int(rest[0], "time slice", 1)
            except ValueError as e:
                self.error(f"sched: {e}")
                return 1
            scheduler = RoundRobinScheduler(list(self.workload.values()), quantum,
                                            tick_seconds=tick, log=log)
        elif sub == "priority":
            if rest:
                self.error("sched: usage: sched priority [--tick SECONDS]")
                return 1
            scheduler = PriorityScheduler(list(self.workload.values()),
                                          tick_seconds=tick, log=log)
        else:
            self.error(f"sched: unknown subcommand '{sub}'. {usage}")
            return 1

        if self._background_builtin:
            print(f"[sched] {scheduler.name} running in background; "
                  f"'proc add' injects new processes", flush=True)
            self.active_run = BackgroundRun(scheduler, self.scheduler_finished)
            self.active_run.start()
            time.sleep(0.05)     # let the first events print before the prompt
            return 0

        try:
            result = scheduler.run()
        except KeyboardInterrupt:
            print("\nmyshell: scheduling interrupted")
            return 130
        self.last_result = result
        print(format_gantt(result))
        print(format_metrics(result))
        return 0

    def scheduler_finished(self, run):
        if run.error is not None:
            self.error(f"sched: {run.error}")
            return
        self.last_result = run.result
        print(format_gantt(run.result))
        print(format_metrics(run.result))
        print("[sched] background scheduling finished ('sched metrics' to view again)")
        # Re-display the prompt, like a shell's asynchronous job notification.
        sys.stdout.write(self.prompt())
        sys.stdout.flush()


    # ------------------------------------------------------------------
    # Deliverable 3: memory management (mem)
    # ------------------------------------------------------------------
    @staticmethod
    def parse_options(args, spec):
        """Split '--name value' and '--flag' options from positional args.
        spec maps option name -> type (int, str, or bool for a flag)."""
        opts, rest, i = {}, [], 0
        while i < len(args):
            a = args[i]
            if a.startswith("--"):
                name = a[2:]
                if name not in spec:
                    raise ValueError(f"unknown option '{a}'")
                if spec[name] is bool:
                    opts[name] = True
                    i += 1
                    continue
                if i + 1 >= len(args):
                    raise ValueError(f"option '{a}' needs a value")
                try:
                    opts[name] = spec[name](args[i + 1])
                except ValueError:
                    raise ValueError(f"option '{a}' needs a number, got '{args[i + 1]}'")
                i += 2
            else:
                rest.append(a)
                i += 1
        return opts, rest

    @staticmethod
    def parse_pages(tokens):
        try:
            pages = [int(t) for t in tokens]
        except ValueError:
            raise ValueError("page numbers must be integers")
        if any(p < 0 for p in pages):
            raise ValueError("page numbers must be >= 0")
        return pages

    def cmd_mem(self, args):
        usage = ("usage: mem init|alloc|free|access|trace|policy|status|demo|refs|"
                 "compare (see 'help')")
        if not args:
            self.error(f"mem: {usage}")
            return 1
        sub, rest = args[0], list(args[1:])
        mm = self.memory
        try:
            if sub in ("init", "policy", "demo"):
                self.require_admin("reconfigure the shared physical memory")
            if sub == "init":
                opts, rest = self.parse_options(rest, {"policy": str})
                if not 1 <= len(rest) <= 2:
                    raise ValueError("usage: mem init FRAMES [PAGE_KB] [--policy fifo|lru]")
                frames = self.parse_int(rest[0], "number of frames", 1)
                page_kb = self.parse_int(rest[1], "page size (KB)", 1) if len(rest) > 1 else 4
                policy = opts.get("policy", mm.policy.name).lower()
                if policy not in ("fifo", "lru"):
                    raise ValueError("policy must be fifo or lru")
                self.memory = MemoryManager(frames, page_kb * 1024, policy)
                self.owners["mem"].clear()
                print(f"Physical memory: {frames} frames x {page_kb} KB = "
                      f"{frames * page_kb} KB, replacement policy {policy.upper()}")
                return 0

            if sub == "policy":
                if len(rest) != 1:
                    raise ValueError("usage: mem policy fifo|lru")
                mm.set_policy(rest[0])
                print(f"Page replacement policy set to {mm.policy.name}")
                return 0

            if sub == "alloc":
                if len(rest) != 2:
                    raise ValueError("usage: mem alloc NAME PAGES")
                mm.allocate(rest[0], self.parse_int(rest[1], "number of pages", 1))
                self.owners["mem"][rest[0]] = self.user.name
                return 0

            if sub == "free":
                if len(rest) != 1:
                    raise ValueError("usage: mem free NAME")
                self.check_mem_owner(rest[0])
                mm.free(rest[0])
                self.owners["mem"].pop(rest[0], None)
                return 0

            if sub == "access":
                if len(rest) < 2:
                    raise ValueError("usage: mem access NAME PAGE [PAGE ...]")
                self.check_mem_owner(rest[0])
                for page in self.parse_pages(rest[1:]):
                    mm.access(rest[0], page)
                print(mm.frame_table())
                return 0

            if sub == "trace":
                if not rest:
                    raise ValueError("usage: mem trace NAME:PAGE [NAME:PAGE ...]")
                self.run_trace(rest)
                print(mm.frame_table())
                return 0

            if sub == "status":
                print(mm.status())
                return 0

            if sub == "demo":
                policy = rest[0].lower() if rest else "fifo"
                if policy not in ("fifo", "lru") or len(rest) > 1:
                    raise ValueError("usage: mem demo [fifo|lru]")
                self.memory = MemoryManager(4, 4096, policy)
                self.owners["mem"].clear()
                print(f"Physical memory: 4 frames x 4 KB = 16 KB, policy {policy.upper()}")
                for name, pages in MEM_DEMO_PROCS:
                    self.memory.allocate(name, pages)
                    self.owners["mem"][name] = self.user.name
                self.run_trace(MEM_DEMO_TRACE)
                print(self.memory.status())
                return 0

            if sub == "refs":
                if len(rest) < 3:
                    raise ValueError("usage: mem refs FRAMES fifo|lru|opt PAGE [PAGE ...]")
                frames = self.parse_int(rest[0], "number of frames", 1)
                policy = rest[1].lower()
                if policy not in ("fifo", "lru", "opt"):
                    raise ValueError("policy must be fifo, lru, or opt")
                refs = (TEXTBOOK_REFS if rest[2:] == ["textbook"]
                        else self.parse_pages(rest[2:]))
                print(format_trace(refs, frames, policy)[0])
                return 0

            if sub == "compare":
                frames = list(range(1, 8))
                if "--frames" in rest:
                    i = rest.index("--frames")
                    try:
                        lo, hi = (int(x) for x in rest[i + 1].split("-"))
                        if lo < 1 or hi < lo:
                            raise ValueError
                    except (IndexError, ValueError):
                        raise ValueError("--frames needs a range such as 1-7")
                    frames = list(range(lo, hi + 1))
                    del rest[i:i + 2]
                if not rest:
                    raise ValueError("usage: mem compare [--frames A-B] PAGE [PAGE ...]")
                refs = TEXTBOOK_REFS if rest == ["textbook"] else self.parse_pages(rest)
                print(mem_comparison(refs, frames))
                return 0
        except (ValueError, MemoryError_) as e:
            self.error(f"mem: {e}")
            return 1
        self.error(f"mem: unknown subcommand '{sub}'. {usage}")
        return 1

    def run_trace(self, tokens):
        """Run NAME:PAGE references in order (validated before any is run)."""
        refs = []
        for tok in tokens:
            name, sep, page = tok.partition(":")
            if not sep or not page.isdigit():
                raise ValueError(f"bad reference '{tok}' (expected NAME:PAGE)")
            refs.append((name, int(page)))
        for name in {n for n, _ in refs}:
            self.check_mem_owner(name)
        for name, page in refs:
            self.memory.access(name, page)

    def check_mem_owner(self, name):
        """Memory protection: a user may touch only their own address spaces."""
        owner = self.owners["mem"].get(name)
        if name in self.memory.procs and not self.owns_or_admin(owner):
            raise AccessDenied(f"address space {name} belongs to {owner}")

    # ------------------------------------------------------------------
    # Deliverable 3: process synchronization (sync)
    # ------------------------------------------------------------------
    def cmd_sync(self, args):
        usage = "usage: sync race [THREADS] [ITERATIONS] | pc [options] | dining [options]"
        if not args:
            self.error(f"sync: {usage}")
            return 1
        sub, rest = args[0], list(args[1:])
        try:
            if sub == "race":
                if len(rest) > 2:
                    raise ValueError("usage: sync race [THREADS] [ITERATIONS]")
                threads = self.parse_int(rest[0], "threads", 2) if rest else 4
                iters = self.parse_int(rest[1], "iterations", 1) if len(rest) > 1 else 2000
                print(f"{threads} threads each increment a shared counter {iters} times "
                      f"(read -> yield -> write)")
                for label, use in (("WITHOUT mutex", False), ("WITH mutex", True)):
                    r = race_demo(threads, iters, use)
                    verdict = ("RACE CONDITION: lost updates" if r["lost"]
                               else "correct, no lost updates")
                    print(f"{label:<14} expected {r['expected']:>6}  actual {r['actual']:>6}  "
                          f"lost {r['lost']:>6}  ({verdict})")
                    if use:
                        print(f"{'':<14} mutex acquired {r['acquisitions']} times; a thread "
                              f"found it locked and waited {r['contended']} times")
                return 0

            if sub == "pc":
                opts, rest = self.parse_options(rest, {"producers": int, "consumers": int,
                                                       "items": int, "capacity": int,
                                                       "quiet": bool})
                if rest:
                    raise ValueError(f"unexpected argument '{rest[0]}'")
                for k in ("producers", "consumers", "items", "capacity"):
                    if k in opts and opts[k] < 1:
                        raise ValueError(f"--{k} must be at least 1")
                r = producer_consumer(opts.get("producers", 2), opts.get("consumers", 2),
                                      opts.get("items", 5), opts.get("capacity", 3),
                                      verbose=not opts.get("quiet", False))
                ok = (r["produced"] == r["consumed"] and not r["duplicates"]
                      and not r["lost"] and not r["violations"])
                print(f"Result: produced {r['produced']}, consumed {r['consumed']}, "
                      f"lost {r['lost']}, duplicated {r['duplicates']}, max occupancy "
                      f"{r['max_occupancy']}/{r['capacity']}")
                print(f"Blocking: producers blocked on 'empty' {r['producer_blocks']}x, "
                      f"consumers blocked on 'full' {r['consumer_blocks']}x, "
                      f"mutex contended {r['mutex_contended']}x")
                print("Verdict: " + ("buffer consistent, no race condition, no deadlock"
                                     if ok else "INCONSISTENT"))
                return 0

            if sub == "dining":
                opts, rest = self.parse_options(rest, {"n": int, "meals": int,
                                                       "naive": bool, "quiet": bool})
                if rest:
                    raise ValueError(f"unexpected argument '{rest[0]}'")
                n, meals = opts.get("n", 5), opts.get("meals", 3)
                if n < 2 or meals < 1:
                    raise ValueError("need --n >= 2 and --meals >= 1")
                r = dining_philosophers(n, meals, naive=opts.get("naive", False),
                                        verbose=not opts.get("quiet", False))
                print(f"Result: meals eaten {r['meals']} (target {meals} each), "
                      f"max eating at once {r['max_eating']} (limit {n // 2}), "
                      f"neighbor conflicts {r['neighbor_violations']}")
                if r["deadlock"]:
                    print("Verdict: DEADLOCK detected and run aborted "
                          "(circular wait on forks)")
                else:
                    print("Verdict: every philosopher finished, no deadlock, "
                          "no two neighbors ate at once")
                return 0
        except ValueError as e:
            self.error(f"sync: {e}")
            return 1
        self.error(f"sync: unknown subcommand '{sub}'. {usage}")
        return 1


if __name__ == "__main__":
    if os.name == "nt":
        print("myshell requires Linux, macOS, or WSL (POSIX signals).")
        sys.exit(1)
    Shell().run()
