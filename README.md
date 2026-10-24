# Advanced Shell Simulation — Final Integrated Shell (Deliverables 1–4)

A Python-based Unix-like shell demonstrating command execution, built-in utilities, foreground and background processes, job control (Deliverable 1), and an internal process scheduler with Round-Robin and preemptive Priority scheduling (Deliverable 2), memory management with paging plus process synchronization (Deliverable 3), and piping with user authentication and file permissions (Deliverable 4).

## Requirements
- Python 3.9 or later
- Linux, macOS, or Windows Subsystem for Linux (WSL)

> This project relies on POSIX signals and is not compatible with native Windows Command Prompt or PowerShell.

## Files
| File | Contents |
|---|---|
| `myshell.py` | The shell (Deliverable 1) extended with the `proc` and `sched` built-ins |
| `scheduler.py` | Process model, Round-Robin and Priority schedulers, timers, and metrics |
| `memory.py` | Paging system: frames, page tables, demand paging, FIFO/LRU (and OPT for analysis) |
| `sync.py` | Mutex, counting semaphore, race demo, Producer-Consumer, Dining Philosophers |
| `security.py` | Login (salted PBKDF2, lockout), roles, groups, rwx permissions, sandboxed file system, audit log |
| `pipeline.py` | Pipeline parsing, `<` `>` `>>` redirection, grep/sort/uniq/wc/head/tail |
| `test_scheduler.py` | Unit tests for Deliverable 2 |
| `test_security_pipes.py` | Unit and integration tests for Deliverable 4 |
| `test_memory_sync.py` | Unit tests for Deliverable 3 |

## Run
```bash
python3 myshell.py
python3 -m unittest -v test_security_pipes.py test_memory_sync.py test_scheduler.py   # all 54 tests
```

## Deliverable 1: built-in commands
`cd`, `pwd`, `exit`, `echo`, `clear`, `ls`, `cat`, `mkdir`, `rmdir`, `rm`, `touch`, `kill`, `jobs`, `fg`, `bg`, `stop`, `help`.

## Deliverable 2: process scheduling
The shell keeps a table of simulated processes and schedules them on a simulated CPU. One tick of CPU time is backed by `time.sleep()`; its length is configurable. Lower priority numbers mean higher priority.

| Command | Purpose |
|---|---|
| `proc add NAME BURST [PRIORITY] [ARRIVAL]` | Add a simulated process (defaults: priority 5, arrival 0) |
| `proc list` / `proc rm NAME` / `proc clear` / `proc demo` | Manage the process table or load the demo workload |
| `sched rr QUANTUM [--tick S]` | Round-Robin with a configurable time slice |
| `sched priority [--tick S]` | Preemptive Priority scheduling (heap, FCFS ties) |
| `sched ... &` | Run in the background; `proc add` then injects a process that can preempt |
| `sched ... --quiet` | Hide the event log; show only the Gantt chart and metrics |
| `sched tick S` | Set seconds per simulated tick (default 0.1) |
| `sched metrics` / `sched compare [Q ...]` / `sched status` | Show last results, compare policies, check a background run |

Each run prints an event log (ARRIVE, DISPATCH, PREEMPT, COMPLETE), a Gantt chart, and per-process response, waiting, and turnaround times with averages, CPU utilization, throughput, and context switches.

### Example
```text
proc demo
sched rr 2
sched rr 4 --tick 0.05
sched priority
sched compare 1 2 4 8
proc clear
proc add BATCH 6 5
proc add EDITOR 3 3
sched priority --tick 0.5 &
proc add URGENT 2 1          # typed while it runs: preempts BATCH
```

## Deliverable 3: memory management and synchronization
| Command | Purpose |
|---|---|
| `mem init FRAMES [PAGE_KB] [--policy fifo\|lru]` | Reset physical memory (default 4 frames x 4 KB, FIFO) |
| `mem alloc NAME PAGES` / `mem free NAME` | Allocate or deallocate a process's virtual pages |
| `mem access NAME PAGE ...` / `mem trace NAME:PAGE ...` | Reference pages; page faults load them, overflow triggers replacement |
| `mem policy fifo\|lru` / `mem status` | Switch policy; show frames, eviction order, per-process usage and faults |
| `mem demo [fifo\|lru]` | Three processes (9 pages) sharing 4 frames |
| `mem refs FRAMES fifo\|lru\|opt PAGE ...` | Step-by-step frame table (`textbook` = 7 0 1 2 0 3 0 4 2 3 0 3 2 1 2 0 1 7 0 1) |
| `mem compare [--frames A-B] PAGE ...` | Page faults for FIFO, LRU, and OPT |
| `sync race [THREADS] [ITERATIONS]` | Shared counter without vs with a mutex |
| `sync pc [--producers N] [--consumers N] [--items N] [--capacity N] [--quiet]` | Producer-Consumer bounded buffer |
| `sync dining [--n N] [--meals N] [--naive] [--quiet]` | Dining Philosophers (resource ordering; `--naive` shows detected deadlock) |

## Deliverable 4: login, permissions, and pipes
The shell starts at a `login:` prompt. On first run it creates `myshell_data/` (user database and
permission metadata) and the sandboxed file system `myshell_fs/` ("/" inside the shell). Delete both to reset.

| User | Role | Groups | Demo password |
|---|---|---|---|
| admin | admin | admin, staff | `Admin@MSCS630` |
| alice | standard | staff | `Alice@MSCS630` |
| bob | standard | staff | `Bob@MSCS630` |
| guest | standard | guests | `Guest@MSCS630` |

Three failed logins lock an account for 60 seconds. Change the demo passwords with `passwd`.

| Command | Purpose |
|---|---|
| `cmd1 \| cmd2 \| ...`, `< file`, `> file`, `>> file` | Pipes and redirection |
| `grep sort uniq wc head tail` | Filters for pipelines |
| `whoami`, `id`, `users`, `passwd`, `su USER`, `logout` | Identity and sessions |
| `useradd NAME admin\|standard`, `userdel NAME`, `chown` | Admin only |
| `chmod MODE FILE` | Owner or admin (octal or u+x style) |
| `run SCRIPT` or `./SCRIPT` | Run a script (needs read + execute) |

Examples:
```text
ls /shared | grep txt
cat /shared/server.log | grep ERROR | sort
sched rr 2 --tick 0 | grep COMPLETE
echo hacked > /system/config      # denied for standard users
cat /var/log/auth.log | grep DENIED   # admin only
```

## Report
See `docs/` for the APA 7 reports in Word format, including terminal execution figures.

## Limitations
This is an educational shell, not a full Bash replacement. It does not support full terminal foreground-process-group control. Pipes use a string model (stages run one after another). Permissions are enforced by the shell over its sandbox, so host programs run with real OS rights; standard users may only run sleep, date, seq, uname, true, and false. The scheduler schedules simulated processes rather than host processes, so that results are repeatable; context switches are counted but cost no time.
