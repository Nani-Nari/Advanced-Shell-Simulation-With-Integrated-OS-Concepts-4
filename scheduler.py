#!/usr/bin/env python3
"""
scheduler.py - Advanced Shell Simulation, Deliverable 2: Process Scheduling

A simulated CPU scheduler used by myshell. It implements:

  * Round-Robin scheduling with a configurable time slice (quantum).
  * Preemptive Priority-Based scheduling backed by a binary heap (heapq),
    with First-Come, First-Served (FCFS) tie-breaking for equal priorities.

Time model
----------
The scheduler keeps a logical clock measured in "ticks". One tick is one
unit of CPU time. Every tick of simulated execution is backed by a real
timer, time.sleep(tick_seconds), so the shell visibly "runs" each process
for the duration of its slice. Metrics are computed from the logical clock
(arrival, first-run, and completion events), which makes the results exact
and repeatable regardless of host load; measured wall-clock time is reported
alongside them.

Priority convention: a LOWER number means a HIGHER priority (1 is the most
important), matching the Unix nice convention.

Metric definitions (all in ticks):
    turnaround = completion - arrival
    waiting    = turnaround - burst      (time spent ready but not running)
    response   = first_run - arrival
"""

import heapq
import itertools
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, List, Optional

IDLE = "idle"


# ----------------------------------------------------------------------
# Process model
# ----------------------------------------------------------------------
@dataclass
class SimProcess:
    """A simulated process (process control block) known to the scheduler."""

    name: str
    burst: int                     # total CPU time required, in ticks
    priority: int = 5              # lower number = higher priority
    arrival: int = 0               # tick at which the process becomes ready
    pid: int = 0                   # assigned by the process table
    seq: int = 0                   # admission order, used for FCFS ties

    # Runtime state (filled in by the scheduler)
    remaining: int = field(init=False)
    first_run: Optional[int] = field(default=None, init=False)
    completion: Optional[int] = field(default=None, init=False)
    state: str = field(default="NEW", init=False)

    def __post_init__(self):
        self.remaining = self.burst

    def fresh_copy(self):
        """Return an un-run copy so a workload can be scheduled repeatedly."""
        return SimProcess(self.name, self.burst, self.priority,
                          self.arrival, self.pid, self.seq)

    # Metrics ----------------------------------------------------------
    @property
    def turnaround(self):
        return self.completion - self.arrival

    @property
    def waiting(self):
        return self.turnaround - self.burst

    @property
    def response(self):
        return self.first_run - self.arrival


@dataclass
class ScheduleResult:
    """Everything a run produced: per-process records, timeline, metrics."""

    algorithm: str
    quantum: Optional[int]
    processes: List[SimProcess]
    gantt: List[tuple]             # (start_tick, end_tick, process name or IDLE)
    context_switches: int
    makespan: int
    wall_seconds: float

    def averages(self):
        n = len(self.processes)
        return {
            "waiting": sum(p.waiting for p in self.processes) / n,
            "turnaround": sum(p.turnaround for p in self.processes) / n,
            "response": sum(p.response for p in self.processes) / n,
        }

    @property
    def busy_ticks(self):
        return sum(e - s for s, e, n in self.gantt if n != IDLE)

    @property
    def cpu_utilization(self):
        return 100.0 * self.busy_ticks / self.makespan if self.makespan else 0.0

    @property
    def throughput(self):
        return len(self.processes) / self.makespan if self.makespan else 0.0


# ----------------------------------------------------------------------
# Scheduler base class
# ----------------------------------------------------------------------
class Scheduler:
    """Common machinery: clock, timer, arrivals, logging, and the Gantt chart."""

    name = "base"

    def __init__(self, processes, tick_seconds=0.1,
                 log: Callable[[str], None] = print):
        if not processes:
            raise ValueError("no processes to schedule")
        self.procs = [p.fresh_copy() for p in processes]
        # Processes not yet arrived, ordered by (arrival time, admission order).
        self.pending = deque(sorted(self.procs, key=lambda p: (p.arrival, p.seq)))
        self.tick_seconds = max(0.0, float(tick_seconds))
        self.log = log
        self.clock = 0
        self.gantt = []
        self.context_switches = 0
        self._last_dispatched = None
        # Processes injected while the scheduler is running (thread-safe).
        self._inbox = queue.Queue()
        self._seq = itertools.count(max(p.seq for p in self.procs) + 1)

    # Hooks implemented by each algorithm --------------------------------
    def enqueue(self, proc):
        raise NotImplementedError

    def has_ready(self):
        raise NotImplementedError

    def schedule(self):
        raise NotImplementedError

    # Shared helpers ------------------------------------------------------
    def emit(self, message):
        self.log(f"[t={self.clock:>3}] {message}")

    def inject(self, proc):
        """Add a process while the scheduler is running (called from the shell
        thread). It arrives at the scheduler's current clock time."""
        self._inbox.put(proc)

    def admit_arrivals(self):
        """Move every process whose arrival time has been reached into the
        ready structure, including processes injected live from the shell."""
        while True:
            try:
                proc = self._inbox.get_nowait()
            except queue.Empty:
                break
            proc = proc.fresh_copy()
            proc.arrival = self.clock
            proc.seq = next(self._seq)
            self.procs.append(proc)
            self.pending.append(proc)
            self.pending = deque(sorted(self.pending, key=lambda p: (p.arrival, p.seq)))
        arrived = []
        while self.pending and self.pending[0].arrival <= self.clock:
            proc = self.pending.popleft()
            proc.state = "READY"
            self.enqueue(proc)
            arrived.append(proc)
            self.emit(f"ARRIVE   {proc.name:<4} (pid {proc.pid}, burst {proc.burst}, "
                      f"priority {proc.priority})")
        return arrived

    def tick(self, proc):
        """Run `proc` on the simulated CPU for one tick, backed by a timer."""
        if self.tick_seconds:
            time.sleep(self.tick_seconds)          # simulated execution
        self.clock += 1
        proc.remaining -= 1

    def idle_until_next_arrival(self):
        nxt = self.pending[0].arrival if self.pending else self.clock + 1
        start = self.clock
        self.emit(f"IDLE     CPU idle until t={nxt}")
        while self.clock < nxt and self._inbox.empty():
            if self.tick_seconds:
                time.sleep(self.tick_seconds)
            self.clock += 1
        self.record(start, self.clock, IDLE)

    def dispatch(self, proc, note=""):
        if self._last_dispatched is not None and self._last_dispatched is not proc:
            self.context_switches += 1
        self._last_dispatched = proc
        proc.state = "RUNNING"
        if proc.first_run is None:
            proc.first_run = self.clock
        self.emit(f"DISPATCH {proc.name:<4} {note}".rstrip())

    def finish(self, proc, note=""):
        proc.state = "TERMINATED"
        proc.completion = self.clock
        self.emit(f"COMPLETE {proc.name:<4} {note}".rstrip())

    def record(self, start, end, name):
        if end <= start:
            return
        if self.gantt and self.gantt[-1][2] == name and self.gantt[-1][1] == start:
            self.gantt[-1] = (self.gantt[-1][0], end, name)
        else:
            self.gantt.append((start, end, name))

    def unfinished(self):
        return self.has_ready() or bool(self.pending) or not self._inbox.empty()

    def run(self):
        started = time.perf_counter()
        self.schedule()
        wall = time.perf_counter() - started
        return ScheduleResult(self.name, getattr(self, "quantum", None),
                              sorted(self.procs, key=lambda p: p.pid),
                              self.gantt, self.context_switches, self.clock, wall)


# ----------------------------------------------------------------------
# Round-Robin
# ----------------------------------------------------------------------
class RoundRobinScheduler(Scheduler):
    """FIFO ready queue; each dispatch runs for at most `quantum` ticks.

    A process that finishes inside its slice is removed immediately and the
    next process is dispatched without waiting for the slice to expire. A
    process whose slice expires is moved to the back of the ready queue.
    Processes that arrive during a slice are queued ahead of the preempted
    process (the common textbook convention).
    """

    name = "Round-Robin"

    def __init__(self, processes, quantum, **kwargs):
        if int(quantum) < 1:
            raise ValueError("time slice (quantum) must be a positive integer")
        self.quantum = int(quantum)
        self.ready = deque()
        super().__init__(processes, **kwargs)

    def enqueue(self, proc):
        self.ready.append(proc)

    def has_ready(self):
        return bool(self.ready)

    def queue_snapshot(self):
        return "[" + " ".join(p.name for p in self.ready) + "]"

    def schedule(self):
        self.emit(f"START    Round-Robin, time slice = {self.quantum} tick(s), "
                  f"1 tick = {self.tick_seconds:g}s")
        self.admit_arrivals()
        while self.unfinished():
            if not self.ready:
                self.idle_until_next_arrival()
                self.admit_arrivals()
                continue
            proc = self.ready.popleft()
            slice_len = min(self.quantum, proc.remaining)
            self.dispatch(proc, f"slice {self.quantum}, remaining {proc.remaining}, "
                                f"queue {self.queue_snapshot()}")
            start = self.clock
            for _ in range(slice_len):
                self.tick(proc)
                self.admit_arrivals()      # arrivals join the queue mid-slice
            self.record(start, self.clock, proc.name)
            if proc.remaining == 0:
                used = self.clock - start
                if used < self.quantum:
                    self.finish(proc, f"used {used}/{self.quantum} of its slice, "
                                      f"removed from queue early")
                else:
                    self.finish(proc, "finished at end of slice")
            else:
                proc.state = "READY"
                self.ready.append(proc)
                self.emit(f"PREEMPT  {proc.name:<4} time slice expired, remaining "
                          f"{proc.remaining} -> back of queue {self.queue_snapshot()}")
        self.emit("DONE     all processes completed")


# ----------------------------------------------------------------------
# Preemptive Priority
# ----------------------------------------------------------------------
class PriorityScheduler(Scheduler):
    """Preemptive priority scheduling with a min-heap.

    Heap keys are (priority, arrival, seq). The lowest priority number is
    selected first; equal priorities fall back to arrival time and then
    admission order, which is First-Come, First-Served. The scheduler checks
    for arrivals after every tick, so a newly arrived higher-priority process
    preempts the running process immediately.
    """

    name = "Priority (preemptive)"

    def __init__(self, processes, **kwargs):
        self.heap = []
        super().__init__(processes, **kwargs)

    @staticmethod
    def key(proc):
        return (proc.priority, proc.arrival, proc.seq)

    def enqueue(self, proc):
        heapq.heappush(self.heap, (self.key(proc), proc.pid, proc))

    def has_ready(self):
        return bool(self.heap)

    def heap_snapshot(self):
        items = sorted(self.heap)
        return "[" + " ".join(f"{p.name}:{p.priority}" for _, _, p in items) + "]"

    def schedule(self):
        self.emit(f"START    Priority (preemptive, lower number = higher priority), "
                  f"1 tick = {self.tick_seconds:g}s")
        self.admit_arrivals()
        current = None
        start = 0
        while current is not None or self.unfinished():
            # Preemption check: is a strictly higher-priority process ready?
            if current is not None and self.heap and \
                    self.heap[0][0] < self.key(current):
                challenger = self.heap[0][2]
                self.record(start, self.clock, current.name)
                current.state = "READY"
                self.enqueue(current)
                self.emit(f"PREEMPT  {current.name:<4} (priority {current.priority}) "
                          f"by {challenger.name} (priority {challenger.priority}), "
                          f"remaining {current.remaining}")
                current = None
            if current is None:
                if not self.heap:
                    self.idle_until_next_arrival()
                    self.admit_arrivals()
                    continue
                _, _, current = heapq.heappop(self.heap)
                start = self.clock
                self.dispatch(current, f"priority {current.priority}, remaining "
                                       f"{current.remaining}, heap {self.heap_snapshot()}")
            self.tick(current)
            if current.remaining == 0:
                self.record(start, self.clock, current.name)
                self.finish(current)
                current = None
            self.admit_arrivals()
        self.emit("DONE     all processes completed")


# ----------------------------------------------------------------------
# Reporting helpers
# ----------------------------------------------------------------------
def format_metrics(result: ScheduleResult) -> str:
    title = result.algorithm
    if result.quantum is not None:
        title += f" (time slice = {result.quantum})"
    lines = [f"Performance metrics - {title}  [units: ticks]",
             f"{'PID':<4}{'NAME':<6}{'ARR':>4}{'BURST':>6}{'PRI':>4}"
             f"{'START':>6}{'END':>5}{'RESP':>6}{'WAIT':>6}{'TAT':>5}"]
    for p in result.processes:
        lines.append(f"{p.pid:<4}{p.name:<6}{p.arrival:>4}{p.burst:>6}{p.priority:>4}"
                     f"{p.first_run:>6}{p.completion:>5}{p.response:>6}"
                     f"{p.waiting:>6}{p.turnaround:>5}")
    avg = result.averages()
    lines.append(f"{'AVG':<38}{avg['response']:>6.2f}{avg['waiting']:>6.2f}"
                 f"{avg['turnaround']:>5.1f}")
    lines.append(f"Makespan {result.makespan} ticks | CPU utilization "
                 f"{result.cpu_utilization:.1f}% | throughput "
                 f"{result.throughput:.3f} proc/tick")
    lines.append(f"Context switches {result.context_switches} | measured wall-clock "
                 f"time {result.wall_seconds:.2f}s")
    return "\n".join(lines)


def format_gantt(result: ScheduleResult) -> str:
    """Return a compact text Gantt chart of the CPU timeline."""
    bar, axis = "|", str(result.gantt[0][0]) if result.gantt else "0"
    for start, end, name in result.gantt:
        label = "--" if name == IDLE else name
        width = max(len(label) + 2, 4)
        bar += label.center(width) + "|"
        axis = axis.ljust(len(bar) - 1) + str(end)
    return "Gantt: " + bar + "\n       " + axis


def compare(processes, quanta=(1, 2, 4, 8)):
    """Run the same workload under every policy without sleeping (tick = 0)."""
    silent = lambda _msg: None  # noqa: E731
    results = [RoundRobinScheduler(processes, q, tick_seconds=0, log=silent).run()
               for q in quanta]
    results.append(PriorityScheduler(processes, tick_seconds=0, log=silent).run())
    return results


def format_comparison(results) -> str:
    lines = ["Policy comparison on the current workload  [units: ticks]",
             f"{'POLICY':<24}{'AVG WAIT':>9}{'AVG TAT':>9}{'AVG RESP':>9}"
             f"{'SWITCHES':>9}"]
    for r in results:
        label = f"RR q={r.quantum}" if r.quantum is not None else "Priority (preemptive)"
        a = r.averages()
        lines.append(f"{label:<24}{a['waiting']:>9.2f}{a['turnaround']:>9.2f}"
                     f"{a['response']:>9.2f}{r.context_switches:>9}")
    return "\n".join(lines)


class BackgroundRun(threading.Thread):
    """Runs a scheduler in a background thread so the shell stays interactive
    and new processes can be added (and preempt) while it is running."""

    def __init__(self, scheduler, on_done):
        super().__init__(daemon=True)
        self.scheduler = scheduler
        self.on_done = on_done
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.scheduler.run()
        except Exception as e:  # report instead of killing the thread silently
            self.error = e
        self.on_done(self)
