#!/usr/bin/env python3
"""
memory.py - Advanced Shell Simulation, Deliverable 3: Memory Management

A simulated paging system used by myshell.

  * Physical memory is a fixed number of equal-size page frames.
  * Each process is allocated a virtual address space measured in pages and
    receives a page table (virtual page -> frame, or None when not resident).
  * Pages are loaded on demand: the first reference to a non-resident page is
    a page fault. If a free frame exists the page is loaded into it;
    otherwise memory has overflowed and the active replacement policy picks a
    victim page to evict.
  * Replacement is global (a victim may belong to any process), as in Linux.

Replacement policies
--------------------
  FIFO - evict the page that was loaded into memory earliest.
  LRU  - evict the page whose most recent reference is oldest.
  OPT  - (analysis only) evict the page whose next use is farthest in the
         future (Belady's optimal algorithm); needs the full reference string,
         so it is used only as a lower bound when comparing FIFO and LRU.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

POLICIES = ("fifo", "lru")


# ----------------------------------------------------------------------
# Replacement policies
# ----------------------------------------------------------------------
class ReplacementPolicy:
    """Tracks resident pages (keys are (process, page) tuples) in eviction
    order: the first key in `self.order` is the next victim."""

    name = "base"

    def __init__(self):
        self.order = OrderedDict()

    def loaded(self, key):
        self.order[key] = None

    def referenced(self, key):
        pass

    def removed(self, key):
        self.order.pop(key, None)

    def victim(self, future=None):
        return next(iter(self.order))

    def queue(self):
        return list(self.order)


class FIFOPolicy(ReplacementPolicy):
    """Order = load order. A hit does not change the order."""
    name = "FIFO"


class LRUPolicy(ReplacementPolicy):
    """Order = recency. Every reference moves the page to the most-recent end."""
    name = "LRU"

    def referenced(self, key):
        self.order.move_to_end(key)


class OPTPolicy(ReplacementPolicy):
    """Belady's optimal policy; requires the future reference string."""
    name = "OPT"

    def victim(self, future=None):
        future = list(future or [])
        best, best_dist = None, -1
        for key in self.order:                      # ties -> earliest loaded
            dist = future.index(key) if key in future else float("inf")
            if dist > best_dist:
                best, best_dist = key, dist
            if dist == float("inf"):
                break
        return best


def make_policy(name):
    name = name.lower()
    if name == "fifo":
        return FIFOPolicy()
    if name == "lru":
        return LRUPolicy()
    if name == "opt":
        return OPTPolicy()
    raise ValueError(f"unknown replacement policy '{name}' (use fifo or lru)")


# ----------------------------------------------------------------------
# Process memory bookkeeping
# ----------------------------------------------------------------------
@dataclass
class ProcessMemory:
    name: str
    pid: int
    pages: int                                   # size of the virtual address space
    page_table: Dict[int, Optional[int]] = field(default_factory=dict)
    faults: int = 0
    hits: int = 0
    evicted: int = 0                             # pages of this process evicted
    peak_resident: int = 0

    def __post_init__(self):
        self.page_table = {p: None for p in range(self.pages)}

    @property
    def resident(self):
        return sum(1 for f in self.page_table.values() if f is not None)


@dataclass
class AccessResult:
    process: str
    page: int
    hit: bool
    frame: int
    evicted: Optional[tuple] = None              # (process, page) that was replaced


class MemoryError_(Exception):
    """Raised for invalid memory operations (reported by the shell)."""


# ----------------------------------------------------------------------
# Memory manager
# ----------------------------------------------------------------------
class MemoryManager:
    def __init__(self, frames=4, page_size=4096, policy="fifo",
                 log: Callable[[str], None] = print):
        if int(frames) < 1:
            raise MemoryError_("number of frames must be at least 1")
        if int(page_size) < 1:
            raise MemoryError_("page size must be positive")
        self.num_frames = int(frames)
        self.page_size = int(page_size)
        self.frames: List[Optional[tuple]] = [None] * self.num_frames
        self.policy = make_policy(policy)
        self.procs: Dict[str, ProcessMemory] = {}
        self.next_pid = 201
        self.log = log
        self.faults = 0
        self.hits = 0
        self.replacements = 0

    # Helpers -------------------------------------------------------------
    def kb(self, pages):
        size = pages * self.page_size
        return f"{size // 1024} KB" if size % 1024 == 0 else f"{size} B"

    @property
    def used_frames(self):
        return sum(1 for f in self.frames if f is not None)

    def free_frame(self):
        for i, owner in enumerate(self.frames):
            if owner is None:
                return i
        return None

    def set_policy(self, name):
        """Switch policy. Resident pages are kept; the new policy starts from
        the current eviction order (load order for FIFO, recency for LRU)."""
        new = make_policy(name)
        if isinstance(new, OPTPolicy):
            raise MemoryError_("OPT needs the future reference string; "
                               "use 'mem compare' for OPT")
        new.order = OrderedDict(self.policy.order)
        self.policy = new

    # Allocation / deallocation ------------------------------------------
    def allocate(self, name, pages):
        if name in self.procs:
            raise MemoryError_(f"process '{name}' already has memory allocated")
        if int(pages) < 1:
            raise MemoryError_("a process needs at least 1 page")
        proc = ProcessMemory(name, self.next_pid, int(pages))
        self.next_pid += 1
        self.procs[name] = proc
        self.log(f"ALLOC    {name} (pid {proc.pid}): {pages} virtual pages = "
                 f"{self.kb(proc.pages)}; page table created, 0 pages resident")
        return proc

    def free(self, name):
        proc = self.procs.pop(name, None)
        if proc is None:
            raise MemoryError_(f"no memory allocated for '{name}'")
        released = []
        for page, frame in proc.page_table.items():
            if frame is not None:
                self.frames[frame] = None
                self.policy.removed((name, page))
                released.append(frame)
        self.log(f"FREE     {name} (pid {proc.pid}): released "
                 f"{len(released)} frame(s) {sorted(released)}; "
                 f"{self.num_frames - self.used_frames}/{self.num_frames} frames free")
        return released

    # Address translation -------------------------------------------------
    def access(self, name, page, future: Sequence = None):
        proc = self.procs.get(name)
        if proc is None:
            raise MemoryError_(f"no memory allocated for '{name}'")
        if not 0 <= page < proc.pages:
            raise MemoryError_(f"segmentation fault: {name} has pages 0-"
                               f"{proc.pages - 1}, page {page} is invalid")
        key = (name, page)
        frame = proc.page_table[page]
        if frame is not None:                              # page hit
            proc.hits += 1
            self.hits += 1
            self.policy.referenced(key)
            self.log(f"HIT      {name}:{page} in frame {frame}")
            return AccessResult(name, page, True, frame)

        # Page fault
        proc.faults += 1
        self.faults += 1
        evicted = None
        frame = self.free_frame()
        if frame is not None:
            self.log(f"FAULT    {name}:{page} not resident -> loaded into free frame "
                     f"{frame} ({self.used_frames + 1}/{self.num_frames} used)")
        else:
            victim = self.policy.victim(future)
            vname, vpage = victim
            frame = self.procs[vname].page_table[vpage]
            self.procs[vname].page_table[vpage] = None
            self.procs[vname].evicted += 1
            self.policy.removed(victim)
            self.replacements += 1
            evicted = victim
            self.log(f"FAULT    {name}:{page} not resident, memory full -> "
                     f"{self.policy.name} evicts {vname}:{vpage} from frame {frame}")
        self.frames[frame] = key
        proc.page_table[page] = frame
        self.policy.loaded(key)
        proc.peak_resident = max(proc.peak_resident, proc.resident)
        return AccessResult(name, page, False, frame, evicted)

    # Reporting -----------------------------------------------------------
    def frame_table(self):
        cells = []
        for i, owner in enumerate(self.frames):
            cells.append(f"[{i}] {owner[0]}:{owner[1]}" if owner else f"[{i}] free")
        return "Frames: " + "  ".join(cells)

    def status(self):
        lines = [f"Physical memory: {self.num_frames} frames x {self.kb(1)} = "
                 f"{self.kb(self.num_frames)} | used {self.used_frames}/"
                 f"{self.num_frames} | policy {self.policy.name}",
                 self.frame_table(),
                 f"{self.policy.name} eviction order: " +
                 (" ".join(f"{n}:{p}" for n, p in self.policy.queue()) or "(empty)")]
        if self.procs:
            lines.append(f"{'PROC':<6}{'PID':>4}{'VIRT':>7}{'RESIDENT':>10}{'MEMORY':>9}"
                         f"{'PEAK':>6}{'FAULTS':>8}{'HITS':>6}{'EVICTED':>9}")
            for p in self.procs.values():
                lines.append(f"{p.name:<6}{p.pid:>4}{p.pages:>7}{p.resident:>10}"
                             f"{self.kb(p.resident):>9}{p.peak_resident:>6}"
                             f"{p.faults:>8}{p.hits:>6}{p.evicted:>9}")
        total = self.faults + self.hits
        rate = 100.0 * self.faults / total if total else 0.0
        lines.append(f"Totals: {total} references | {self.faults} page faults "
                     f"({rate:.1f}%) | {self.hits} hits | {self.replacements} replacements")
        return "\n".join(lines)


# ----------------------------------------------------------------------
# Reference-string simulation (single process), used for analysis
# ----------------------------------------------------------------------
def simulate(refs, frames, policy):
    """Run a reference string through `frames` frames.

    Returns (faults, steps) where each step is (page, frame contents, fault?,
    evicted page or None)."""
    mm = MemoryManager(frames, policy="fifo", log=lambda _m: None)
    mm.policy = make_policy(policy)
    pages = max(refs) + 1
    mm.allocate("T", pages)
    keys = [("T", r) for r in refs]
    steps = []
    for i, r in enumerate(refs):
        res = mm.access("T", r, future=keys[i + 1:])
        snapshot = [f[1] if f else None for f in mm.frames]
        steps.append((r, snapshot, not res.hit, res.evicted[1] if res.evicted else None))
    return mm.faults, steps


def format_trace(refs, frames, policy):
    faults, steps = simulate(refs, frames, policy)
    width = max(3, max(len(str(r)) for r in refs) + 2)
    head = "ref    " + "".join(str(r).rjust(width) for r in refs)
    rows = [head]
    for f in range(frames):
        cells = []
        for (_r, snap, fault, _ev) in steps:
            v = snap[f]
            cells.append(("-" if v is None else str(v)).rjust(width))
        rows.append(f"frame{f} " + "".join(cells))
    rows.append("fault  " + "".join(("F" if s[2] else ".").rjust(width) for s in steps))
    rows.append(f"{make_policy(policy).name}: {faults} page faults, "
                f"{len(refs) - faults} hits, fault rate {100 * faults / len(refs):.1f}%")
    return "\n".join(rows), faults


def compare_policies(refs, frame_counts, policies=("fifo", "lru", "opt")):
    return {pol: [simulate(refs, f, pol)[0] for f in frame_counts] for pol in policies}


def format_comparison(refs, frame_counts):
    data = compare_policies(refs, frame_counts)
    lines = [f"Page faults for {len(refs)} references: " + " ".join(map(str, refs)),
             "FRAMES " + "".join(f"{f:>6}" for f in frame_counts)]
    for pol, faults in data.items():
        lines.append(f"{pol.upper():<7}" + "".join(f"{x:>6}" for x in faults))
    return "\n".join(lines)
