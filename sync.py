#!/usr/bin/env python3
"""
sync.py - Advanced Shell Simulation, Deliverable 3: Process Synchronization

Synchronization primitives and classical problems used by myshell. Each
simulated process is a thread; the shared resources are Python objects that
all threads can reach (a shared counter, a bounded buffer, and forks).

  Mutex      - binary lock with an owner; only the owner may unlock it.
  Semaphore  - counting semaphore with wait()/signal() (Dijkstra's P/V),
               built from a lock and a condition variable.

Demonstrations
  race_demo            - shared counter updated with and without a mutex
  producer_consumer    - bounded buffer: semaphores `empty`/`full` + mutex
  dining_philosophers  - resource ordering prevents deadlock; the naive
                         left-then-right version deadlocks and is detected
"""

import random
import threading
import time
from collections import deque


# ----------------------------------------------------------------------
# Thread-safe event log
# ----------------------------------------------------------------------
class EventLog:
    def __init__(self, out=print, enabled=True):
        self.out = out
        self.enabled = enabled
        self.start = time.perf_counter()
        self._lock = threading.Lock()

    def __call__(self, who, message):
        if not self.enabled:
            return
        stamp = time.perf_counter() - self.start
        with self._lock:
            self.out(f"[{stamp:6.3f}s] {who:<12} {message}")


# ----------------------------------------------------------------------
# Primitives
# ----------------------------------------------------------------------
class Mutex:
    """Mutual-exclusion lock. Records contention so it can be reported."""

    def __init__(self, name="mutex"):
        self.name = name
        self._lock = threading.Lock()
        self.owner = None
        self.acquisitions = 0
        self.contended = 0
        self._stats = threading.Lock()

    def acquire(self, timeout=None):
        if not self._lock.acquire(blocking=False):
            with self._stats:
                self.contended += 1
            ok = self._lock.acquire(timeout=-1 if timeout is None else timeout)
            if not ok:
                return False
        self.owner = threading.current_thread().name
        with self._stats:
            self.acquisitions += 1
        return True

    def release(self):
        if self.owner != threading.current_thread().name:
            raise RuntimeError(f"{self.name}: released by a thread that does not own it")
        self.owner = None
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


class Semaphore:
    """Counting semaphore. wait() decrements and blocks while the value is 0;
    signal() increments and wakes one waiting thread."""

    def __init__(self, value, name="sem"):
        if value < 0:
            raise ValueError("semaphore value must be >= 0")
        self.name = name
        self.value = value
        self._cond = threading.Condition(threading.Lock())
        self.blocks = 0

    def wait(self, on_block=None):
        with self._cond:
            if self.value == 0:
                self.blocks += 1
                if on_block:
                    on_block()
                while self.value == 0:
                    self._cond.wait()
            self.value -= 1

    def signal(self):
        with self._cond:
            self.value += 1
            self._cond.notify()


# ----------------------------------------------------------------------
# 1. Race condition on shared memory
# ----------------------------------------------------------------------
def race_demo(threads=4, iterations=2000, use_mutex=False):
    """Each thread increments a shared counter `iterations` times using a
    read-modify-write sequence. time.sleep(0) between the read and the write
    yields the CPU, widening the window in which another thread can
    interleave - exactly what a preemptive scheduler can do at any time."""
    shared = {"counter": 0}
    lock = Mutex("counter_mutex") if use_mutex else None

    def worker():
        for _ in range(iterations):
            if lock:
                lock.acquire()
            value = shared["counter"]        # read
            time.sleep(0)                    # possible context switch
            shared["counter"] = value + 1    # write
            if lock:
                lock.release()

    workers = [threading.Thread(target=worker, name=f"T{i + 1}") for i in range(threads)]
    started = time.perf_counter()
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    elapsed = time.perf_counter() - started
    expected = threads * iterations
    return {"expected": expected, "actual": shared["counter"],
            "lost": expected - shared["counter"], "seconds": elapsed,
            "contended": lock.contended if lock else 0,
            "acquisitions": lock.acquisitions if lock else 0}


# ----------------------------------------------------------------------
# 2. Producer-Consumer (bounded buffer)
# ----------------------------------------------------------------------
class BoundedBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.items = deque()
        self.mutex = Mutex("buffer_mutex")
        self.empty = Semaphore(capacity, "empty")     # free slots
        self.full = Semaphore(0, "full")              # filled slots
        self.max_occupancy = 0
        self.violations = 0

    def snapshot(self):
        return "[" + " ".join(self.items) + "]" + f" {len(self.items)}/{self.capacity}"


def producer_consumer(producers=2, consumers=2, items=5, capacity=3,
                      produce_delay=0.02, consume_delay=0.06, seed=7, out=print,
                      verbose=True):
    log = EventLog(out, verbose)
    rng = random.Random(seed)
    delays = threading.Lock()
    buf = BoundedBuffer(capacity)
    produced, consumed = [], []
    record = threading.Lock()
    STOP = "<stop>"

    def jitter(base):
        with delays:
            return base * rng.uniform(0.5, 1.5)

    def put(who, item):
        buf.empty.wait(on_block=lambda: log(who, f"wait(empty) BLOCKS - buffer full "
                                                 f"{buf.snapshot()}"))
        with buf.mutex:                                # critical section
            buf.items.append(item)
            if len(buf.items) > buf.capacity:
                buf.violations += 1
            buf.max_occupancy = max(buf.max_occupancy, len(buf.items))
            if item != STOP:
                log(who, f"PRODUCE {item:<6} -> buffer {buf.snapshot()}")
        buf.full.signal()

    def take(who):
        buf.full.wait(on_block=lambda: log(who, f"wait(full)  BLOCKS - buffer empty"))
        with buf.mutex:                                # critical section
            item = buf.items.popleft()
            if item != STOP:
                log(who, f"CONSUME {item:<6} <- buffer {buf.snapshot()}")
        buf.empty.signal()
        return item

    def producer(i):
        who = f"Producer-{i}"
        for k in range(1, items + 1):
            time.sleep(jitter(produce_delay))           # produce the item
            item = f"P{i}.{k}"
            put(who, item)
            with record:
                produced.append(item)
        log(who, "finished")

    def consumer(j):
        who = f"Consumer-{j}"
        while True:
            item = take(who)
            if item == STOP:
                log(who, "received stop signal, exiting")
                return
            with record:
                consumed.append(item)
            time.sleep(jitter(consume_delay))           # consume the item

    log("main", f"START bounded buffer capacity={capacity}, {producers} producer(s) x "
                f"{items} items, {consumers} consumer(s); empty={capacity}, full=0, "
                f"mutex=unlocked")
    ps = [threading.Thread(target=producer, args=(i,), name=f"Producer-{i}")
          for i in range(1, producers + 1)]
    cs = [threading.Thread(target=consumer, args=(j,), name=f"Consumer-{j}")
          for j in range(1, consumers + 1)]
    started = time.perf_counter()
    for t in cs + ps:
        t.start()
    for t in ps:
        t.join()
    for _ in cs:                                       # one stop marker per consumer
        put("main", STOP)
    for t in cs:
        t.join()
    elapsed = time.perf_counter() - started
    return {
        "produced": len(produced), "consumed": len(consumed),
        "duplicates": len(consumed) - len(set(consumed)),
        "lost": len(set(produced) - set(consumed)),
        "max_occupancy": buf.max_occupancy, "capacity": capacity,
        "violations": buf.violations,
        "producer_blocks": buf.empty.blocks, "consumer_blocks": buf.full.blocks,
        "mutex_contended": buf.mutex.contended, "seconds": elapsed,
    }


# ----------------------------------------------------------------------
# 3. Dining Philosophers
# ----------------------------------------------------------------------
def dining_philosophers(n=5, meals=3, naive=False, think=0.02, eat=0.03,
                        grab_delay=0.05, seed=3, out=print, verbose=True,
                        deadlock_timeout=1.0):
    """Ordered mode (default): every philosopher picks up the lower-numbered
    fork first. This breaks the circular-wait condition, so deadlock cannot
    occur. Naive mode: left fork then right fork, with a pause in between so
    every philosopher can hold one fork - a circular wait. A watchdog detects
    the deadlock, reports the wait-for cycle, and aborts the run."""
    log = EventLog(out, verbose)
    rng = random.Random(seed)
    rng_lock = threading.Lock()
    forks = [Mutex(f"F{i}") for i in range(n)]
    holder = [None] * n
    eaten = [0] * n
    eating = [False] * n
    state = threading.Lock()
    waiting_for = {}
    abort = threading.Event()
    stats = {"max_eating": 0, "neighbor_violations": 0}

    def pause(base):
        with rng_lock:
            return base * rng.uniform(0.5, 1.5)

    def pick(i, f):
        who = f"Philosopher{i}"
        with state:
            waiting_for[i] = f
        while not forks[f].acquire(timeout=0.05):
            if abort.is_set():
                with state:
                    waiting_for.pop(i, None)
                return False
        if abort.is_set():                      # run aborted while we waited
            forks[f].release()
            with state:
                waiting_for.pop(i, None)
            return False
        with state:
            waiting_for.pop(i, None)
            holder[f] = i
        log(who, f"picks up F{f}")
        return True

    def put(i, f):
        with state:
            holder[f] = None
        forks[f].release()

    def philosopher(i):
        who = f"Philosopher{i}"
        left, right = i, (i + 1) % n
        first, second = (left, right) if naive else (min(left, right), max(left, right))
        while eaten[i] < meals and not abort.is_set():
            log(who, "thinking")
            time.sleep(pause(think))
            log(who, f"hungry, wants F{first} then F{second}")
            if not pick(i, first):
                log(who, f"run aborted, ate {eaten[i]} meal(s)")
                return
            if naive:
                time.sleep(grab_delay)          # widen the window for circular wait
            if not pick(i, second):
                put(i, first)
                log(who, f"run aborted: releases F{first}, ate {eaten[i]} meal(s)")
                return
            with state:                         # verify mutual exclusion on forks
                eating[i] = True
                if eating[(i - 1) % n] or eating[(i + 1) % n]:
                    stats["neighbor_violations"] += 1
                stats["max_eating"] = max(stats["max_eating"], sum(eating))
            eaten[i] += 1
            log(who, f"EATING meal {eaten[i]}/{meals} with F{first}+F{second}")
            time.sleep(pause(eat))
            with state:
                eating[i] = False
            put(i, second)
            put(i, first)
            log(who, f"puts down F{first} and F{second}")
        log(who, "done")

    def watchdog():
        stuck_since = None
        while not abort.is_set() and any(t.is_alive() for t in threads):
            with state:
                cycle = (len(waiting_for) == n and
                         all(holder[f] is not None for f in waiting_for.values()))
                snapshot = dict(waiting_for), list(holder)
            if cycle:
                stuck_since = stuck_since or time.perf_counter()
                if time.perf_counter() - stuck_since >= deadlock_timeout:
                    waits, held = snapshot
                    log("watchdog", f"DEADLOCK: no progress for {deadlock_timeout:.1f}s, "
                                    f"wait-for cycle:")
                    for i in sorted(waits):
                        mine = ",".join(f"F{f}" for f, h in enumerate(held) if h == i)
                        log("watchdog", f"  P{i} holds {mine or 'nothing'} and waits "
                                        f"for F{waits[i]} held by P{held[waits[i]]}")
                    stats["deadlock"] = True
                    abort.set()
                    return
            else:
                stuck_since = None
            time.sleep(0.02)

    mode = "naive (left then right)" if naive else "resource ordering (lower fork first)"
    log("main", f"START {n} philosophers, {meals} meal(s) each, strategy: {mode}")
    threads = [threading.Thread(target=philosopher, args=(i,), name=f"Philosopher{i}")
               for i in range(n)]
    started = time.perf_counter()
    for t in threads:
        t.start()
    wd = threading.Thread(target=watchdog, name="watchdog")
    wd.start()
    for t in threads:
        t.join()
    abort.set()
    wd.join()
    return {"meals": list(eaten), "deadlock": stats.get("deadlock", False),
            "max_eating": stats["max_eating"],
            "neighbor_violations": stats["neighbor_violations"],
            "seconds": time.perf_counter() - started, "n": n, "target": meals}
