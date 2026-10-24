#!/usr/bin/env python3
"""
test_memory_sync.py - unit tests for Deliverable 3.

Page-fault counts for the reference string 7 0 1 2 0 3 0 4 2 3 0 3 2 1 2 0 1 7 0 1
with three frames (FIFO 15, LRU 12, OPT 9) and Belady's anomaly string
1 2 3 4 1 2 5 1 2 3 4 5 (FIFO: 9 faults with 3 frames, 10 with 4) are the
standard textbook values (Silberschatz et al., 2018).

Run:  python3 -m unittest -v test_memory_sync.py
"""

import threading
import unittest

from memory import MemoryError_, MemoryManager, compare_policies, simulate
from sync import Mutex, Semaphore, dining_philosophers, producer_consumer, race_demo

TEXTBOOK = [7, 0, 1, 2, 0, 3, 0, 4, 2, 3, 0, 3, 2, 1, 2, 0, 1, 7, 0, 1]
BELADY = [1, 2, 3, 4, 1, 2, 5, 1, 2, 3, 4, 5]
quiet = lambda _m: None  # noqa: E731


class ReplacementTests(unittest.TestCase):
    def test_textbook_fault_counts(self):
        self.assertEqual(simulate(TEXTBOOK, 3, "fifo")[0], 15)
        self.assertEqual(simulate(TEXTBOOK, 3, "lru")[0], 12)
        self.assertEqual(simulate(TEXTBOOK, 3, "opt")[0], 9)

    def test_beladys_anomaly_fifo_only(self):
        r = compare_policies(BELADY, [3, 4])
        self.assertEqual(r["fifo"], [9, 10])           # more frames, MORE faults
        self.assertGreaterEqual(r["lru"][0], r["lru"][1])   # LRU is a stack algorithm

    def test_fifo_and_lru_choose_different_victims(self):
        # refs 1 2 3 1 4 with 3 frames: FIFO evicts 1 (oldest load),
        # LRU evicts 2 (1 was just used).
        self.assertEqual(simulate([1, 2, 3, 1, 4], 3, "fifo")[1][-1][3], 1)
        self.assertEqual(simulate([1, 2, 3, 1, 4], 3, "lru")[1][-1][3], 2)

    def test_opt_is_lower_bound(self):
        data = compare_policies(TEXTBOOK, range(1, 8))
        for i in range(7):
            self.assertLessEqual(data["opt"][i], data["fifo"][i])
            self.assertLessEqual(data["opt"][i], data["lru"][i])


class PagingTests(unittest.TestCase):
    def setUp(self):
        self.mm = MemoryManager(3, 4096, "fifo", log=quiet)

    def test_demand_paging_and_hits(self):
        self.mm.allocate("A", 4)
        self.assertEqual(self.mm.procs["A"].resident, 0)
        self.assertFalse(self.mm.access("A", 0).hit)          # page fault
        self.assertTrue(self.mm.access("A", 0).hit)
        self.assertEqual((self.mm.faults, self.mm.hits), (1, 1))

    def test_overflow_triggers_replacement_across_processes(self):
        self.mm.allocate("A", 2)
        self.mm.allocate("B", 2)
        for name, page in [("A", 0), ("A", 1), ("B", 0)]:
            self.mm.access(name, page)
        res = self.mm.access("B", 1)                          # memory full
        self.assertEqual(res.evicted, ("A", 0))
        self.assertIsNone(self.mm.procs["A"].page_table[0])
        self.assertEqual(self.mm.procs["A"].evicted, 1)
        self.assertEqual(self.mm.used_frames, 3)

    def test_free_releases_frames(self):
        self.mm.allocate("A", 2)
        self.mm.access("A", 0)
        self.mm.access("A", 1)
        self.assertEqual(sorted(self.mm.free("A")), [0, 1])
        self.assertEqual(self.mm.used_frames, 0)
        self.assertEqual(self.mm.policy.queue(), [])
        with self.assertRaises(MemoryError_):
            self.mm.access("A", 0)

    def test_invalid_access_is_segfault(self):
        self.mm.allocate("A", 2)
        with self.assertRaises(MemoryError_):
            self.mm.access("A", 2)
        with self.assertRaises(MemoryError_):
            self.mm.allocate("A", 1)

    def test_memory_usage_tracking(self):
        mm = MemoryManager(4, 4096, "lru", log=quiet)
        mm.allocate("A", 3)
        for p in (0, 1, 2):
            mm.access("A", p)
        self.assertEqual(mm.procs["A"].resident, 3)
        self.assertEqual(mm.procs["A"].peak_resident, 3)
        self.assertEqual(mm.kb(mm.procs["A"].resident), "12 KB")

    def test_frame_and_page_table_stay_consistent(self):
        mm = MemoryManager(2, 4096, "lru", log=quiet)
        mm.allocate("A", 3)
        mm.allocate("B", 3)
        for tok in "A0 B0 A1 A0 B2 B0 A2 B1 A0".split():
            mm.access(tok[0], int(tok[1]))
            for f, owner in enumerate(mm.frames):
                if owner:
                    self.assertEqual(mm.procs[owner[0]].page_table[owner[1]], f)
            self.assertEqual(len(mm.policy.queue()), mm.used_frames)


class SyncTests(unittest.TestCase):
    def test_mutex_prevents_lost_updates(self):
        r = race_demo(threads=4, iterations=500, use_mutex=True)
        self.assertEqual(r["actual"], r["expected"])

    def test_unsynchronized_counter_loses_updates(self):
        r = race_demo(threads=4, iterations=500, use_mutex=False)
        self.assertLess(r["actual"], r["expected"])

    def test_mutex_owner_check(self):
        m = Mutex()
        m.acquire()
        errors = []

        def other():
            try:
                m.release()
            except RuntimeError:
                errors.append(True)
        t = threading.Thread(target=other)
        t.start()
        t.join()
        self.assertEqual(errors, [True])
        m.release()

    def test_semaphore_blocks_at_zero(self):
        s = Semaphore(1)
        s.wait()
        done = threading.Event()
        t = threading.Thread(target=lambda: (s.wait(), done.set()))
        t.start()
        self.assertFalse(done.wait(0.2))                 # blocked while value is 0
        s.signal()
        self.assertTrue(done.wait(1.0))
        t.join()
        self.assertEqual(s.blocks, 1)

    def test_producer_consumer_consistency(self):
        for capacity in (1, 3):
            r = producer_consumer(producers=3, consumers=2, items=6, capacity=capacity,
                                  produce_delay=0.002, consume_delay=0.004, verbose=False)
            self.assertEqual(r["produced"], 18)
            self.assertEqual(r["consumed"], 18)
            self.assertEqual((r["lost"], r["duplicates"], r["violations"]), (0, 0, 0))
            self.assertLessEqual(r["max_occupancy"], capacity)

    def test_dining_ordered_no_deadlock(self):
        r = dining_philosophers(n=5, meals=3, verbose=False)
        self.assertFalse(r["deadlock"])
        self.assertEqual(r["meals"], [3] * 5)
        self.assertEqual(r["neighbor_violations"], 0)
        self.assertLessEqual(r["max_eating"], 2)

    def test_dining_naive_deadlock_detected(self):
        r = dining_philosophers(n=5, meals=3, naive=True, verbose=False,
                                deadlock_timeout=0.5)
        self.assertTrue(r["deadlock"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
