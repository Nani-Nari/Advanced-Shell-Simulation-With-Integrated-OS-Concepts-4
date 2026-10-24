#!/usr/bin/env python3
"""
test_scheduler.py - unit tests for Deliverable 2 (Process Scheduling).

Expected values were worked out by hand from the textbook definitions:
    turnaround = completion - arrival, waiting = turnaround - burst,
    response = first run - arrival.

Run:  python3 -m unittest -v test_scheduler.py
"""

import time
import unittest

from scheduler import (IDLE, PriorityScheduler, RoundRobinScheduler,
                       SimProcess, compare)


def workload(spec):
    """spec: list of (name, burst, priority, arrival)."""
    return [SimProcess(n, b, p, a, pid=i + 1, seq=i + 1)
            for i, (n, b, p, a) in enumerate(spec)]


DEMO = workload([("P1", 5, 2, 0), ("P2", 3, 1, 1), ("P3", 8, 4, 2),
                 ("P4", 2, 1, 3), ("P5", 6, 2, 4)])

quiet = dict(tick_seconds=0, log=lambda _m: None)


def by_name(result):
    return {p.name: p for p in result.processes}


class RoundRobinTests(unittest.TestCase):
    def test_classic_example_quantum_2(self):
        # Three processes arriving at 0 with bursts 5, 3, 1 and q = 2.
        # Timeline: A0-2 B2-4 C4-5 A5-7 B7-8 A8-9
        r = RoundRobinScheduler(workload([("A", 5, 1, 0), ("B", 3, 1, 0),
                                          ("C", 1, 1, 0)]), 2, **quiet).run()
        self.assertEqual(r.gantt, [(0, 2, "A"), (2, 4, "B"), (4, 5, "C"),
                                   (5, 7, "A"), (7, 8, "B"), (8, 9, "A")])
        p = by_name(r)
        self.assertEqual([p[x].completion for x in "ABC"], [9, 8, 5])
        self.assertEqual([p[x].waiting for x in "ABC"], [4, 5, 4])
        self.assertEqual([p[x].response for x in "ABC"], [0, 2, 4])

    def test_early_completion_frees_cpu_immediately(self):
        # C needs 1 tick of a 4-tick slice; the next process starts at t=1.
        r = RoundRobinScheduler(workload([("C", 1, 1, 0), ("D", 2, 1, 0)]),
                                4, **quiet).run()
        self.assertEqual(r.gantt, [(0, 1, "C"), (1, 3, "D")])

    def test_quantum_is_configurable(self):
        small = RoundRobinScheduler(DEMO, 1, **quiet).run()
        large = RoundRobinScheduler(DEMO, 8, **quiet).run()
        self.assertGreater(small.context_switches, large.context_switches)
        self.assertLess(small.averages()["response"], large.averages()["response"])

    def test_demo_workload_quantum_2(self):
        r = RoundRobinScheduler(DEMO, 2, **quiet).run()
        p = by_name(r)
        self.assertEqual({k: v.completion for k, v in p.items()},
                         {"P1": 16, "P2": 13, "P3": 24, "P4": 10, "P5": 22})
        self.assertAlmostEqual(r.averages()["waiting"], 10.2)

    def test_invalid_quantum(self):
        with self.assertRaises(ValueError):
            RoundRobinScheduler(DEMO, 0, **quiet)

    def test_idle_gap(self):
        r = RoundRobinScheduler(workload([("A", 2, 1, 0), ("B", 1, 1, 5)]),
                                2, **quiet).run()
        self.assertEqual(r.gantt, [(0, 2, "A"), (2, 5, IDLE), (5, 6, "B")])
        self.assertAlmostEqual(r.cpu_utilization, 50.0)


class PriorityTests(unittest.TestCase):
    def test_demo_workload(self):
        # t0 P1 | t1 P2 preempts P1 | t3 P4 (same priority as P2) waits: FCFS
        # t4 P4 | t6 P1 before P5 (both priority 2, P1 arrived first)
        r = PriorityScheduler(DEMO, **quiet).run()
        self.assertEqual(r.gantt, [(0, 1, "P1"), (1, 4, "P2"), (4, 6, "P4"),
                                   (6, 10, "P1"), (10, 16, "P5"), (16, 24, "P3")])
        p = by_name(r)
        self.assertEqual({k: v.waiting for k, v in p.items()},
                         {"P1": 5, "P2": 0, "P3": 14, "P4": 1, "P5": 6})
        self.assertEqual({k: v.response for k, v in p.items()},
                         {"P1": 0, "P2": 0, "P3": 14, "P4": 1, "P5": 6})

    def test_equal_priority_is_fcfs(self):
        r = PriorityScheduler(workload([("X", 2, 3, 0), ("Y", 2, 3, 0),
                                        ("Z", 2, 3, 0)]), **quiet).run()
        self.assertEqual([g[2] for g in r.gantt], ["X", "Y", "Z"])

    def test_equal_priority_arrival_does_not_preempt(self):
        r = PriorityScheduler(workload([("X", 4, 2, 0), ("Y", 1, 2, 1)]),
                              **quiet).run()
        self.assertEqual(r.gantt, [(0, 4, "X"), (4, 5, "Y")])

    def test_higher_priority_arrival_preempts_immediately(self):
        r = PriorityScheduler(workload([("LOW", 5, 9, 0), ("HIGH", 2, 1, 2)]),
                              **quiet).run()
        self.assertEqual(r.gantt, [(0, 2, "LOW"), (2, 4, "HIGH"), (4, 7, "LOW")])

    def test_live_injection_preempts(self):
        # A process added from another thread while running preempts.
        s = PriorityScheduler(workload([("BG", 6, 5, 0)]), tick_seconds=0.05,
                              log=lambda _m: None)
        import threading
        t = threading.Thread(target=lambda: (time.sleep(0.12),
                                             s.inject(SimProcess("URG", 1, 1, 0, pid=9))))
        t.start()
        r = s.run()
        t.join()
        names = [g[2] for g in r.gantt]
        self.assertEqual(names, ["BG", "URG", "BG"])
        self.assertEqual(by_name(r)["URG"].response, 0)


class TimerAndMetricTests(unittest.TestCase):
    def test_timer_drives_execution(self):
        start = time.perf_counter()
        RoundRobinScheduler(workload([("A", 4, 1, 0)]), 2,
                            tick_seconds=0.05, log=lambda _m: None).run()
        self.assertGreaterEqual(time.perf_counter() - start, 0.19)

    def test_metric_identities(self):
        for r in compare(DEMO, (1, 2, 3, 4, 8)):
            for p in r.processes:
                self.assertEqual(p.turnaround, p.completion - p.arrival)
                self.assertEqual(p.waiting, p.turnaround - p.burst)
                self.assertGreaterEqual(p.waiting, p.response)
            self.assertEqual(r.busy_ticks, sum(p.burst for p in DEMO))

    def test_workload_reusable(self):
        a = PriorityScheduler(DEMO, **quiet).run()
        b = PriorityScheduler(DEMO, **quiet).run()
        self.assertEqual(a.gantt, b.gantt)
        self.assertTrue(all(p.remaining == p.burst for p in DEMO))


if __name__ == "__main__":
    unittest.main(verbosity=2)
