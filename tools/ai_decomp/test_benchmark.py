#!/usr/bin/env python3

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import benchmark as benchmark_mod
import benchmark_report as report_mod

ROOT = HERE.parents[1]
MANIFEST = ROOT / "tools" / "ai_decomp" / "benchmark_10.json"
DB_PATH = ROOT / "tools" / "ai_decomp" / "decomp.db"


class BenchmarkManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with MANIFEST.open("r", encoding="utf-8") as f:
            cls.manifest = json.load(f)

        cls.db = sqlite3.connect(DB_PATH)
        cls.db.row_factory = sqlite3.Row

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_manifest_shape(self):
        self.assertEqual(self.manifest["version"], 1)
        self.assertEqual(self.manifest["phase"], "5.6")
        self.assertEqual(self.manifest["selection"], "frozen_deterministic")
        self.assertEqual(self.manifest["count"], 10)
        self.assertEqual(len(self.manifest["functions"]), 10)

    def test_ranks_are_contiguous(self):
        ranks = [x["rank"] for x in self.manifest["functions"]]
        self.assertEqual(ranks, list(range(1, 11)))

    def test_addresses_are_unique(self):
        addresses = [x["address"] for x in self.manifest["functions"]]
        self.assertEqual(len(addresses), len(set(addresses)))

    def test_functions_exist_and_are_eligible(self):
        for item in self.manifest["functions"]:
            row = self.db.execute(
                """
                SELECT address, name, size, status, is_thunk, is_external
                FROM functions
                WHERE address = ?
                """,
                (item["address"],),
            ).fetchone()

            self.assertIsNotNone(
                row,
                f'missing benchmark function {item["address"]}',
            )

            self.assertEqual(row["name"], item["name"])
            self.assertEqual(row["size"], item["size"])

            # selection-time status is recorded in the manifest; the
            # live database status legitimately advances afterwards
            self.assertIn(
                item["status_at_selection"],
                {"unknown", "candidate", "review", "blocked"},
                f'{item["address"]} selection status '
                f'{item["status_at_selection"]}',
            )
            self.assertEqual(row["is_thunk"], 0)
            self.assertEqual(row["is_external"], 0)

            self.assertFalse(
                (row["name"] or "").startswith("__"),
                f'{item["address"]} looks like a runtime helper',
            )

    def test_known_phase_5_target_is_not_benchmark(self):
        addresses = {
            x["address"] for x in self.manifest["functions"]
        }
        self.assertNotIn("801b16b0", addresses)


class ManifestValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        # minimal functions table for validation queries
        self.conn.execute(
            "CREATE TABLE functions (address TEXT PRIMARY KEY, "
            "name TEXT)")
        for addr, name in (("80200000", "F%d" % i)
                           for i, in enumerate(())):
            pass
        for i in range(12):
            self.conn.execute(
                "INSERT OR IGNORE INTO functions VALUES (?, ?)",
                ("%08x" % (0x80200000 + i), "F%d" % i))

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def manifest(self, count=10, addresses=None, extra=None,
                 drop_field=None, archetype="small_leaf"):
        addresses = addresses or [
            "%08x" % (0x80200000 + i) for i in range(count)]
        functions = []
        for i, addr in enumerate(addresses):
            entry = {"rank": i + 1, "address": addr,
                     "name": "F%d" % i, "size": 64,
                     "archetype": archetype,
                     "status_at_selection": "unknown"}
            if extra:
                entry.update(extra)
            if drop_field:
                entry.pop(drop_field, None)
            functions.append(entry)
        return {"version": 1, "phase": "5.6", "count": count,
                "selection": "frozen_deterministic",
                "functions": functions}

    def write(self, manifest):
        path = os.path.join(self.tmp, "m.json")
        with open(path, "w") as f:
            json.dump(manifest, f)
        return path

    def test_valid_manifest_passes(self):
        m = self.manifest(10)
        self.assertTrue(benchmark_mod.validate_manifest(m, self.conn))
        # loading round-trips
        loaded = benchmark_mod.load_manifest(self.write(m))
        self.assertEqual(len(loaded["functions"]), 10)

    def test_wrong_count_rejected(self):
        for count in (9, 11):
            with self.assertRaises(benchmark_mod.ManifestError):
                benchmark_mod.validate_manifest(
                    self.manifest(count), self.conn, count=10)

    def test_duplicate_address_rejected(self):
        addresses = ["%08x" % (0x80200000 + i) for i in range(9)]
        addresses.append(addresses[0])  # duplicate, still 10 entries
        with self.assertRaisesRegex(benchmark_mod.ManifestError,
                                    "duplicate"):
            benchmark_mod.validate_manifest(
                self.manifest(10, addresses=addresses), self.conn)

    def test_missing_address_rejected(self):
        addresses = ["%08x" % (0x80200000 + i) for i in range(9)]
        addresses.append("80999999")  # not in the analyzed set
        with self.assertRaisesRegex(benchmark_mod.ManifestError,
                                    "not present"):
            benchmark_mod.validate_manifest(
                self.manifest(10, addresses=addresses), self.conn)

    def test_missing_metadata_rejected(self):
        with self.assertRaisesRegex(benchmark_mod.ManifestError,
                                    "missing required field"):
            benchmark_mod.validate_manifest(
                self.manifest(10, drop_field="archetype"), self.conn)

    def test_malformed_archetype_rejected(self):
        with self.assertRaisesRegex(benchmark_mod.ManifestError,
                                    "archetype"):
            benchmark_mod.validate_manifest(
                self.manifest(10, archetype="banana"), self.conn)

    def test_name_mismatch_rejected(self):
        m = self.manifest(10)
        m["functions"][3]["name"] = "Renamed"
        with self.assertRaisesRegex(benchmark_mod.ManifestError,
                                    "name mismatch"):
            benchmark_mod.validate_manifest(m, self.conn)

    def test_deterministic_ordering(self):
        addresses = ["%08x" % (0x80200000 + i) for i in range(10)]
        m = self.manifest(10, addresses=addresses)
        benchmark_mod.validate_manifest(m, self.conn)
        m2 = json.loads(json.dumps(m))
        m2["functions"].reverse()
        # validation is order-independent; ranks recorded stay as-is
        self.assertTrue(benchmark_mod.validate_manifest(m2, self.conn))


class ReportMathTests(unittest.TestCase):
    def test_improvement_with_nulls(self):
        self.assertEqual(
            report_mod.improvement(73.33, None), None)
        self.assertEqual(
            report_mod.improvement(None, 50.0), None)
        self.assertAlmostEqual(
            report_mod.improvement(73.33, 100.0), 26.67, places=2)
        self.assertEqual(
            report_mod.improvement(50.0, 50.0), 0.0)

    def test_unavailable_not_treated_as_zero(self):
        agg = report_mod.aggregate([
            {"baseline": None, "best": None, "delta": None},
            {"baseline": 50.0, "best": 75.0, "delta": 25.0},
        ])
        self.assertEqual(agg["average_baseline"], 50.0)
        self.assertEqual(agg["average_best"], 75.0)
        self.assertEqual(agg["improvement_samples"], 1)
        self.assertEqual(agg["average_improvement"], 25.0)

    def test_aggregate_counts(self):
        results = [
            {"classification": "matching", "attempts": 1,
             "build_success": True, "reached_100": False,
             "regressions": 0, "baseline": 73.33, "best": 85.0},
            {"classification": "objdiff_no_improvement",
             "attempts": 2, "build_success": True,
             "reached_100": False, "regressions": 0,
             "baseline": None, "best": None},
            {"classification": "llm_error", "attempts": 1,
             "build_success": False, "reached_100": False,
             "regressions": 0, "baseline": None, "best": None},
        ]
        agg = report_mod.aggregate(results)
        self.assertEqual(agg["functions"], 3)
        self.assertEqual(agg["improved"], 1)
        self.assertEqual(agg["unchanged"], 1)
        self.assertEqual(agg["llm_failures"], 1)
        self.assertEqual(agg["build_failures"], 1)
        self.assertEqual(agg["successful_builds"], 2)
        self.assertEqual(agg["reached_100"], 0)
        self.assertEqual(agg["total_attempts"], 4)

    def test_compare_per_function_verdicts(self):
        a = [{"address": "80000001", "name": "A", "best_match": 40.0,
              "classification": "matching", "attempts": 1,
              "build_success": True, "regressions": 0},
             {"address": "80000002", "name": "B",
              "classification": "compile_error", "attempts": 1,
              "build_success": False, "regressions": 0},
             {"address": "80000003", "name": "C", "best_match": 20.0,
              "classification": "matching", "attempts": 1,
              "build_success": True, "regressions": 0}]
        b = [{"address": "80000001", "name": "A", "best_match": 100.0,
              "classification": "ok", "attempts": 1,
              "build_success": True, "reached_100": True,
              "regressions": 0},
             {"address": "80000002", "name": "B", "best_match": 55.0,
              "classification": "matching", "attempts": 1,
              "build_success": True, "regressions": 0},
             {"address": "80000003", "name": "C",
              "classification": "no_edits", "attempts": 1,
              "build_success": False, "regressions": 0}]
        rows = report_mod.per_function(a, b)
        verdicts = {r["address"]: r["verdict"] for r in rows}
        self.assertEqual(verdicts["80000001"], "b_better")
        self.assertEqual(verdicts["80000002"], "b_better")
        self.assertEqual(verdicts["80000003"], "b_worse")
        summary = report_mod.summarize(a, b, rows)
        self.assertEqual(summary["successful_builds"], {"a": 2, "b": 2})
        self.assertEqual(summary["compile_success_rate"]["b"], 0.67)
        self.assertEqual(summary["verdicts"]["b_better"], 2)
        self.assertEqual(summary["verdicts"]["b_worse"], 1)

    def test_compare_missing_evidence_safe(self):
        rows = report_mod.per_function(
            [], [{"address": "80000001", "name": "X"}])
        self.assertEqual(rows[0]["verdict"], "both_unavailable")

    def test_report_formatting(self):
        results = [{"address": "801b16b0", "name": "NuFileRead__FiPvii",
                    "baseline": 73.33, "best": 85.0, "delta": 11.67,
                    "attempts": 1, "build": "OK",
                    "classification": "matching"}]
        text = report_mod.format_table(results)
        self.assertIn("801b16b0", text)
        self.assertIn("NuFileRead__FiPvii", text)
        self.assertIn("73.33", text)


if __name__ == "__main__":
    unittest.main()
