"""Tests for the v0.4.14 #5a simhash near-duplicate subsystem.

Two layers:
  1. Pure helpers — _tokenize_simhash, compute_simhash, hamming_distance,
     DEFAULT_SIMHASH_MAX_HAMMING.  These are the deterministic core that
     makes near-duplicate *content* detection possible without bloating the
     discoveries table.
  2. DiscoveryDB integration — _ensure_simhash_table, record_simhash,
     get_simhash, record_simhash_for_text, find_similar.  Confirms the
     simhash_index table roundtrips, upserts by ident_hash_hex, and that
     find_similar excludes the target while returning neighbours within the
     Hamming threshold.

Run with:
    pytest tests/test_simhash_dedup.py -v --tb=short
"""
import os
import tempfile
import unittest

from src.integration import (
    DiscoveryDB,
    compute_simhash,
    hamming_distance,
    _tokenize_simhash,
    DEFAULT_SIMHASH_MAX_HAMMING,
)


# ---------------------------------------------------------------------------
# 1. Pure helpers
# ---------------------------------------------------------------------------

class TestTokenize(unittest.TestCase):
    def test_lowercase_word_tokens(self):
        self.assertEqual(_tokenize_simhash("Hello World"), ["hello", "world"])

    def test_handles_contractions_and_hyphen(self):
        self.assertEqual(
            _tokenize_simhash("It's rock-n-roll"),
            ["it's", "rock-n-roll"],
        )

    def test_empty_and_whitespace_only(self):
        self.assertEqual(_tokenize_simhash(""), [])
        self.assertEqual(_tokenize_simhash("   "), [])
        self.assertEqual(_tokenize_simhash("<<<"), [])

    def test_html_and_punctuation_stripped(self):
        toks = _tokenize_simhash("<p>Hi, there!  <b>Hello</b></p>")
        self.assertEqual(toks, ["hi", "there", "hello"])


class TestComputeSimhash(unittest.TestCase):
    def test_deterministic(self):
        a = "The quick brown fox jumps over the lazy dog"
        self.assertEqual(compute_simhash(a), compute_simhash(a))

    def test_64bit_range(self):
        for text in ["hello", "the quick brown fox", "a" * 50]:
            h = compute_simhash(text)
            self.assertTrue(0 <= h < (1 << 64))

    def test_empty_returns_zero(self):
        self.assertEqual(compute_simhash(""), 0)
        self.assertEqual(compute_simhash("  "), 0)
        self.assertEqual(compute_simhash("<<<"), 0)
        self.assertEqual(compute_simhash(None), 0)  # type: ignore[arg-type]

    def test_identical_text_zero_distance(self):
        text = "similarity of machine learning systems across datasets"
        h = compute_simhash(text)
        self.assertEqual(hamming_distance(h, h), 0)

    def test_near_vs_far_distance(self):
        base = "The quick brown fox jumps over the lazy dog. A tail wags."
        near = "The quick brown fox jumps over the lazy dog. The tail wags."
        far = "Quantum computing, economics, finance, and blockchain ledgers"
        h_base = compute_simhash(base)
        d_near = hamming_distance(h_base, compute_simhash(near))
        d_far = hamming_distance(h_base, compute_simhash(far))
        self.assertLess(d_near, d_far, "near-dup must be closer than unrelated text")
        self.assertLess(d_near, 20, "near-dup on 64-bit hashes should be a low distance")

    def test_word_order_insensitive_to_some_degree(self):
        # Simhash is a bag-of-tokens meta-characteristic, not a sequence hash.
        a = compute_simhash("apple banana cherry")
        b = compute_simhash("cherry banana apple")
        self.assertEqual(hamming_distance(a, b), 0)


class TestHammingDistance(unittest.TestCase):
    def test_zero_vs_one(self):
        self.assertEqual(hamming_distance(0, 1), 1)

    def test_single_bits(self):
        h = compute_simhash("the quick brown fox")
        self.assertEqual(hamming_distance(h, h ^ (1 << 0)), 1)
        self.assertEqual(hamming_distance(h, h ^ (1 << 31)), 1)
        self.assertEqual(hamming_distance(h, h ^ (1 << 63)), 1)

    def test_all_differing(self):
        self.assertEqual(hamming_distance(0, (1 << 64) - 1), 64)

    def test_default_threshold_is_small_positive(self):
        self.assertGreater(DEFAULT_SIMHASH_MAX_HAMMING, 0)
        self.assertLessEqual(DEFAULT_SIMHASH_MAX_HAMMING, 8)


# ---------------------------------------------------------------------------
# 2. DiscoveryDB integration
# ---------------------------------------------------------------------------

class TestSimhashTable(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mktemp(suffix=".db")
        self.db = DiscoveryDB(self.tmp)

    def tearDown(self) -> None:
        self.db.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_table_created_on_init(self):
        cur = self.db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        self.assertIn("simhash_index", tables)

    def test_record_and_get_roundtrip(self):
        ident = "a" * 40
        sh = compute_simhash("the quick brown fox jumps over the lazy dog")
        rid = self.db.record_simhash(ident, sh)
        self.assertGreater(rid, 0)
        self.assertEqual(self.db.get_simhash(ident), sh)

    def test_get_simhash_missing_returns_none(self):
        self.assertIsNone(self.db.get_simhash("missing-ident"))

    def test_upsert_overwrites_same_ident(self):
        ident = "b" * 40
        self.db.record_simhash(ident, compute_simhash("alpha beta"))
        self.db.record_simhash(ident, compute_simhash("gamma delta"))
        # Exactly one row, with the latest hash.
        rows = self.db._conn.execute(
            "SELECT COUNT(*) FROM simhash_index WHERE ident_hash_hex=?", (ident,)
        ).fetchone()
        self.assertEqual(rows[0], 1)
        self.assertEqual(self.db.get_simhash(ident), compute_simhash("gamma delta"))

    def test_last_computed_is_populated(self):
        ident = "c" * 40
        self.db.record_simhash(ident, 0xDEADBEEF)
        row = self.db._conn.execute(
            "SELECT last_computed FROM simhash_index WHERE ident_hash_hex=?",
            (ident,),
        ).fetchone()
        self.assertGreater(row[0], 0)

    def test_record_simhash_for_text_skips_empty(self):
        ident = "d" * 40
        self.assertEqual(self.db.record_simhash_for_text(ident, ""), 0)
        self.assertEqual(self.db.record_simhash_for_text(ident, "   "), 0)
        self.assertIsNone(self.db.get_simhash(ident))

    def test_record_simhash_for_text_writes_on_content(self):
        ident = "e" * 40
        text = "the quick brown fox jumps over the lazy dog"
        rid = self.db.record_simhash_for_text(ident, text)
        self.assertGreater(rid, 0)
        self.assertEqual(self.db.get_simhash(ident), compute_simhash(text))

    def test_find_similar_excludes_self_and_returns_near(self):
        # Two near-duplicate texts (share most tokens) land within a small Hamming
        # distance of each other after fingerprinting.
        ident_a = "f" * 40
        ident_b = "f" * 39 + "A"
        text_a = "The quick brown fox jumps over the lazy dog. A tail wags."
        text_b = "The quick brown fox jumps over the lazy dog. The tail wags."
        self.db.record_simhash(ident_a, compute_simhash(text_a))
        self.db.record_simhash(ident_b, compute_simhash(text_b))

        d_ab = hamming_distance(compute_simhash(text_a), compute_simhash(text_b))
        # Use a threshold generous enough to include the real neighbours, but
        # still well below the random 32-bit median.
        threshold = max(DEFAULT_SIMHASH_MAX_HAMMING, d_ab + 1)
        hits = self.db.find_similar(ident_a, max_hamming=threshold)
        # Self excluded; the neighbour is present with correct distance.
        self.assertNotIn(ident_a, [h["ident_hash_hex"] for h in hits])
        self.assertIn(ident_b, [h["ident_hash_hex"] for h in hits])
        entry = [h for h in hits if h["ident_hash_hex"] == ident_b][0]
        self.assertEqual(entry["hamming_distance"], d_ab)

    def test_find_similar_zero_for_unrelated(self):
        ident_a = "g" * 40
        ident_b = "g" * 39 + "B"
        # Deliberately dissimilar content: unrelated topics.
        self.db.record_simhash(ident_a, compute_simhash("apple banana cherry date elderberry"))
        self.db.record_simhash(ident_b, compute_simhash("relativity quantum mechanics thermodynamics"))
        hits = self.db.find_similar(ident_a, max_hamming=DEFAULT_SIMHASH_MAX_HAMMING)
        self.assertEqual(hits, [], "unrelated texts must not appear as near-dups")

    def test_find_similar_unknown_target_return_empty(self):
        self.assertEqual(self.db.find_similar("unknown-ident"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
