"""Tests for time-based sweep filters (stale, min_age_hours)."""
import pytest
import time as _time

from src.integration import DiscoveryDB, discover_addresses


class TestStaleFilterTargets:
    """get_targets('stale') returns only targets older than threshold."""

    @pytest.fixture
    def db(self, tmp_path):
        inst = DiscoveryDB(db_path=str(tmp_path / "stale.db"))
        yield inst
        inst.close()

    def _set_last_probed(self, db, hash_hex, ts):
        """Set last_probed_at for a specific target by its full hash."""
        cur = db._conn.cursor()
        cur.execute(
            "UPDATE targets SET last_probed_at=? WHERE ident_hash_hex=?", (ts, hash_hex)
        )
        db._conn.commit()

    def test_stale_excludes_recent(self, db):
        HASH_A = "A" * 40
        HASH_B = "B" * 40
        now = _time.time()

        db.upsert_targets([
            (HASH_A, "fresh.i2p"),
            (HASH_B, "stale_target.i2p"),
        ])
        # A was just probed (not stale)
        self._set_last_probed(db, HASH_A, now)
        # B was probed 48h ago (stale for 24h threshold)
        self._set_last_probed(db, HASH_B, now - 48 * 3600)

        targets = db.get_targets(filter_mode="stale", min_age_hours=24.0)
        assert len(targets) == 1
        assert targets[0][0] == HASH_B
        assert targets[0][1] == "stale_target.i2p"

    def test_stale_respects_custom_min_age(self, db):
        HASH_C = "C" * 40
        HASH_D = "D" * 40
        now = _time.time()

        db.upsert_targets([
            (HASH_C, "old.i2p"),
            (HASH_D, "newer.i2p"),
        ])
        # C was probed 36h ago
        self._set_last_probed(db, HASH_C, now - 36 * 3600)
        # D was probed 12h ago
        self._set_last_probed(db, HASH_D, now - 12 * 3600)

        # With min_age_hours=24, only C is stale
        targets = db.get_targets(filter_mode="stale", min_age_hours=24.0)
        assert len(targets) == 1
        assert targets[0][0] == HASH_C

        # With min_age_hours=10, both C and D are stale
        targets = db.get_targets(filter_mode="stale", min_age_hours=10.0)
        assert len(targets) == 2

    def test_stale_empty_when_all_fresh(self, db):
        HASH_E = "E" * 40
        HASH_F = "F" * 40
        now = _time.time()

        db.upsert_targets([
            (HASH_E, "fresh1.i2p"),
            (HASH_F, "fresh2.i2p"),
        ])
        # Both probed literally now
        self._set_last_probed(db, HASH_E, now)
        self._set_last_probed(db, HASH_F, now)

        targets = db.get_targets(filter_mode="stale", min_age_hours=1.0)
        assert len(targets) == 0

    def test_never_probed_is_stale(self, db):
        """A target with last_probed_at=0 counts as stale (epoch 0)."""
        HASH_G = "6" * 40
        db.upsert_targets([(HASH_G, "never.i2p")])

        targets = db.get_targets(filter_mode="stale", min_age_hours=24.0)
        assert len(targets) == 1
        assert targets[0][0] == HASH_G

    def test_all_mode_returns_everything(self, db):
        HASH_H = "7" * 40
        HASH_I = "8" * 40
        now = _time.time()

        db.upsert_targets([
            (HASH_H, "recent.i2p"),
            (HASH_I, "ancient.i2p"),
        ])
        self._set_last_probed(db, HASH_H, now)
        self._set_last_probed(db, HASH_I, now - 100 * 3600)

        targets = db.get_targets(filter_mode="all")
        assert len(targets) == 2

    def test_parameterized_query_safe(self, db):
        """The stale filter uses ? parameterization, not f-string SQL."""
        HASH_J = "9" * 40
        now = _time.time()
        db.upsert_targets([(HASH_J, "param.i2p")])
        self._set_last_probed(db, HASH_J, now - 48 * 3600)

        # Should work with any float value
        targets = db.get_targets(filter_mode="stale", min_age_hours=1.5)
        assert len(targets) == 1

        # Even with a very specific decimal value
        targets = db.get_targets(filter_mode="stale", min_age_hours=0.5)
        assert len(targets) == 1
