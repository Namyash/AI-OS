"""The session store: random ids kept only as hashes, absolute lifetime, a cap of eight, revocation."""

from __future__ import annotations

import hashlib
import re
import secrets

import pytest

from backend.api import sessions as sessions_module
from backend.api.sessions import MAX_SESSIONS, SessionStore
from backend.core.logging import REDACTED, redact_text

TTL = 3600


class Clock:
    """Replaces the store's monotonic clock, so lifetimes are tested without waiting."""

    def __init__(self) -> None:
        self.now = 1000.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(sessions_module, "monotonic", lambda: fake.now)
    return fake


@pytest.fixture
def store(clock: Clock) -> SessionStore:
    return SessionStore(TTL)


def _live(store: SessionStore, session_id: str) -> bool:
    return store.authenticate(session_id.encode("ascii")) is not None


# ------------------------------------------------------------------ ids
def test_ids_are_256_bit_url_safe_random_values(store: SessionStore) -> None:
    session_id = store.create()
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", session_id)  # 32 random bytes, base64url without padding


def test_ids_are_unique() -> None:
    ids = set()
    for _ in range(50):
        store = SessionStore(TTL)  # a fresh store each time: uniqueness must not depend on the store's own state
        ids.add(store.create())
    assert len(ids) == 50


def test_the_store_keeps_a_hash_of_the_id_and_never_the_id(store: SessionStore) -> None:
    session_id = store.create()
    assert session_id not in repr(vars(store))
    assert [hashlib.sha256(session_id.encode("ascii")).digest()] == list(store._deadlines)


# ------------------------------------------------------------------ authentication
def test_a_live_id_authenticates_and_anything_else_does_not(store: SessionStore) -> None:
    session_id = store.create()
    assert _live(store, session_id)
    for wrong in (session_id[:-1], session_id + "x", session_id[::-1], session_id.swapcase(), "", " " + session_id):
        assert store.authenticate(wrong.encode("ascii")) is None, wrong


def test_authentication_returns_the_same_key_for_the_same_session(store: SessionStore) -> None:
    first, second = store.create(), store.create()
    assert store.authenticate(first.encode()) == store.authenticate(first.encode())
    assert store.authenticate(first.encode()) != store.authenticate(second.encode())


def test_an_oversized_presentation_is_refused_without_being_hashed(
    store: SessionStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.create()
    hashed: list[bytes] = []
    monkeypatch.setattr(sessions_module, "_digest", lambda value: hashed.append(value) or b"")
    assert store.authenticate(b"x" * 1_000_000) is None
    assert hashed == []


def test_every_live_session_is_compared_whatever_matches(store: SessionStore, monkeypatch: pytest.MonkeyPatch) -> None:
    # Constant-time: the comparison is compare_digest, and it does not stop at the first match, so the time taken
    # does not reveal which session matched.
    ids = [store.create() for _ in range(4)]
    comparisons: list[tuple[bytes, bytes]] = []
    real_compare = secrets.compare_digest  # the module is shared, so keep the real function before replacing it

    def counting(left: bytes, right: bytes) -> bool:
        comparisons.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(sessions_module.secrets, "compare_digest", counting)
    assert _live(store, ids[0])
    assert len(comparisons) == 4
    comparisons.clear()
    assert not _live(store, "not-a-session-id")
    assert len(comparisons) == 4


# ------------------------------------------------------------------ lifetime
def test_a_session_lasts_exactly_its_lifetime(store: SessionStore, clock: Clock) -> None:
    session_id = store.create()
    clock.advance(TTL - 1)
    assert _live(store, session_id)
    clock.advance(1)
    assert not _live(store, session_id)


def test_using_a_session_does_not_extend_it(store: SessionStore, clock: Clock) -> None:
    session_id = store.create()
    for _ in range(3):
        clock.advance(TTL / 2 - 1)
        _live(store, session_id)
    clock.advance(TTL)
    assert not _live(store, session_id)  # an absolute lifetime, not an idle timeout


def test_expired_sessions_are_dropped_so_memory_stays_bounded(store: SessionStore, clock: Clock) -> None:
    for _ in range(MAX_SESSIONS):
        store.create()
    clock.advance(TTL)
    assert len(store) == 0
    assert vars(store)["_deadlines"] == {}


# ------------------------------------------------------------------ the cap of eight
def test_at_most_eight_sessions_are_alive_and_the_oldest_is_evicted(store: SessionStore, clock: Clock) -> None:
    assert MAX_SESSIONS == 8
    ids = []
    for _ in range(MAX_SESSIONS):
        ids.append(store.create())
        clock.advance(1)
    assert all(_live(store, session_id) for session_id in ids)

    newest = store.create()
    assert len(store) == MAX_SESSIONS
    assert not _live(store, ids[0])  # the oldest went
    assert all(_live(store, session_id) for session_id in [*ids[1:], newest])


def test_the_store_never_holds_more_than_the_cap_however_many_are_minted(store: SessionStore) -> None:
    for _ in range(100):
        store.create()
    assert len(store) == MAX_SESSIONS


def test_an_expired_session_makes_room_before_a_live_one_is_evicted(store: SessionStore, clock: Clock) -> None:
    old = [store.create() for _ in range(2)]
    clock.advance(TTL - 10)
    recent = [store.create() for _ in range(MAX_SESSIONS - 2)]
    clock.advance(10)  # the two old sessions have expired now; the rest have not
    newcomer = store.create()
    assert all(_live(store, session_id) for session_id in [*recent, newcomer])
    assert not any(_live(store, session_id) for session_id in old)


# ------------------------------------------------------------------ revocation
def test_a_revoked_session_stops_working_and_the_others_do_not(store: SessionStore) -> None:
    first, second = store.create(), store.create()
    key = store.authenticate(first.encode())
    assert key is not None
    store.revoke(key)
    assert not _live(store, first)
    assert _live(store, second)
    store.revoke(key)  # twice is harmless
    store.revoke(b"\x00" * 32)  # as is an unknown key
    assert _live(store, second)


# ------------------------------------------------------------------ log redaction
def test_a_live_id_is_masked_wherever_it_is_logged(store: SessionStore) -> None:
    session_id = store.create()
    assert redact_text(f"debug: handling {session_id} now") == f"debug: handling {REDACTED} now"


@pytest.mark.parametrize("how", ["revoked", "evicted", "expired"])
def test_an_id_leaves_the_log_registry_when_its_session_ends(store: SessionStore, clock: Clock, how: str) -> None:
    # The registry must stay as small as the number of live sessions, or minting would grow it without bound.
    session_id = store.create()
    if how == "revoked":
        key = store.authenticate(session_id.encode())
        assert key is not None
        store.revoke(key)
    elif how == "evicted":
        for _ in range(MAX_SESSIONS):
            store.create()
    else:
        clock.advance(TTL)
        len(store)  # any use drops the expired
    assert redact_text(session_id) == session_id  # no longer a secret of ours, so it is no longer rewritten


def test_the_log_registry_does_not_grow_with_every_session_minted(store: SessionStore) -> None:
    from backend.core import logging as core_logging

    before = len(core_logging._secrets)
    for _ in range(100):
        store.create()
    assert len(core_logging._secrets) - before <= MAX_SESSIONS
