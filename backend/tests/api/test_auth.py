"""Token generation, atomic publication, and the fail-closed authenticator."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import pytest

from backend.api.auth import (
    TOKEN_BYTES,
    TOKEN_DIRECTORY_MODE,
    TOKEN_FILE_MODE,
    TokenAuthenticator,
    issue_token,
    write_token_file,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes and symlink semantics")


def test_tokens_are_urlsafe_and_carry_at_least_32_bytes_of_entropy() -> None:
    token = issue_token()
    assert re.fullmatch(r"[A-Za-z0-9_-]+", token)
    # token_urlsafe(n) yields ceil(n * 4 / 3) characters without padding: 43 for 32 bytes.
    assert len(token) >= 43
    assert TOKEN_BYTES >= 32


def test_tokens_are_unique() -> None:
    assert len({issue_token() for _ in range(200)}) == 200


def test_token_file_holds_exactly_the_token(tmp_path: Path) -> None:
    path = tmp_path / "token"
    write_token_file(path, "abc123")
    assert path.read_bytes() == b"abc123"


def test_parent_directory_is_created(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "token"
    write_token_file(path, "abc123")
    assert path.read_text() == "abc123"


def test_existing_token_is_replaced_and_no_temporary_files_remain(tmp_path: Path) -> None:
    path = tmp_path / "token"
    write_token_file(path, "first")
    write_token_file(path, "second")
    assert path.read_text() == "second"
    assert [p.name for p in tmp_path.iterdir()] == ["token"]


@posix_only
def test_token_file_is_group_readable_but_not_group_writable_and_closed_to_others(tmp_path: Path) -> None:
    path = tmp_path / "token"
    write_token_file(path, "abc123")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == TOKEN_FILE_MODE == 0o640
    assert mode & stat.S_IRGRP
    assert not mode & stat.S_IWGRP
    assert not mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)


@posix_only
def test_mode_is_exact_even_under_a_restrictive_umask(tmp_path: Path) -> None:
    # The service runs with UMask=0077, which would strip the group bit from a plain open().
    previous = os.umask(0o077)
    try:
        write_token_file(tmp_path / "token", "abc123")
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "token").stat().st_mode) == 0o640


@posix_only
def test_a_previous_permissive_file_does_not_leak_its_mode_to_the_new_token(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("stale")
    path.chmod(0o666)
    write_token_file(path, "fresh")
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


@posix_only
def test_a_symlink_at_the_token_path_is_replaced_not_followed(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("must not change")
    path = tmp_path / "token"
    path.symlink_to(victim)
    write_token_file(path, "fresh")
    assert victim.read_text() == "must not change"
    assert not path.is_symlink()
    assert path.read_text() == "fresh"


def test_a_failed_replace_keeps_the_previous_token_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "token"
    write_token_file(path, "previous")

    def broken_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk went away")

    monkeypatch.setattr("backend.api.auth.os.replace", broken_replace)
    with pytest.raises(OSError, match="disk went away"):
        write_token_file(path, "new")
    assert path.read_text() == "previous"
    assert [p.name for p in tmp_path.iterdir()] == ["token"]


def test_authenticator_refuses_everything_until_a_token_is_installed() -> None:
    authenticator = TokenAuthenticator()
    assert not authenticator.verify(b"anything")
    assert not authenticator.verify(b"")


def test_authenticator_accepts_only_the_installed_token() -> None:
    authenticator = TokenAuthenticator()
    authenticator.install("installed-token")
    assert authenticator.verify(b"installed-token")
    assert not authenticator.verify(b"installed-toke")
    assert not authenticator.verify(b"installed-token ")
    assert not authenticator.verify(b"")


def test_installing_a_new_token_revokes_the_old_one() -> None:
    authenticator = TokenAuthenticator()
    authenticator.install("old-token")
    authenticator.install("new-token")
    assert not authenticator.verify(b"old-token")
    assert authenticator.verify(b"new-token")


@posix_only
def test_a_new_token_directory_lets_the_group_enter_it_and_nobody_else(tmp_path: Path) -> None:
    previous = os.umask(0)  # a permissive umask must not widen the directory
    try:
        write_token_file(tmp_path / "run" / "token", "abc123")
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "run").stat().st_mode) == TOKEN_DIRECTORY_MODE == 0o750
