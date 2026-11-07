"""Helpers shared by the API tests (kept out of conftest.py, which pytest owns)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

PORT = 18765


def client_for(app: FastAPI, port: int = PORT) -> TestClient:
    """A client whose Host header is a legitimate one for ``port``. Server-side failures become 500 responses."""
    return TestClient(app, base_url=f"http://127.0.0.1:{port}", raise_server_exceptions=False)
