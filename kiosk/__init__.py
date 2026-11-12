"""The kiosk launcher: shows the web UI full screen in Chromium and hands it a session without leaking the secret.

``python3 -m kiosk`` runs under ``cage`` (see ``os/kiosk``). It is standard library only and imports nothing from
``backend``: it talks to the backend over HTTP like any other client, so the two cannot drift into sharing code that
handles the secret.
"""
