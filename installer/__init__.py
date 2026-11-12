"""The installer engine: copies the running live system onto a blank disk, encrypted with LUKS2.

``python3 -m installer --plan plan.json`` runs as root on the live image. It is standard library only and imports
nothing from ``backend`` or ``kiosk``: it is driven by a plan file and reports progress as JSON lines, so a wizard, a
test harness or a person can run it the same way. The design and its safety rules are in
``docs/architecture/INSTALLER_DESIGN.md``; how to run and test it is in ``docs/development/INSTALLER.md``.
"""
