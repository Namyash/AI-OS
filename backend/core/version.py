"""Backend version reported by the API.

The service runs from a plain source copy in the image, where no package metadata exists, so the version
lives in code. A test keeps it equal to ``pyproject.toml``.
"""

__version__ = "0.0.1"
