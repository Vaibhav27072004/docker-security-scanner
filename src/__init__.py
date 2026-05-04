"""
docker_security_scanner — src package initialiser.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("docker-security-scanner")
except PackageNotFoundError:
    __version__ = "1.0.0-dev"

__all__ = ["__version__"]
