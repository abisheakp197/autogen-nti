"""
autogen-nti: Drop-in NTI (Neutral Trust Infrastructure) security for AutoGen / Microsoft Agent Framework.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

from autogen_nti.security import NTISecurityWrapper

try:
    __version__ = _version("autogen-nti")
except PackageNotFoundError:  # imported from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["NTISecurityWrapper"]
