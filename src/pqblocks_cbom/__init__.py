"""pqblocks_cbom - Post-Quantum CBOM Enricher

Enriches CycloneDX 1.5 SBOMs with PQ metadata per CBOM Profile specifications.
"""

from .enricher import CBOMEnricher, CBOMProfile
from .classify import classify_component, canonicalize_property

__all__ = [
    "CBOMEnricher",
    "CBOMProfile",
    "classify_component",
    "canonicalize_property",
]

__version__ = "0.1.0"