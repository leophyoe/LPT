"""Open-Source Intelligence (OSINT) and Attack Surface Mapping Module."""

from modules.osint.amass_osint_adapter import AmassOSINTAdapter
from modules.osint.base_adapter import BaseOSINTAdapter, OSINTDiscoveryResult
from modules.osint.cert_transparency_adapter import CertTransparencyAdapter
from modules.osint.maltego_graph import MALTEGO_ENTITY_MAP, MaltegoGraphEngine
from modules.osint.recon_ng_adapter import ReconNgAdapter
from modules.osint.theharvester_adapter import TheHarvesterAdapter

__all__ = [
    "BaseOSINTAdapter",
    "OSINTDiscoveryResult",
    "AmassOSINTAdapter",
    "CertTransparencyAdapter",
    "TheHarvesterAdapter",
    "ReconNgAdapter",
    "MaltegoGraphEngine",
    "MALTEGO_ENTITY_MAP",
]

