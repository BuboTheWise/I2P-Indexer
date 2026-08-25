"""I2P Indexer — client-side eepsite discovery tools."""

__version__ = "0.4.11"

from .addressbook import AddressBookCatalog
from .config import I2PConfig
from .i2p_proxy import (
    Response,
    I2PProxyClient,
    I2PSAMClient,
    ProxyBackend,
    fetch_i2p,
    probe_health,
)
from .ls64_parser import parse_ls64_file
from .models import (
    LeaseSetInfo,
    RouterInfo,
    TransportInfo,
    classify_bw,
)
from .rtr_parser import parse_rtr_file

__all__ = [
    "AddressBookCatalog",
    "I2PConfig",
    "fetch_i2p",
    "I2PProxyClient",
    "I2PSAMClient",
    "LeaseSetInfo",
    "ProxyBackend",
    "Response",
    "RouterInfo",
    "TransportInfo",
    "classify_bw",
    "parse_ls64_file",
    "parse_rtr_file",
    "probe_health",
]
