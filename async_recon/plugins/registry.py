"""Central plugin registry for ReconForge.

Lists all known plugins with metadata used by the CLI ``plugins-list``
command and the PluginManager.  Adding a new plugin to the framework
requires only appending an entry here.
"""

from typing import Any, Dict, List

PLUGIN_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "subfinder",
        "type": "passive",
        "binary": "subfinder",
        "description": "Passive subdomain discovery via certificate logs, APIs, and search engines",
    },
    {
        "name": "assetfinder",
        "type": "passive",
        "binary": "assetfinder",
        "description": "Passive subdomain discovery using certificate transparency and web archives",
    },
    {
        "name": "amass",
        "type": "passive",
        "binary": "amass",
        "description": "Comprehensive passive subdomain enumeration and network mapping",
    },
    {
        "name": "naabu",
        "type": "active",
        "binary": "naabu",
        "description": "Fast SYN/CONNECT port scanning for open port discovery",
    },
    {
        "name": "http_prober",
        "type": "active",
        "binary": "—",
        "description": "HTTP/HTTPS endpoint probing with TLS certificate extraction (built-in)",
    },
    {
        "name": "tech_detector",
        "type": "active",
        "binary": "—",
        "description": "Technology fingerprinting via HTTP headers, cookies, and HTML signatures (built-in)",
    },
    {
        "name": "gowitness",
        "type": "active",
        "binary": "gowitness",
        "description": "Automated web screenshot capture for visual asset cataloging",
    },
]
