"""Asset correlator — reads the database and builds a normalized AssetModel.

Responsibilities:
  - Query all recon data for a target from the DatabaseStore
  - Join subdomains ↔ DNS ↔ ports ↔ HTTP records ↔ tech ↔ screenshots
  - Compute summary statistics
  - Return a single AssetModel

This layer is completely independent of the reporting layer. It knows
nothing about output formats (HTML, JSON, etc.).

Design notes:
  - All DB access is centralised here; the reporter never touches the DB.
  - Failure to enrich any single subdomain is non-fatal — we log and move on.
  - The correlator is stateless: create it, call correlate(), discard it.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Set

from async_recon.database.store import DatabaseStore
from async_recon.modules.correlation.models import (
    AssetDnsRecord,
    AssetHttpEndpoint,
    AssetModel,
    AssetPort,
    AssetSubdomain,
    AssetTechnology,
)

logger = logging.getLogger(__name__)


class AssetCorrelator:
    """Correlates all recon data for a target into a single AssetModel.

    Args:
        db: An open, initialised DatabaseStore instance.
    """

    def __init__(self, db: DatabaseStore) -> None:
        self._db = db

    async def correlate(self, target: str) -> AssetModel:
        """Build the complete AssetModel for a target.

        Args:
            target: The root domain that was scanned (e.g. 'example.com').

        Returns:
            A fully-populated AssetModel ready for the reporting layer.
        """
        logger.info(f"Starting correlation for target: {target}")

        subdomains = await self._db.get_all_subdomains(target)
        logger.debug(f"Correlating {len(subdomains)} subdomains for {target}")

        # Bulk fetch all relations for the target
        dns_records = await self._db.get_all_dns_records_by_target(target)
        ports = await self._db.get_all_ports_by_target(target)
        http_records = await self._db.get_all_http_records_by_target(target)
        tech_records = await self._db.get_all_tech_records_by_target(target)
        screenshots = await self._db.get_all_screenshots_by_target(target)

        # Group by subdomain_id
        dns_map = defaultdict(list)
        for d in dns_records:
            dns_map[d.subdomain_id].append(d)

        port_map = defaultdict(list)
        for p in ports:
            port_map[p.subdomain_id].append(p)

        http_map = defaultdict(list)
        for h in http_records:
            http_map[h.subdomain_id].append(h)

        tech_map = defaultdict(list)
        for t in tech_records:
            tech_map[t.subdomain_id].append(t)

        screenshot_map: Dict[int, Dict[str, str]] = defaultdict(dict)
        for s in screenshots:
            screenshot_map[s.subdomain_id][s.url] = s.file_path

        asset_subdomains: List[AssetSubdomain] = []
        unique_tech_names: Set[str] = set()
        total_ports = 0
        total_http = 0

        for sub in subdomains:
            if sub.id is None:
                continue

            sub_id = sub.id

            # Map DNS
            asset_dns = [
                AssetDnsRecord(record_type=r.record_type, value=r.value)
                for r in dns_map[sub_id]
            ]

            # Map Ports
            asset_ports = [
                AssetPort(port=p.port, protocol=p.protocol, service=p.service)
                for p in port_map[sub_id]
            ]
            total_ports += len(asset_ports)

            # Map HTTP
            asset_http = []
            for h in http_map[sub_id]:
                asset_http.append(
                    AssetHttpEndpoint(
                        url=h.url,
                        port=h.port,
                        status_code=h.status_code,
                        title=h.title,
                        server=h.server,
                        content_type=h.content_type,
                        content_length=h.content_length,
                        redirect_url=h.redirect_url,
                        tls_issuer=h.tls_issuer,
                        tls_subject=h.tls_subject,
                        tls_not_after=h.tls_not_after,
                        screenshot_path=screenshot_map[sub_id].get(h.url, ""),
                    )
                )
            total_http += len(asset_http)

            # Map Tech
            asset_tech = []
            for t in tech_map[sub_id]:
                unique_tech_names.add(t.name)
                asset_tech.append(
                    AssetTechnology(
                        category=t.category,
                        name=t.name,
                        version=t.version,
                        confidence=t.confidence,
                    )
                )

            asset_subdomains.append(
                AssetSubdomain(
                    subdomain=sub.subdomain,
                    source=sub.source,
                    resolved=sub.resolved,
                    is_wildcard=sub.is_wildcard,
                    dns_records=asset_dns,
                    ports=asset_ports,
                    http_endpoints=asset_http,
                    technologies=asset_tech,
                )
            )

        live_count = sum(1 for s in asset_subdomains if s.is_live)

        model = AssetModel(
            target=target,
            subdomains=asset_subdomains,
            total_subdomains=len(asset_subdomains),
            live_subdomains=live_count,
            total_open_ports=total_ports,
            total_http_endpoints=total_http,
            unique_technologies=sorted(unique_tech_names),
        )

        logger.info(
            f"Correlation complete for {target}: "
            f"{model.total_subdomains} subdomains, "
            f"{model.live_subdomains} live, "
            f"{model.total_open_ports} open ports, "
            f"{model.total_http_endpoints} HTTP endpoints"
        )
        return model
