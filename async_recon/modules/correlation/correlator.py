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

        asset_subdomains: List[AssetSubdomain] = []
        unique_tech_names: Set[str] = set()
        total_ports = 0
        total_http = 0

        for sub in subdomains:
            if sub.id is None:
                continue
            asset_sub = await self._correlate_subdomain(sub.id, sub, unique_tech_names)
            total_ports += len(asset_sub.ports)
            total_http += len(asset_sub.http_endpoints)
            asset_subdomains.append(asset_sub)

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

    async def _correlate_subdomain(
        self,
        subdomain_id: int,
        sub_record: object,
        unique_tech_names: Set[str],
    ) -> AssetSubdomain:
        """Enrich a single subdomain with all its associated recon data."""
        # Import here to avoid circular type issues; models are simple attrs
        from async_recon.database.models import SubdomainRecord

        assert isinstance(sub_record, SubdomainRecord)

        # Build screenshot path map: url -> file_path
        screenshot_map: Dict[str, str] = {}
        try:
            screenshots = await self._db.get_screenshots(subdomain_id)
            for ss in screenshots:
                screenshot_map[ss.url] = ss.file_path
        except Exception as e:
            logger.warning(
                f"Failed to fetch screenshots for subdomain_id={subdomain_id}: {e}"
            )

        # DNS records
        dns_records: List[AssetDnsRecord] = []
        try:
            raw_dns = await self._db.get_dns_records(subdomain_id)
            dns_records = [
                AssetDnsRecord(record_type=r.record_type, value=r.value)
                for r in raw_dns
            ]
        except Exception as e:
            logger.warning(
                f"Failed to fetch DNS records for subdomain_id={subdomain_id}: {e}"
            )

        # Ports
        asset_ports: List[AssetPort] = []
        try:
            raw_ports = await self._db.get_ports(subdomain_id)
            asset_ports = [
                AssetPort(port=p.port, protocol=p.protocol, service=p.service)
                for p in raw_ports
            ]
        except Exception as e:
            logger.warning(
                f"Failed to fetch ports for subdomain_id={subdomain_id}: {e}"
            )

        # HTTP endpoints — join screenshot path by URL
        http_endpoints: List[AssetHttpEndpoint] = []
        try:
            raw_http = await self._db.get_http_records(subdomain_id)
            for h in raw_http:
                http_endpoints.append(
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
                        screenshot_path=screenshot_map.get(h.url, ""),
                    )
                )
        except Exception as e:
            logger.warning(
                f"Failed to fetch HTTP records for subdomain_id={subdomain_id}: {e}"
            )

        # Technologies
        asset_tech: List[AssetTechnology] = []
        try:
            raw_tech = await self._db.get_tech_records(subdomain_id)
            for t in raw_tech:
                unique_tech_names.add(t.name)
                asset_tech.append(
                    AssetTechnology(
                        category=t.category,
                        name=t.name,
                        version=t.version,
                        confidence=t.confidence,
                    )
                )
        except Exception as e:
            logger.warning(
                f"Failed to fetch tech records for subdomain_id={subdomain_id}: {e}"
            )

        return AssetSubdomain(
            subdomain=sub_record.subdomain,
            source=sub_record.source,
            resolved=sub_record.resolved,
            is_wildcard=sub_record.is_wildcard,
            dns_records=dns_records,
            ports=asset_ports,
            http_endpoints=http_endpoints,
            technologies=asset_tech,
        )
