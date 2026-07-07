"""Async SQLite database store.

Provides CRUD operations for all recon data types. Schema is designed
so a future Postgres swap only requires changing the connection layer.
"""

import logging
from typing import List, Optional

import aiosqlite

from async_recon.database.models import (
    DNSRecord,
    HttpRecord,
    PortRecord,
    ScreenshotRecord,
    SubdomainRecord,
    TechRecord,
)

logger = logging.getLogger(__name__)


class DatabaseStore:
    """Async SQLite storage backend for all recon data."""

    def __init__(self, db_path: str = "recon.db") -> None:
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Open a connection to the database."""
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.execute("PRAGMA foreign_keys = ON;")
        await self._conn.commit()

    async def disconnect(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    def _require_conn(self) -> aiosqlite.Connection:
        """Return the active connection or raise."""
        if not self._conn:
            raise RuntimeError("Database not connected")
        return self._conn

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    async def init_schema(self) -> None:
        """Create all tables if they do not already exist."""
        conn = self._require_conn()

        await conn.executescript("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                source TEXT NOT NULL,
                resolved BOOLEAN DEFAULT 0,
                is_wildcard BOOLEAN DEFAULT 0,
                UNIQUE(target, subdomain)
            );

            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                FOREIGN KEY(subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service TEXT NOT NULL DEFAULT '',
                UNIQUE(subdomain_id, port, protocol),
                FOREIGN KEY(subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS http_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                content_length INTEGER NOT NULL DEFAULT 0,
                redirect_url TEXT NOT NULL DEFAULT '',
                server TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL DEFAULT '',
                tls_issuer TEXT NOT NULL DEFAULT '',
                tls_subject TEXT NOT NULL DEFAULT '',
                tls_not_after TEXT NOT NULL DEFAULT '',
                UNIQUE(subdomain_id, port),
                FOREIGN KEY(subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS tech_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                confidence INTEGER NOT NULL DEFAULT 100,
                UNIQUE(subdomain_id, category, name),
                FOREIGN KEY(subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                file_path TEXT NOT NULL,
                width INTEGER NOT NULL DEFAULT 1280,
                height INTEGER NOT NULL DEFAULT 800,
                UNIQUE(subdomain_id, url),
                FOREIGN KEY(subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
            );
        """)
        await conn.commit()

    # ------------------------------------------------------------------
    # Subdomains
    # ------------------------------------------------------------------

    async def add_subdomain(self, target: str, subdomain: str, source: str) -> int:
        """Insert a subdomain (deduplicating) and return its ID."""
        conn = self._require_conn()

        await conn.execute(
            "INSERT OR IGNORE INTO subdomains (target, subdomain, source) VALUES (?, ?, ?)",
            (target, subdomain, source),
        )
        await conn.commit()

        async with conn.execute(
            "SELECT id FROM subdomains WHERE target = ? AND subdomain = ?",
            (target, subdomain),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return int(row[0])
            raise RuntimeError("Failed to retrieve subdomain ID after insert.")

    async def get_unresolved_subdomains(self) -> List[SubdomainRecord]:
        """Return all subdomains that have not been resolved yet."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, target, subdomain, source, resolved, is_wildcard "
            "FROM subdomains WHERE resolved = 0"
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                SubdomainRecord(
                    id=row[0],
                    target=row[1],
                    subdomain=row[2],
                    source=row[3],
                    resolved=bool(row[4]),
                    is_wildcard=bool(row[5]),
                )
                for row in rows
            ]

    async def get_all_subdomains(self, target: str) -> List[SubdomainRecord]:
        """Return all subdomains for a given target."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, target, subdomain, source, resolved, is_wildcard "
            "FROM subdomains WHERE target = ?",
            (target,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                SubdomainRecord(
                    id=row[0],
                    target=row[1],
                    subdomain=row[2],
                    source=row[3],
                    resolved=bool(row[4]),
                    is_wildcard=bool(row[5]),
                )
                for row in rows
            ]

    async def mark_resolved(self, subdomain_id: int, is_wildcard: bool = False) -> None:
        """Mark a subdomain as resolved."""
        conn = self._require_conn()

        await conn.execute(
            "UPDATE subdomains SET resolved = 1, is_wildcard = ? WHERE id = ?",
            (is_wildcard, subdomain_id),
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    async def add_dns_record(
        self, subdomain_id: int, record_type: str, value: str
    ) -> None:
        """Insert a DNS record for a subdomain."""
        conn = self._require_conn()

        await conn.execute(
            "INSERT INTO dns_records (subdomain_id, record_type, value) VALUES (?, ?, ?)",
            (subdomain_id, record_type, value),
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------

    async def add_port(
        self,
        subdomain_id: int,
        port: int,
        protocol: str = "tcp",
        service: str = "",
    ) -> None:
        """Insert a discovered port (deduplicating)."""
        conn = self._require_conn()

        await conn.execute(
            "INSERT OR IGNORE INTO ports (subdomain_id, port, protocol, service) "
            "VALUES (?, ?, ?, ?)",
            (subdomain_id, port, protocol, service),
        )
        await conn.commit()

    async def get_ports(self, subdomain_id: int) -> List[PortRecord]:
        """Return all ports for a subdomain."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, subdomain_id, port, protocol, service "
            "FROM ports WHERE subdomain_id = ?",
            (subdomain_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                PortRecord(
                    id=row[0],
                    subdomain_id=row[1],
                    port=row[2],
                    protocol=row[3],
                    service=row[4],
                )
                for row in rows
            ]

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def add_http_record(
        self,
        subdomain_id: int,
        port: int,
        url: str,
        status_code: int,
        title: str = "",
        content_length: int = 0,
        redirect_url: str = "",
        server: str = "",
        content_type: str = "",
        tls_issuer: str = "",
        tls_subject: str = "",
        tls_not_after: str = "",
    ) -> None:
        """Insert an HTTP probe result (deduplicating on subdomain + port)."""
        conn = self._require_conn()

        await conn.execute(
            "INSERT OR REPLACE INTO http_records "
            "(subdomain_id, port, url, status_code, title, content_length, "
            "redirect_url, server, content_type, tls_issuer, tls_subject, tls_not_after) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                subdomain_id,
                port,
                url,
                status_code,
                title,
                content_length,
                redirect_url,
                server,
                content_type,
                tls_issuer,
                tls_subject,
                tls_not_after,
            ),
        )
        await conn.commit()

    async def get_http_records(self, subdomain_id: int) -> List[HttpRecord]:
        """Return all HTTP records for a subdomain."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, subdomain_id, port, url, status_code, title, "
            "content_length, redirect_url, server, content_type, "
            "tls_issuer, tls_subject, tls_not_after "
            "FROM http_records WHERE subdomain_id = ?",
            (subdomain_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                HttpRecord(
                    id=row[0],
                    subdomain_id=row[1],
                    port=row[2],
                    url=row[3],
                    status_code=row[4],
                    title=row[5],
                    content_length=row[6],
                    redirect_url=row[7],
                    server=row[8],
                    content_type=row[9],
                    tls_issuer=row[10],
                    tls_subject=row[11],
                    tls_not_after=row[12],
                )
                for row in rows
            ]

    # ------------------------------------------------------------------
    # Technology
    # ------------------------------------------------------------------

    async def add_tech_record(
        self,
        subdomain_id: int,
        category: str,
        name: str,
        version: str = "",
        confidence: int = 100,
    ) -> None:
        """Insert a technology detection record (deduplicating)."""
        conn = self._require_conn()

        await conn.execute(
            "INSERT OR IGNORE INTO tech_records "
            "(subdomain_id, category, name, version, confidence) "
            "VALUES (?, ?, ?, ?, ?)",
            (subdomain_id, category, name, version, confidence),
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # Screenshots
    # ------------------------------------------------------------------

    async def add_screenshot(
        self,
        subdomain_id: int,
        url: str,
        file_path: str,
        width: int = 1280,
        height: int = 800,
    ) -> None:
        """Insert or replace a screenshot metadata record."""
        conn = self._require_conn()

        await conn.execute(
            "INSERT OR REPLACE INTO screenshots "
            "(subdomain_id, url, file_path, width, height) "
            "VALUES (?, ?, ?, ?, ?)",
            (subdomain_id, url, file_path, width, height),
        )
        await conn.commit()

    async def get_screenshots(self, subdomain_id: int) -> List[ScreenshotRecord]:
        """Return all screenshot records for a subdomain."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, subdomain_id, url, file_path, width, height "
            "FROM screenshots WHERE subdomain_id = ?",
            (subdomain_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                ScreenshotRecord(
                    id=row[0],
                    subdomain_id=row[1],
                    url=row[2],
                    file_path=row[3],
                    width=row[4],
                    height=row[5],
                )
                for row in rows
            ]

    async def get_tech_records(self, subdomain_id: int) -> List[TechRecord]:
        """Return all technology records for a subdomain."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, subdomain_id, category, name, version, confidence "
            "FROM tech_records WHERE subdomain_id = ?",
            (subdomain_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                TechRecord(
                    id=row[0],
                    subdomain_id=row[1],
                    category=row[2],
                    name=row[3],
                    version=row[4],
                    confidence=row[5],
                )
                for row in rows
            ]

    async def get_dns_records(self, subdomain_id: int) -> List[DNSRecord]:
        """Return all DNS records for a subdomain."""
        conn = self._require_conn()

        async with conn.execute(
            "SELECT id, subdomain_id, record_type, value "
            "FROM dns_records WHERE subdomain_id = ?",
            (subdomain_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                DNSRecord(
                    id=row[0],
                    subdomain_id=row[1],
                    record_type=row[2],
                    value=row[3],
                )
                for row in rows
            ]
