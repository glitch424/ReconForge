import aiosqlite
from typing import List, Optional
from async_recon.database.models import SubdomainRecord
import logging

logger = logging.getLogger(__name__)


class DatabaseStore:
    def __init__(self, db_path: str = "recon.db") -> None:
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.execute("PRAGMA foreign_keys = ON;")
        await self._conn.commit()

    async def disconnect(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def init_schema(self) -> None:
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.executescript("""
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
        """)
        await self._conn.commit()

    async def add_subdomain(self, target: str, subdomain: str, source: str) -> int:
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.execute(
            """
            INSERT OR IGNORE INTO subdomains (target, subdomain, source)
            VALUES (?, ?, ?)
            """,
            (target, subdomain, source),
        )
        await self._conn.commit()

        async with self._conn.execute(
            "SELECT id FROM subdomains WHERE target = ? AND subdomain = ?",
            (target, subdomain),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return int(row[0])
            raise RuntimeError("Failed to retrieve subdomain ID after insert.")

    async def get_unresolved_subdomains(self) -> List[SubdomainRecord]:
        if not self._conn:
            raise RuntimeError("Database not connected")

        async with self._conn.execute(
            "SELECT id, target, subdomain, source, resolved, is_wildcard FROM subdomains WHERE resolved = 0"
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
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.execute(
            "UPDATE subdomains SET resolved = 1, is_wildcard = ? WHERE id = ?",
            (is_wildcard, subdomain_id),
        )
        await self._conn.commit()

    async def add_dns_record(
        self, subdomain_id: int, record_type: str, value: str
    ) -> None:
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.execute(
            "INSERT INTO dns_records (subdomain_id, record_type, value) VALUES (?, ?, ?)",
            (subdomain_id, record_type, value),
        )
        await self._conn.commit()
