"""SQLite-backed knowledge graph for DFIR-Nexus.

Provides CRUD operations for entities (threat_actor, technique, detection,
campaign, tool, vulnerability, data_source), typed relations between them,
observations, decisions, and learnings.  All data is persisted in a local
SQLite database.  No external dependencies — uses only ``sqlite3``.

Design principles:
- Entities and relations are keyed by user-supplied string IDs.
- Relations carry a ``relation_type`` label and optional ``properties`` JSON.
- Observations, decisions, and learnings are first-class graph entries linked
  to entities or relations via foreign keys.
- All timestamps are ISO-8601 UTC strings.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

VALID_ENTITY_TYPES = frozenset({
    "threat_actor",
    "technique",
    "detection",
    "campaign",
    "tool",
    "vulnerability",
    "data_source",
})

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    name        TEXT NOT NULL,
    properties  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relations (
    id            TEXT PRIMARY KEY,
    source_id     TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_id     TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    properties    TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id          TEXT PRIMARY KEY,
    entity_id   TEXT REFERENCES entities(id) ON DELETE SET NULL,
    relation_id TEXT REFERENCES relations(id) ON DELETE SET NULL,
    content     TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    confidence  REAL NOT NULL DEFAULT 0.5,
    properties  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id          TEXT PRIMARY KEY,
    entity_id   TEXT REFERENCES entities(id) ON DELETE SET NULL,
    relation_id TEXT REFERENCES relations(id) ON DELETE SET NULL,
    decision    TEXT NOT NULL,
    rationale   TEXT NOT NULL DEFAULT '',
    outcome     TEXT NOT NULL DEFAULT '',
    properties  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS learnings (
    id          TEXT PRIMARY KEY,
    entity_id   TEXT REFERENCES entities(id) ON DELETE SET NULL,
    lesson      TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT '',
    properties  TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_relations_source ON relations(source_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_id);
CREATE INDEX IF NOT EXISTS idx_relations_type ON relations(relation_type);
CREATE INDEX IF NOT EXISTS idx_observations_entity ON observations(entity_id);
CREATE INDEX IF NOT EXISTS idx_decisions_entity ON decisions(entity_id);
CREATE INDEX IF NOT EXISTS idx_learnings_entity ON learnings(entity_id);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


class KnowledgeGraph:
    """SQLite-backed knowledge graph.

    Args:
        db_path: Path to the SQLite database file.  Created on first use.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self._path),
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA_SQL)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Entities ──────────────────────────────────────────────────────

    def create_entity(
        self,
        entity_type: str,
        name: str,
        *,
        entity_id: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Create a new entity and return its ID.

        Args:
            entity_type: One of the valid entity types.
            name: Human-readable name.
            entity_id: Optional caller-supplied ID.  Auto-generated if omitted.
            properties: Arbitrary JSON-serialisable properties.

        Returns:
            The entity ID.

        Raises:
            ValueError: If *entity_type* is not valid.
        """
        if entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(
                f"Invalid entity_type {entity_type!r}. "
                f"Must be one of {sorted(VALID_ENTITY_TYPES)}"
            )
        eid = entity_id or _new_id()
        now = _utcnow()
        props = json.dumps(properties or {}, ensure_ascii=False)
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO entities (id, entity_type, name, properties, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (eid, entity_type, name, props, now, now),
        )
        conn.commit()
        return eid

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        """Retrieve an entity by ID, or ``None`` if not found."""
        row = self._get_conn().execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "entity_type": row["entity_type"],
            "name": row["name"],
            "properties": json.loads(row["properties"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def update_entity(
        self,
        entity_id: str,
        *,
        name: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> bool:
        """Update an existing entity.  Returns ``True`` if a row was changed."""
        existing = self.get_entity(entity_id)
        if existing is None:
            return False
        new_name = name if name is not None else existing["name"]
        new_props = json.dumps(
            properties if properties is not None else existing["properties"],
            ensure_ascii=False,
        )
        now = _utcnow()
        self._get_conn().execute(
            "UPDATE entities SET name = ?, properties = ?, updated_at = ? WHERE id = ?",
            (new_name, new_props, now, entity_id),
        )
        self._get_conn().commit()
        return True

    def delete_entity(self, entity_id: str) -> bool:
        """Delete an entity and cascade to its relations.  Returns ``True`` if deleted."""
        cur = self._get_conn().execute(
            "DELETE FROM entities WHERE id = ?", (entity_id,)
        )
        self._get_conn().commit()
        return cur.rowcount > 0

    def list_entities(
        self,
        entity_type: str | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List entities, optionally filtered by type."""
        conn = self._get_conn()
        if entity_type:
            rows = conn.execute(
                "SELECT * FROM entities WHERE entity_type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (entity_type, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM entities ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "entity_type": r["entity_type"],
                "name": r["name"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    # ── Relations ─────────────────────────────────────────────────────

    def create_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        *,
        relation_id: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Create a relation between two entities.

        Args:
            source_id: ID of the source entity.
            target_id: ID of the target entity.
            relation_type: Label for the relation (e.g. ``"uses"``, ``"mitigates"``).
            relation_id: Optional caller-supplied ID.
            properties: Arbitrary JSON-serialisable properties.

        Returns:
            The relation ID.
        """
        rid = relation_id or _new_id()
        now = _utcnow()
        props = json.dumps(properties or {}, ensure_ascii=False)
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO relations (id, source_id, target_id, relation_type, properties, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rid, source_id, target_id, relation_type, props, now, now),
        )
        conn.commit()
        return rid

    def get_relation(self, relation_id: str) -> dict[str, Any] | None:
        """Retrieve a relation by ID."""
        row = self._get_conn().execute(
            "SELECT * FROM relations WHERE id = ?", (relation_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "source_id": row["source_id"],
            "target_id": row["target_id"],
            "relation_type": row["relation_type"],
            "properties": json.loads(row["properties"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def delete_relation(self, relation_id: str) -> bool:
        """Delete a relation.  Returns ``True`` if deleted."""
        cur = self._get_conn().execute(
            "DELETE FROM relations WHERE id = ?", (relation_id,)
        )
        self._get_conn().commit()
        return cur.rowcount > 0

    def list_relations(
        self,
        *,
        source_id: str | None = None,
        target_id: str | None = None,
        relation_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List relations with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if relation_type:
            clauses.append("relation_type = ?")
            params.append(relation_type)

        where = " AND ".join(clauses) if clauses else "1=1"
        params.extend([limit, offset])
        rows = self._get_conn().execute(
            f"SELECT * FROM relations WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [
            {
                "id": r["id"],
                "source_id": r["source_id"],
                "target_id": r["target_id"],
                "relation_type": r["relation_type"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    # ── Observations ──────────────────────────────────────────────────

    def add_observation(
        self,
        content: str,
        *,
        entity_id: str | None = None,
        relation_id: str | None = None,
        source: str = "",
        confidence: float = 0.5,
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Record an observation linked to an entity or relation.

        Returns:
            The observation ID.
        """
        oid = _new_id()
        now = _utcnow()
        props = json.dumps(properties or {}, ensure_ascii=False)
        self._get_conn().execute(
            "INSERT INTO observations (id, entity_id, relation_id, content, source, confidence, properties, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (oid, entity_id, relation_id, content, source, confidence, props, now),
        )
        self._get_conn().commit()
        return oid

    def list_observations(
        self,
        *,
        entity_id: str | None = None,
        relation_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List observations, optionally filtered by entity or relation."""
        if entity_id:
            rows = self._get_conn().execute(
                "SELECT * FROM observations WHERE entity_id = ? ORDER BY created_at DESC LIMIT ?",
                (entity_id, limit),
            ).fetchall()
        elif relation_id:
            rows = self._get_conn().execute(
                "SELECT * FROM observations WHERE relation_id = ? ORDER BY created_at DESC LIMIT ?",
                (relation_id, limit),
            ).fetchall()
        else:
            rows = self._get_conn().execute(
                "SELECT * FROM observations ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "entity_id": r["entity_id"],
                "relation_id": r["relation_id"],
                "content": r["content"],
                "source": r["source"],
                "confidence": r["confidence"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ── Decisions ─────────────────────────────────────────────────────

    def add_decision(
        self,
        decision: str,
        *,
        entity_id: str | None = None,
        relation_id: str | None = None,
        rationale: str = "",
        outcome: str = "",
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Record a decision linked to an entity or relation.

        Returns:
            The decision ID.
        """
        did = _new_id()
        now = _utcnow()
        props = json.dumps(properties or {}, ensure_ascii=False)
        self._get_conn().execute(
            "INSERT INTO decisions (id, entity_id, relation_id, decision, rationale, outcome, properties, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (did, entity_id, relation_id, decision, rationale, outcome, props, now),
        )
        self._get_conn().commit()
        return did

    def list_decisions(
        self,
        *,
        entity_id: str | None = None,
        relation_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List decisions, optionally filtered by entity or relation."""
        if entity_id:
            rows = self._get_conn().execute(
                "SELECT * FROM decisions WHERE entity_id = ? ORDER BY created_at DESC LIMIT ?",
                (entity_id, limit),
            ).fetchall()
        elif relation_id:
            rows = self._get_conn().execute(
                "SELECT * FROM decisions WHERE relation_id = ? ORDER BY created_at DESC LIMIT ?",
                (relation_id, limit),
            ).fetchall()
        else:
            rows = self._get_conn().execute(
                "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "entity_id": r["entity_id"],
                "relation_id": r["relation_id"],
                "decision": r["decision"],
                "rationale": r["rationale"],
                "outcome": r["outcome"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ── Learnings ─────────────────────────────────────────────────────

    def add_learning(
        self,
        lesson: str,
        *,
        entity_id: str | None = None,
        category: str = "",
        properties: dict[str, Any] | None = None,
    ) -> str:
        """Record a learning / lesson-learned entry.

        Returns:
            The learning ID.
        """
        lid = _new_id()
        now = _utcnow()
        props = json.dumps(properties or {}, ensure_ascii=False)
        self._get_conn().execute(
            "INSERT INTO learnings (id, entity_id, lesson, category, properties, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (lid, entity_id, lesson, category, props, now),
        )
        self._get_conn().commit()
        return lid

    def list_learnings(
        self,
        *,
        entity_id: str | None = None,
        category: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List learnings, optionally filtered by entity or category."""
        if entity_id:
            rows = self._get_conn().execute(
                "SELECT * FROM learnings WHERE entity_id = ? ORDER BY created_at DESC LIMIT ?",
                (entity_id, limit),
            ).fetchall()
        elif category:
            rows = self._get_conn().execute(
                "SELECT * FROM learnings WHERE category = ? ORDER BY created_at DESC LIMIT ?",
                (category, limit),
            ).fetchall()
        else:
            rows = self._get_conn().execute(
                "SELECT * FROM learnings ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "entity_id": r["entity_id"],
                "lesson": r["lesson"],
                "category": r["category"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ── Query helpers ─────────────────────────────────────────────────

    def get_entity_relations(
        self, entity_id: str, *, direction: str = "both"
    ) -> list[dict[str, Any]]:
        """Get all relations involving an entity.

        Args:
            entity_id: The entity to query.
            direction: ``"outgoing"``, ``"incoming"``, or ``"both"``.
        """
        conn = self._get_conn()
        rows: list[sqlite3.Row] = []
        if direction in ("outgoing", "both"):
            rows.extend(conn.execute(
                "SELECT * FROM relations WHERE source_id = ?", (entity_id,)
            ).fetchall())
        if direction in ("incoming", "both"):
            rows.extend(conn.execute(
                "SELECT * FROM relations WHERE target_id = ?", (entity_id,)
            ).fetchall())
        return [
            {
                "id": r["id"],
                "source_id": r["source_id"],
                "target_id": r["target_id"],
                "relation_type": r["relation_type"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def search_entities(
        self, query: str, *, entity_type: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Search entities by name (case-insensitive substring match)."""
        conn = self._get_conn()
        pattern = f"%{query}%"
        if entity_type:
            rows = conn.execute(
                "SELECT * FROM entities WHERE name LIKE ? AND entity_type = ? LIMIT ?",
                (pattern, entity_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM entities WHERE name LIKE ? LIMIT ?",
                (pattern, limit),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "entity_type": r["entity_type"],
                "name": r["name"],
                "properties": json.loads(r["properties"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def stats(self) -> dict[str, int]:
        """Return counts of entities by type and total relations."""
        conn = self._get_conn()
        result: dict[str, int] = {}
        for row in conn.execute(
            "SELECT entity_type, COUNT(*) as cnt FROM entities GROUP BY entity_type"
        ).fetchall():
            result[row["entity_type"]] = row["cnt"]
        row = conn.execute("SELECT COUNT(*) as cnt FROM relations").fetchone()
        result["relations"] = row["cnt"]
        return result
