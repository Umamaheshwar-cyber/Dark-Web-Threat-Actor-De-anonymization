"""Central SQLite Database Layer for SHADOWTRACE.

Provides persistent, thread-safe relational storage and automatic JSON serialization
for captured dark web evidence, OPSEC decay telemetry, psycholinguistic profiles,
language ghost indicators, relationship graphs, and threat feeds.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "shadowtrace.db"

TABLE_SCHEMAS = {
    "captured_posts": """
        CREATE TABLE IF NOT EXISTS captured_posts (
          evidence_id TEXT PRIMARY KEY,
          post_id TEXT,
          thread_id TEXT,
          alias TEXT,
          content TEXT,
          timestamp_posted TEXT,
          timestamp_captured TEXT,
          capture_latency_ms REAL,
          was_deleted INTEGER DEFAULT 0,
          deleted_at TEXT,
          deletion_speed_seconds REAL,
          opsec_signal TEXT,
          opsec_score_impact INTEGER DEFAULT 0,
          edit_history TEXT,
          suspicious INTEGER DEFAULT 0,
          provenance TEXT,
          sha256_hash TEXT,
          version INTEGER DEFAULT 1,
          created_at TEXT
        );
    """,
    "opsec_scores": """
        CREATE TABLE IF NOT EXISTS opsec_scores (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          alias TEXT,
          post_id TEXT,
          timestamp TEXT,
          score INTEGER,
          signals_detected TEXT,
          score_impact INTEGER,
          created_at TEXT
        );
    """,
    "psycho_profiles": """
        CREATE TABLE IF NOT EXISTS psycho_profiles (
          alias TEXT PRIMARY KEY,
          post_count INTEGER DEFAULT 0,
          mean_avg_sentence_length REAL,
          mean_vocabulary_richness REAL,
          mean_punctuation_ratio REAL,
          mean_uppercase_ratio REAL,
          mean_exclamation_count REAL,
          mean_question_count REAL,
          mean_digit_ratio REAL,
          mean_stopword_ratio REAL,
          mean_avg_paragraph_length REAL,
          mean_ellipsis_count REAL,
          mean_bracket_usage REAL,
          mean_sentence_count REAL,
          common_misspellings TEXT,
          style_signature TEXT,
          last_updated TEXT,
          disclaimer TEXT
        );
    """,
    "language_profiles": """
        CREATE TABLE IF NOT EXISTS language_profiles (
          alias TEXT PRIMARY KEY,
          total_posts_analyzed INTEGER DEFAULT 0,
          language_family_votes TEXT,
          predicted_native_language_family TEXT,
          confidence_score REAL,
          confidence_level TEXT,
          script_confirmations TEXT,
          last_updated TEXT,
          disclaimer TEXT
        );
    """,
    "temporal_posts": """
        CREATE TABLE IF NOT EXISTS temporal_posts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          alias TEXT,
          post_id TEXT,
          timestamp TEXT,
          hour INTEGER,
          day_of_week INTEGER,
          day_name TEXT,
          created_at TEXT
        );
    """,
    "graph_nodes": """
        CREATE TABLE IF NOT EXISTS graph_nodes (
          node_id TEXT PRIMARY KEY,
          node_type TEXT,
          label TEXT,
          properties TEXT,
          first_seen TEXT,
          last_seen TEXT
        );
    """,
    "graph_edges": """
        CREATE TABLE IF NOT EXISTS graph_edges (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT,
          target TEXT,
          edge_type TEXT,
          confidence REAL,
          evidence_ids TEXT,
          first_seen TEXT,
          last_seen TEXT
        );
    """,
    "paste_events": """
        CREATE TABLE IF NOT EXISTS paste_events (
          event_id TEXT PRIMARY KEY,
          site_name TEXT,
          paste_id TEXT,
          full_url TEXT,
          is_raw INTEGER DEFAULT 0,
          is_self_destruct INTEGER DEFAULT 0,
          url_pattern TEXT,
          alias TEXT,
          post_id TEXT,
          detected_at TEXT
        );
    """,
    "feed_evidence": """
        CREATE TABLE IF NOT EXISTS feed_evidence (
          evidence_id TEXT PRIMARY KEY,
          source TEXT,
          ioc_type TEXT,
          ioc_value TEXT,
          threat_type TEXT,
          malware_family TEXT,
          actor_tags TEXT,
          country TEXT,
          confidence TEXT,
          first_seen TEXT,
          last_seen TEXT,
          provenance TEXT,
          sha256_hash TEXT,
          disclaimer TEXT,
          created_at TEXT
        );
    """,
    "otx_evidence": """
        CREATE TABLE IF NOT EXISTS otx_evidence (
          evidence_id TEXT PRIMARY KEY,
          pulse_id TEXT,
          pulse_name TEXT,
          author TEXT,
          actor_tags TEXT,
          malware_families TEXT,
          targeted_countries TEXT,
          ioc_type TEXT,
          ioc_value TEXT,
          description TEXT,
          first_seen TEXT,
          last_seen TEXT,
          provenance TEXT,
          sha256_hash TEXT,
          disclaimer TEXT,
          created_at TEXT
        );
    """,
    "artifact_analysis": """
        CREATE TABLE IF NOT EXISTS artifact_analysis (
          post_id TEXT PRIMARY KEY,
          alias TEXT,
          code_blocks_found INTEGER DEFAULT 0,
          line_ending TEXT,
          indentation TEXT,
          quote_style TEXT,
          unicode_artifacts TEXT,
          comment_style TEXT,
          inferred_os TEXT,
          inferred_editor TEXT,
          inferred_language TEXT,
          confidence REAL,
          analyzed_at TEXT,
          disclaimer TEXT
        );
    """,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    """Return a thread-safe connection with row_factory enabled."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=20.0)
    conn.row_factory = sqlite3.Row
    return conn


def _serialize_val(val: Any) -> Any:
    """Serialize Python objects (lists, dicts) to JSON strings."""
    if isinstance(val, (list, dict)):
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, bool):
        return int(val)
    return val


def _deserialize_val(val: Any) -> Any:
    """Deserialize JSON strings back to Python data structures."""
    if isinstance(val, str) and (val.startswith("{") or val.startswith("[")):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a sqlite3.Row to a deserialized Python dictionary."""
    out = {}
    for key in row.keys():
        out[key] = _deserialize_val(row[key])
    return out


def init_db() -> sqlite3.Connection:
    """Create all required tables and return an open connection."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        created_count = 0
        for table_name, schema_sql in TABLE_SCHEMAS.items():
            cursor.execute(schema_sql)
            created_count += 1
        conn.commit()
        print(f"[SHADOWTRACE DB] Initialized {created_count} tables in {DB_PATH}")
    except Exception as e:
        print(f"[SHADOWTRACE DB ERROR] Failed to initialize tables: {e}")
    return conn


# --- Database Helper Functions ---

def db_insert(table: str, data_dict: Dict[str, Any], or_replace: bool = True) -> bool:
    """Insert or replace a record with automatic JSON serialization."""
    if not data_dict:
        return False
    try:
        conn = get_connection()
        cols = list(data_dict.keys())
        serialized_vals = [_serialize_val(data_dict[c]) for c in cols]
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)

        verb = "INSERT OR REPLACE" if or_replace else "INSERT"
        sql = f"{verb} INTO {table} ({col_names}) VALUES ({placeholders})"

        with conn:
            conn.execute(sql, serialized_vals)
        return True
    except Exception as e:
        print(f"[DB INSERT ERROR] table={table}: {e}")
        return False


def db_get(table: str, where_col: str, where_val: Any) -> Optional[Dict[str, Any]]:
    """Retrieve a single record matching where_col = where_val."""
    try:
        conn = get_connection()
        sql = f"SELECT * FROM {table} WHERE {where_col} = ? LIMIT 1"
        cursor = conn.cursor()
        cursor.execute(sql, (where_val,))
        row = cursor.fetchone()
        return _row_to_dict(row) if row else None
    except Exception as e:
        print(f"[DB GET ERROR] table={table}: {e}")
        return None


def db_get_all(
    table: str,
    where_col: Optional[str] = None,
    where_val: Optional[Any] = None,
    limit: Optional[int] = None,
    order_by: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve all records, optionally filtered, ordered, or bounded."""
    try:
        conn = get_connection()
        sql = f"SELECT * FROM {table}"
        params: List[Any] = []

        if where_col is not None and where_val is not None:
            sql += f" WHERE {where_col} = ?"
            params.append(where_val)

        if order_by:
            sql += f" ORDER BY {order_by}"

        if limit:
            sql += f" LIMIT {int(limit)}"

        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        print(f"[DB GET ALL ERROR] table={table}: {e}")
        return []


def db_update(
    table: str,
    data_dict: Dict[str, Any],
    where_col: str,
    where_val: Any,
) -> bool:
    """Update fields in record(s) matching where_col = where_val."""
    if not data_dict:
        return False
    try:
        conn = get_connection()
        cols = list(data_dict.keys())
        set_clause = ", ".join([f"{c} = ?" for c in cols])
        vals = [_serialize_val(data_dict[c]) for c in cols]
        vals.append(where_val)

        sql = f"UPDATE {table} SET {set_clause} WHERE {where_col} = ?"
        with conn:
            conn.execute(sql, vals)
        return True
    except Exception as e:
        print(f"[DB UPDATE ERROR] table={table}: {e}")
        return False


def db_delete(table: str, where_col: str, where_val: Any) -> bool:
    """Delete record(s) matching where_col = where_val."""
    try:
        conn = get_connection()
        sql = f"DELETE FROM {table} WHERE {where_col} = ?"
        with conn:
            conn.execute(sql, (where_val,))
        return True
    except Exception as e:
        print(f"[DB DELETE ERROR] table={table}: {e}")
        return False


def db_count(table: str, where_col: Optional[str] = None, where_val: Optional[Any] = None) -> int:
    """Count records in a table with optional filter."""
    try:
        conn = get_connection()
        sql = f"SELECT COUNT(*) as cnt FROM {table}"
        params: List[Any] = []
        if where_col is not None and where_val is not None:
            sql += f" WHERE {where_col} = ?"
            params.append(where_val)

        cursor = conn.cursor()
        cursor.execute(sql, params)
        row = cursor.fetchone()
        return int(row["cnt"]) if row else 0
    except Exception as e:
        print(f"[DB COUNT ERROR] table={table}: {e}")
        return 0


def db_execute(query: str, params: Optional[Union[List[Any], Tuple[Any, ...]]] = None) -> List[Dict[str, Any]]:
    """Execute arbitrary raw SQL with parameters."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        if query.strip().upper().startswith("SELECT"):
            rows = cursor.fetchall()
            return [_row_to_dict(r) for r in rows]
        else:
            conn.commit()
            return []
    except Exception as e:
        print(f"[DB EXECUTE ERROR] sql={query}: {e}")
        return []


# Auto-initialize on module load
init_db()
