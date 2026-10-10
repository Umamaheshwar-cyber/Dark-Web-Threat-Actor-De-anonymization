"""Ephemeral content capture engine for the local authorized test forum.

Polls the in-process GET /forum/posts data every 2 seconds, snapshots new posts,
tracks edits and deletions, and stores captured evidence in memory.

This module is an APIRouter. Register it later in backend/main.py.
Do not run it as a standalone application.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from backend.database import db_count, db_get, db_get_all, db_insert, init_db

router = APIRouter(tags=["capture"])

_POLL_SECONDS = 2
_latest_by_post = {}
_known_posts = {}
_capture_task = None
_started = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _log(event: str, detail: str) -> None:
    print("[%s] CAPTURE %s: %s" % (_iso(_now()), event, detail), flush=True)


def _parse_iso(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _sha256(content: str) -> str:
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()


def _opsec(seconds: float):
    if seconds <= 30:
        return "PANIC", -25
    if seconds <= 60:
        return "SUSPICIOUS", -15
    if seconds <= 300:
        return "QUICK CLEANUP", -10
    return "ROUTINE", -5


def _evidence_id(post_id: str, version: int) -> str:
    return "CAP-EV-%s-%s" % (post_id, version)


def _capture_latency_ms(posted_iso: str, captured_at: datetime) -> float:
    posted = _parse_iso(posted_iso)
    if posted is None:
        return 0.0
    if posted.tzinfo is None:
        posted = posted.replace(tzinfo=timezone.utc)
    return round((captured_at - posted).total_seconds() * 1000.0, 3)


def _fetch_forum_posts():
    """Read the same in-memory collection served by GET /forum/posts."""
    from backend import test_forum

    return test_forum.list_posts()


def _make_evidence(post: dict, version: int, captured_at: datetime, content: str) -> dict:
    post_id = str(post.get("post_id") or "")
    return {
        "evidence_id": _evidence_id(post_id, version),
        "post_id": post_id,
        "thread_id": post.get("thread_id"),
        "alias": post.get("alias"),
        "content": content,
        "timestamp_posted": post.get("timestamp_posted"),
        "timestamp_captured": _iso(captured_at),
        "capture_latency_ms": _capture_latency_ms(post.get("timestamp_posted"), captured_at),
        "was_deleted": False,
        "deleted_at": None,
        "deletion_speed_seconds": None,
        "opsec_signal": None,
        "opsec_score_impact": 0,
        "edit_history": [],
        "suspicious": False,
        "provenance": "LOCAL_TEST_FORUM_CAPTURE",
        "sha256_hash": _sha256(content),
        "version": version,
        "created_at": _iso(captured_at),
    }


def _apply_deletion(record: dict, post: dict | None, captured_at: datetime) -> None:
    if record.get("was_deleted"):
        return

    deleted_at = None
    posted_at = _parse_iso(record.get("timestamp_posted"))
    if post:
        deleted_at = _parse_iso(post.get("deleted_at"))
    if deleted_at is None:
        deleted_at = captured_at
    if posted_at is None:
        posted_at = deleted_at
    if posted_at and posted_at.tzinfo is None:
        posted_at = posted_at.replace(tzinfo=timezone.utc)
    if deleted_at.tzinfo is None:
        deleted_at = deleted_at.replace(tzinfo=timezone.utc)

    speed = max(0.0, (deleted_at - posted_at).total_seconds())
    signal, impact = _opsec(speed)
    suspicious = speed <= 60

    record["was_deleted"] = True
    record["deleted_at"] = _iso(deleted_at)
    record["deletion_speed_seconds"] = round(speed, 3)
    record["opsec_signal"] = signal
    record["opsec_score_impact"] = impact
    record["suspicious"] = suspicious


def _process_posts(posts) -> None:
    captured_at = _now()
    current_ids = set()

    for post in posts or []:
        if not isinstance(post, dict):
            continue
        post_id = str(post.get("post_id") or "")
        if not post_id:
            continue
        current_ids.add(post_id)
        content = post.get("content") if post.get("content") is not None else ""
        deleted = bool(post.get("was_deleted")) or post.get("status") == "deleted"

        known = _known_posts.get(post_id)
        if known is None:
            version = 1
            record = _make_evidence(post, version, captured_at, content)
            try:
                db_insert("captured_posts", record)
            except Exception:
                pass
            try:
                from backend.opsec_decay import score_post
                score_post(record)
            except Exception:
                pass
            try:
                from backend.psycho_linguistic import profile_post
                profile_post(record)
            except Exception:
                pass
            try:
                from backend.language_ghost import analyze_post
                analyze_post(record)
            except Exception:
                pass
            try:
                from backend.temporal_rhythm import log_post
                log_post(record)
            except Exception:
                pass
            try:
                from backend.relationship_graph import process_post
                process_post(record)
            except Exception:
                pass
            try:
                from backend.artifact_analysis import analyze_post
                analyze_post(record)
            except Exception:
                pass
            try:
                from backend.dead_drop import process_post
                process_post(record)
            except Exception:
                pass
            _latest_by_post[post_id] = record["evidence_id"]
            _known_posts[post_id] = {
                "content": content,
                "version": version,
                "deleted": False,
            }
            _log(
                "NEW",
                "post_id=%s alias=%s latency_ms=%s" % (
                    post_id,
                    post.get("alias"),
                    record["capture_latency_ms"],
                ),
            )
            if deleted:
                _apply_deletion(record, post, captured_at)
                try:
                    db_insert("captured_posts", record)
                except Exception:
                    pass
                _known_posts[post_id]["deleted"] = True
                _log(
                    "DELETE",
                    "post_id=%s signal=%s speed=%ss" % (
                        post_id,
                        record["opsec_signal"],
                        record["deletion_speed_seconds"],
                    ),
                )
            continue

        if content != known.get("content") and not known.get("deleted"):
            old_content = known.get("content")
            new_version = int(known.get("version") or 1) + 1
            latest_id = _latest_by_post.get(post_id)
            prior = db_get("captured_posts", "evidence_id", latest_id) if latest_id else None
            history_entry = {
                "version": new_version,
                "old_content": old_content,
                "new_content": content,
                "timestamp": _iso(captured_at),
            }
            record = _make_evidence(post, new_version, captured_at, content)
            if prior:
                record["edit_history"] = list(prior.get("edit_history") or [])
                record["timestamp_posted"] = prior.get("timestamp_posted")
                record["capture_latency_ms"] = prior.get("capture_latency_ms")
            record["edit_history"].append(history_entry)
            try:
                db_insert("captured_posts", record)
            except Exception:
                pass
            try:
                from backend.opsec_decay import score_post
                score_post(record)
            except Exception:
                pass
            try:
                from backend.psycho_linguistic import profile_post
                profile_post(record)
            except Exception:
                pass
            try:
                from backend.language_ghost import analyze_post
                analyze_post(record)
            except Exception:
                pass
            try:
                from backend.temporal_rhythm import log_post
                log_post(record)
            except Exception:
                pass
            try:
                from backend.relationship_graph import process_post
                process_post(record)
            except Exception:
                pass
            try:
                from backend.artifact_analysis import analyze_post
                analyze_post(record)
            except Exception:
                pass
            try:
                from backend.dead_drop import process_post
                process_post(record)
            except Exception:
                pass
            _latest_by_post[post_id] = record["evidence_id"]
            known["content"] = content
            known["version"] = new_version
            _log(
                "EDIT",
                "post_id=%s version=%s" % (post_id, new_version),
            )

        if deleted and not known.get("deleted"):
            latest_id = _latest_by_post.get(post_id)
            record = db_get("captured_posts", "evidence_id", latest_id) if latest_id else None
            if record:
                _apply_deletion(record, post, captured_at)
                try:
                    db_insert("captured_posts", record)
                except Exception:
                    pass
                _log(
                    "DELETE",
                    "post_id=%s signal=%s speed=%ss" % (
                        post_id,
                        record["opsec_signal"],
                        record["deletion_speed_seconds"],
                    ),
                )
            known["deleted"] = True

    for post_id, known in list(_known_posts.items()):
        if post_id in current_ids or known.get("deleted"):
            continue
        latest_id = _latest_by_post.get(post_id)
        record = db_get("captured_posts", "evidence_id", latest_id) if latest_id else None
        if record:
            _apply_deletion(record, None, captured_at)
            try:
                db_insert("captured_posts", record)
            except Exception:
                pass
            _log(
                "DELETE",
                "post_id=%s signal=%s speed=%ss (missing from feed)" % (
                    post_id,
                    record["opsec_signal"],
                    record["deletion_speed_seconds"],
                ),
            )
        known["deleted"] = True


async def _capture_loop() -> None:
    _log("START", "polling GET /forum/posts every %ss" % _POLL_SECONDS)
    while True:
        try:
            posts = _fetch_forum_posts()
            _process_posts(posts)
        except asyncio.CancelledError:
            _log("STOP", "capture loop cancelled")
            raise
        except Exception as exc:
            _log("ERROR", str(exc))
        try:
            await asyncio.sleep(_POLL_SECONDS)
        except asyncio.CancelledError:
            _log("STOP", "capture loop cancelled")
            raise


async def start_capture_engine() -> None:
    """Start the background poller once. Safe to call from FastAPI startup."""
    global _capture_task, _started
    if _started and _capture_task is not None and not _capture_task.done():
        return
    _started = True
    _capture_task = asyncio.create_task(_capture_loop())


@router.on_event("startup")
async def _on_startup():
    init_db()
    await start_capture_engine()


@router.get("/capture/evidence")
def list_captured_evidence():
    return db_get_all("captured_posts")


@router.get("/capture/evidence/{evidence_id}")
def get_captured_evidence(evidence_id: str):
    record = db_get("captured_posts", "evidence_id", evidence_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return record


@router.get("/capture/stats")
def capture_stats():
    total_captured = db_count("captured_posts")
    total_deleted = db_count("captured_posts", "was_deleted", 1)
    total_suspicious = db_count("captured_posts", "suspicious", 1)
    records = db_get_all("captured_posts")
    total_edits = sum(len(rec.get("edit_history") or []) for rec in records)
    return {
        "total_captured": len(_known_posts) if _known_posts else total_captured,
        "total_deleted": total_deleted,
        "total_suspicious": total_suspicious,
        "total_edits": total_edits,
        "total_evidence_records": total_captured,
    }
