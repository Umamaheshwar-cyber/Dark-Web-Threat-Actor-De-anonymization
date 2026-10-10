"""Local authorized test forum for evidence versioning and ephemeral-content analysis.

This module exposes an APIRouter. Register it later in backend/main.py.
It is not a standalone FastAPI application.
"""

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

router = APIRouter(tags=["test-forum"])

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
POSTS = {}


class CreatePostBody(BaseModel):
    alias: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)
    thread_id: str = Field(..., min_length=1)


class EditPostBody(BaseModel):
    content: str = Field(..., min_length=1)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _deletion_signal(seconds: float) -> str:
    if seconds <= 30:
        return "PANIC"
    if seconds <= 60:
        return "SUSPICIOUS"
    if seconds <= 300:
        return "QUICK CLEANUP"
    return "ROUTINE"


@router.get("/forum")
def forum_page():
    """Serve the local authorized test forum HTML page."""
    page = FRONTEND_DIR / "test_forum.html"
    if not page.exists():
        raise HTTPException(status_code=404, detail="frontend/test_forum.html not found")
    return FileResponse(page)


@router.post("/forum/posts")
def create_post(body: CreatePostBody):
    posted_at = _now()
    posted_iso = _iso(posted_at)
    post_id = str(uuid4())
    POSTS[post_id] = {
        "post_id": post_id,
        "alias": body.alias,
        "content": body.content,
        "thread_id": body.thread_id,
        "timestamp_posted": posted_iso,
        "timestamp_captured": posted_iso,
        "status": "active",
        "was_deleted": False,
        "deleted_at": None,
        "deletion_speed_seconds": None,
        "suspicious_deletion": False,
        "deletion_signal": None,
        "deletion_note": None,
        "edit_history": [
            {
                "version": 1,
                "content": body.content,
                "timestamp": posted_iso,
            }
        ],
        "screenshot": None,
    }
    return {
        "post_id": post_id,
        "timestamp_posted": posted_iso,
        "status": "active",
    }


@router.put("/forum/posts/{post_id}")
def edit_post(post_id: str, body: EditPostBody):
    post = POSTS.get(post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if post["was_deleted"]:
        raise HTTPException(status_code=400, detail="Cannot edit a deleted post")

    edited_at = _iso(_now())
    next_version = len(post["edit_history"]) + 1
    post["content"] = body.content
    post["status"] = "edited"
    post["edit_history"].append(
        {
            "version": next_version,
            "content": body.content,
            "timestamp": edited_at,
        }
    )
    return {
        "post_id": post_id,
        "edit_number": next_version - 1,
        "timestamp_edited": edited_at,
    }


@router.delete("/forum/posts/{post_id}")
def delete_post(post_id: str):
    post = POSTS.get(post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if post["was_deleted"]:
        return {
            "post_id": post_id,
            "timestamp_deleted": post["deleted_at"],
            "was_deleted": True,
        }

    deleted_at = _now()
    deleted_iso = _iso(deleted_at)
    posted_at = _parse_iso(post["timestamp_posted"])
    speed = (deleted_at - posted_at).total_seconds()
    speed_rounded = round(speed, 3)
    suspicious = speed <= 60
    note = None
    if suspicious:
        note = "PANIC DELETION -- deleted in %s seconds" % int(speed)

    post["status"] = "deleted"
    post["was_deleted"] = True
    post["deleted_at"] = deleted_iso
    post["deletion_speed_seconds"] = speed_rounded
    post["suspicious_deletion"] = suspicious
    post["deletion_signal"] = _deletion_signal(speed)
    post["deletion_note"] = note

    return {
        "post_id": post_id,
        "timestamp_deleted": deleted_iso,
        "was_deleted": True,
    }


@router.get("/forum/posts")
def list_posts():
    """Return all posts, including deleted posts and full edit history."""
    return list(POSTS.values())
