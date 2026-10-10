"""Copy-Paste Artifact Analysis Engine for Threat Actor Toolchain Profiling.

Extracts invisible syntactic artifacts (CRLF/LF line endings, tab vs space indentation,
smart quotes, zero-width Unicode characters, comments, and character encodings)
to infer operating system, text editor/IDE, and authoring workflow environments.

DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, HTTPException

from backend.database import db_get, db_get_all, db_insert

router = APIRouter(tags=["artifact-analysis"])

DISCLAIMER = "ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY"

_alias_posts: Dict[str, List[str]] = {}

# Unicode artifacts definitions
UNICODE_ARTIFACT_NAMES = {
    "\u200B": "ZERO_WIDTH_SPACE",
    "\u200C": "ZERO_WIDTH_NON_JOINER",
    "\u200D": "ZERO_WIDTH_JOINER",
    "\uFEFF": "BOM",
    "\u200F": "RTL_MARK",
    "\u00A0": "NON_BREAKING_SPACE",
}

SMART_QUOTES = {"“", "”", "‘", "’", "«", "»", "„"}
STRAIGHT_QUOTES = {'"', "'"}

FENCED_CODE_REGEX = re.compile(r"```(?:[a-zA-Z0-9_\-]+)?\s*\n?([\s\S]*?)```")
INLINE_CODE_REGEX = re.compile(r"`([^`\n]+)`")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_code_blocks(text: str) -> List[str]:
    """Extract code blocks from markdown fences, inline code, or indented text."""
    blocks: List[str] = []

    # 1. Fenced code blocks
    fenced = FENCED_CODE_REGEX.findall(text)
    if fenced:
        blocks.extend([b.strip() for b in fenced if b.strip()])

    # 2. Indented code blocks (4+ spaces or tabs on non-empty lines)
    indented_lines = []
    for line in text.split("\n"):
        if line.startswith("    ") or line.startswith("\t"):
            indented_lines.append(line)
        elif indented_lines:
            block = "\n".join(indented_lines).strip()
            if block:
                blocks.append(block)
            indented_lines = []
    if indented_lines:
        block = "\n".join(indented_lines).strip()
        if block:
            blocks.append(block)

    # 3. Inline code
    inline = INLINE_CODE_REGEX.findall(text)
    if inline and not blocks:
        blocks.extend([i.strip() for i in inline if len(i.strip()) > 5])

    # 4. Any block with programming keywords or comments
    if not blocks:
        if re.search(r"\b(def|class|import|function|var|const|let|return|select|from|sudo)\b", text) or text.strip().startswith("#"):
            blocks.append(text)

    return blocks


def detect_line_endings(text: str) -> str:
    """Analyze CRLF vs LF vs CR line endings."""
    crlf = text.count("\r\n")
    # Remove CRLF before counting remaining bare \n or \r
    stripped = text.replace("\r\n", "")
    lf = stripped.count("\n")
    cr = stripped.count("\r")

    if crlf > 0 and lf == 0 and cr == 0:
        return "WINDOWS"
    if lf > 0 and crlf == 0 and cr == 0:
        return "UNIX"
    if cr > 0 and crlf == 0 and lf == 0:
        return "MAC_CLASSIC"
    if (crlf + lf + cr) == 0:
        return "UNKNOWN"
    return "MIXED"


def detect_indentation(text: str) -> str:
    """Analyze tab vs space indentation and space widths."""
    tab_count = 0
    space_widths: List[int] = []

    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("\t"):
            tab_count += 1
        elif line.startswith(" "):
            # Count leading spaces
            match = re.match(r"^( +)", line)
            if match:
                width = len(match.group(1))
                space_widths.append(width)

    if tab_count > 0 and not space_widths:
        return "TABS"
    if space_widths and tab_count == 0:
        # Determine common modular width (2, 4, 8)
        counts = {2: 0, 4: 0, 8: 0}
        for w in space_widths:
            if w % 8 == 0:
                counts[8] += 1
            elif w % 4 == 0:
                counts[4] += 1
            elif w % 2 == 0:
                counts[2] += 1
        best = max(counts, key=counts.get)
        if counts[best] > 0:
            return f"{best}_SPACES"
        return "4_SPACES"
    if tab_count > 0 and space_widths:
        return "MIXED"
    return "NONE"


def detect_quote_style(text: str) -> str:
    """Detect presence of typographic smart quotes vs straight programming quotes."""
    smart_count = sum(text.count(q) for q in SMART_QUOTES)
    straight_count = sum(text.count(q) for q in STRAIGHT_QUOTES)

    if smart_count > 0 and straight_count == 0:
        return "SMART_QUOTES"
    if straight_count > 0 and smart_count == 0:
        return "STRAIGHT_QUOTES"
    if smart_count > 0 and straight_count > 0:
        return "MIXED"
    return "NONE"


def detect_unicode_artifacts(text: str) -> List[str]:
    """Find invisible or control Unicode markers."""
    found = []
    for char, name in UNICODE_ARTIFACT_NAMES.items():
        if char in text:
            found.append(name)
    return found


def detect_comment_style_and_language(text: str) -> Tuple[str, str]:
    """Detect comment syntax and infer the primary programming language."""
    c_style = bool(re.search(r"//|/\*", text))
    py_style = bool(re.search(r"#(?!\s*[0-9a-fA-F]{3,6}\b)", text))  # Avoid hex color codes
    sql_style = bool(re.search(r"--", text))

    lang = "UNKNOWN"
    lower = text.lower()

    if "def " in text or "import " in text or py_style and ("self." in text or "print(" in text):
        lang = "PYTHON"
    elif "function " in text or "const " in text or "let " in text or "console.log" in text:
        lang = "JAVASCRIPT"
    elif "#include" in text or "int main" in text or "printf(" in text or "std::" in text:
        lang = "C_CPP"
    elif "select " in lower and "from " in lower:
        lang = "SQL"
    elif "#!/bin/" in text or "sudo " in text or "chmod " in text:
        lang = "SHELL"

    if py_style:
        comment_style = "PYTHON"
    elif c_style:
        comment_style = "C_STYLE"
    elif sql_style:
        comment_style = "SQL"
    else:
        comment_style = "NONE"

    if lang == "UNKNOWN" and comment_style == "PYTHON":
        lang = "PYTHON"

    return comment_style, lang


def detect_trailing_whitespace(text: str) -> int:
    """Count lines with trailing whitespace."""
    count = 0
    for line in text.splitlines():
        if re.search(r"[ \t]+$", line):
            count += 1
    return count


def infer_environment(
    line_ending: str,
    indentation: str,
    quote_style: str,
    unicode_artifacts: List[str],
    comment_style: str,
    inferred_language: str,
    trailing_whitespace_count: int,
) -> Tuple[str, str, float]:
    """Infer Operating System and Editor based on extracted artifact rules."""
    os_votes = Counter()
    editor_votes = Counter()
    confidence = 0.60

    # OS inference
    if line_ending == "WINDOWS":
        os_votes["WINDOWS"] += 3
        confidence += 0.15
    elif line_ending == "UNIX":
        os_votes["LINUX"] += 2
        os_votes["MAC"] += 1
        confidence += 0.10

    if "BOM" in unicode_artifacts:
        os_votes["WINDOWS"] += 2
        editor_votes["NOTEPAD"] += 3
        confidence += 0.15

    if quote_style == "SMART_QUOTES":
        os_votes["MAC"] += 1
        os_votes["WINDOWS"] += 1
        editor_votes["WORD_OR_PAGES"] += 3

    # Editor inference
    if indentation == "4_SPACES":
        editor_votes["VS_CODE"] += 2
    elif indentation == "2_SPACES":
        editor_votes["VS_CODE"] += 1
        editor_votes["SUBLIME_TEXT"] += 1
    elif indentation == "TABS":
        editor_votes["VIM"] += 2
        editor_votes["NOTEPAD++"] += 1

    if line_ending == "WINDOWS" and indentation in ("4_SPACES", "NONE") and "NOTEPAD" not in editor_votes:
        editor_votes["VS_CODE"] += 1
        editor_votes["NOTEPAD++"] += 1

    inferred_os = os_votes.most_common(1)[0][0] if os_votes else ("WINDOWS" if line_ending == "WINDOWS" else "LINUX")
    inferred_editor = editor_votes.most_common(1)[0][0] if editor_votes else "VS_CODE"

    confidence = min(0.95, round(confidence, 2))
    return inferred_os, inferred_editor, confidence


def analyze_text(text: str, post_id: str = "unknown", alias: str = "unknown") -> Dict[str, Any]:
    """Full copy-paste and syntax artifact extraction on post content."""
    blocks = extract_code_blocks(text)
    code_text = "\n\n".join(blocks) if blocks else text

    line_ending = detect_line_endings(text)
    indentation = detect_indentation(text)
    if indentation == "NONE" and code_text:
        indentation = detect_indentation(code_text)
    quote_style = detect_quote_style(text)
    unicode_arts = detect_unicode_artifacts(text)
    comment_style, lang = detect_comment_style_and_language(text)
    if lang == "UNKNOWN" and code_text:
        comment_style, lang = detect_comment_style_and_language(code_text)
    trailing_ws = detect_trailing_whitespace(text)

    # Locale hints from non-ASCII characters
    non_ascii = [c for c in text if ord(c) > 127 and c not in UNICODE_ARTIFACT_NAMES and c not in SMART_QUOTES]
    locale_hints = []
    if any("\u0400" <= c <= "\u04ff" for c in non_ascii):
        locale_hints.append("CYRILLIC_CHARACTERS")
    if any("\u4e00" <= c <= "\u9fff" for c in non_ascii):
        locale_hints.append("CJK_CHARACTERS")
    if any("\u00c0" <= c <= "\u00ff" for c in non_ascii):
        locale_hints.append("LATIN_EXTENDED")

    inferred_os, inferred_editor, conf = infer_environment(
        line_ending=line_ending,
        indentation=indentation,
        quote_style=quote_style,
        unicode_artifacts=unicode_arts,
        comment_style=comment_style,
        inferred_language=lang,
        trailing_whitespace_count=trailing_ws,
    )

    return {
        "post_id": post_id,
        "alias": alias,
        "code_blocks_found": len(blocks),
        "line_ending": line_ending,
        "indentation": indentation,
        "quote_style": quote_style,
        "unicode_artifacts": unicode_arts,
        "comment_style": comment_style,
        "inferred_os": inferred_os,
        "inferred_editor": inferred_editor,
        "inferred_language": lang,
        "locale_hints": locale_hints,
        "trailing_whitespace_lines": trailing_ws,
        "confidence": conf,
        "analyzed_at": _now_iso(),
        "disclaimer": DISCLAIMER,
    }


def update_alias_profile(alias: str) -> Optional[Dict[str, Any]]:
    """Aggregate all post artifact evaluations into an alias environment profile."""
    analyses = db_get_all("artifact_analysis", "alias", alias)
    if not analyses:
        return None

    total_with_code = sum(1 for a in analyses if a.get("code_blocks_found", 0) > 0 or a.get("inferred_language") != "UNKNOWN")

    os_counts = Counter(a.get("inferred_os") for a in analyses if a.get("inferred_os"))
    editor_counts = Counter(a.get("inferred_editor") for a in analyses if a.get("inferred_editor"))
    lang_counts = Counter(a.get("inferred_language") for a in analyses if a.get("inferred_language") != "UNKNOWN")

    dominant_os = os_counts.most_common(1)[0][0] if os_counts else "UNKNOWN"
    dominant_editor = editor_counts.most_common(1)[0][0] if editor_counts else "UNKNOWN"
    dominant_lang = lang_counts.most_common(1)[0][0] if lang_counts else "UNKNOWN"

    total_unicode = 0
    for a in analyses:
        u = a.get("unicode_artifacts") or []
        if isinstance(u, list):
            total_unicode += len(u)

    # Consistency score = frequency of dominant OS
    dominant_os_count = os_counts.get(dominant_os, 0)
    consistency = round(dominant_os_count / len(analyses), 2) if analyses else 1.0

    profile = {
        "alias": alias,
        "total_posts_analyzed": len(analyses),
        "total_posts_with_code": total_with_code,
        "dominant_os": dominant_os,
        "dominant_editor": dominant_editor,
        "dominant_language": dominant_lang,
        "unicode_artifact_count": total_unicode,
        "environment_consistency": consistency,
        "disclaimer": DISCLAIMER,
    }

    return profile


def analyze_post(evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Hook called from capture_engine for every captured post."""
    try:
        alias = evidence.get("alias")
        if not alias:
            return None

        post_id = evidence.get("post_id") or evidence.get("evidence_id") or "UNKNOWN"
        content = evidence.get("content") or ""

        analysis = analyze_text(content, post_id=post_id, alias=alias)
        db_insert("artifact_analysis", analysis)
        return analysis
    except Exception:
        return None


# --- API Endpoints ---

@router.get("/artifacts/profiles")
def get_all_artifact_profiles() -> List[Dict[str, Any]]:
    """Retrieve environment and toolchain profiles for all tracked aliases."""
    analyses = db_get_all("artifact_analysis")
    aliases = sorted(set(a["alias"] for a in analyses if a.get("alias")))
    return [p for p in [update_alias_profile(a) for a in aliases] if p]


@router.get("/artifacts/profiles/{alias}")
def get_single_artifact_profile(alias: str) -> Dict[str, Any]:
    """Retrieve detailed artifact and toolchain analysis for a single alias."""
    prof = update_alias_profile(alias)
    if not prof:
        raise HTTPException(status_code=404, detail=f"No artifact profile found for alias '{alias}'")

    posts = db_get_all("artifact_analysis", "alias", alias)

    return {
        "profile": prof,
        "posts": posts,
        "disclaimer": DISCLAIMER,
    }


@router.get("/artifacts/posts/{post_id}")
def get_single_post_artifacts(post_id: str) -> Dict[str, Any]:
    """Retrieve copy-paste artifact extraction for a single post."""
    art = db_get("artifact_analysis", "post_id", post_id)
    if not art:
        raise HTTPException(status_code=404, detail=f"No artifact analysis found for post '{post_id}'")
    return art


@router.get("/artifacts/stats")
def get_artifact_stats() -> Dict[str, Any]:
    """Retrieve global environment statistics across all analyzed posts."""
    analyses = db_get_all("artifact_analysis")
    aliases = sorted(set(a["alias"] for a in analyses if a.get("alias")))
    os_dist: Dict[str, int] = Counter()
    editor_dist: Dict[str, int] = Counter()

    for p in analyses:
        os_dist[p.get("inferred_os", "UNKNOWN")] += 1
        editor_dist[p.get("inferred_editor", "UNKNOWN")] += 1

    return {
        "total_posts_analyzed": len(analyses),
        "total_aliases_profiled": len(aliases),
        "os_distribution": dict(os_dist),
        "editor_distribution": dict(editor_dist),
        "disclaimer": DISCLAIMER,
    }
