import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import data_store

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Redirect synthetic regression cases to tests/fixtures/
SYNTHETIC_FIXTURE_FILES = {
    "CASE-2026-09X": FIXTURES_DIR / "case_2026_09x.json",
    "CASE-SYN-001": FIXTURES_DIR / "case_2026_09x.json",
    "CASE-2026-02B": FIXTURES_DIR / "case_2026_02b.json",
    "CASE-SYN-002": FIXTURES_DIR / "case_2026_02b.json",
    "CASE-2026-03C": FIXTURES_DIR / "case_2026_03c.json",
    "CASE-SYN-003": FIXTURES_DIR / "case_2026_03c.json",
}

for cid, fixture_path in SYNTHETIC_FIXTURE_FILES.items():
    data_store.CASE_FILES[cid] = fixture_path

# In-process test harness routing for synthetic fixture import tests
import urllib.request
import io
import json

_original_urlopen = urllib.request.urlopen

class _MockHTTPResponse:
    def __init__(self, data_bytes: bytes, status: int = 200, headers: dict = None):
        self._fp = io.BytesIO(data_bytes)
        self.status = status
        self.code = status
        self.headers = headers or {"Content-Type": "application/json"}

    def read(self, *args):
        return self._fp.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

def _test_urlopen_wrapper(req, *args, **kwargs):
    url = getattr(req, "full_url", req) if not isinstance(req, str) else req
    if isinstance(req, urllib.request.Request) and "/api/feeds/misp/import" in url and req.data:
        try:
            body = json.loads(req.data.decode("utf-8"))
            cid = body.get("case_id")
            if cid in SYNTHETIC_FIXTURE_FILES:
                from backend.routers.feeds import import_misp_to_case, MISPImportRequest
                res = import_misp_to_case(MISPImportRequest(case_id=cid, mock_event=body.get("mock_event")))
                resp_bytes = res.model_dump_json().encode("utf-8")
                return _MockHTTPResponse(resp_bytes, 200)
        except Exception:
            pass

    return _original_urlopen(req, *args, **kwargs)

urllib.request.urlopen = _test_urlopen_wrapper

