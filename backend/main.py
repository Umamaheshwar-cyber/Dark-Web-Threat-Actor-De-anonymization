from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.routers import cases, actors, evidence, analytics, search, reports, feeds
from backend import test_forum
from backend import capture_engine
from backend import opsec_decay
from backend import psycho_linguistic
from backend import language_ghost
from backend import temporal_rhythm
from backend import relationship_graph
from backend import artifact_analysis
from backend import dead_drop
from backend import threat_feeds
from backend import otx_feed

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="SHADOWTRACE",
    description="Threat Actor Intelligence & Identity Correlation Platform — defensive intelligence platform using public/authorized CTI data",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount logical domain routers
app.include_router(cases.router)
app.include_router(actors.router)
app.include_router(evidence.router)
app.include_router(analytics.router)
app.include_router(search.router)
app.include_router(reports.router)
app.include_router(feeds.router)
app.include_router(feeds.circl_router)
app.include_router(test_forum.router)
app.include_router(capture_engine.router)
app.include_router(opsec_decay.router)
app.include_router(psycho_linguistic.router)
app.include_router(language_ghost.router)
app.include_router(temporal_rhythm.router)
app.include_router(relationship_graph.router)
app.include_router(artifact_analysis.router)
app.include_router(dead_drop.router)
app.include_router(threat_feeds.router)
app.include_router(otx_feed.router)

# Static frontend assets
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def root():
    """Serve the single-page dashboard shell."""
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/api/health")
def health():
    """Health and safety compliance probe."""
    return {
        "status": "ok",
        "mode": "authorized-cti",
        "platform": "SHADOWTRACE"
    }
