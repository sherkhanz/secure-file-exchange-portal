import os
import uuid
import hashlib
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_PATH      = os.environ.get("DB_PATH",                  "/data/db/portal.db")
STORAGE_PATH = os.environ.get("STORAGE_PATH",             "/data/files")
API_TOKEN    = os.environ.get("API_TOKEN",                 "supersecret-mock-token")
EXPIRY_MINS  = int(os.environ.get("DEFAULT_EXPIRY_MINUTES", "60"))
MAX_MB       = int(os.environ.get("MAX_UPLOAD_MB",          "20"))

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(STORAGE_PATH, exist_ok=True)

# ---------------------------------------------------------------------------
# Structured stdout audit log
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  AUDIT  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("portal")


def audit(event: str, **kwargs):
    parts = " | ".join(f"{k}={v}" for k, v in kwargs.items())
    log.info(f"event={event} | {parts}")


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                id           TEXT PRIMARY KEY,
                filename     TEXT NOT NULL,
                stored_name  TEXT NOT NULL,
                size_bytes   INTEGER,
                sha256       TEXT,
                created_at   TEXT
            );

            CREATE TABLE IF NOT EXISTS links (
                token        TEXT PRIMARY KEY,
                file_id      TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                revoked      INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id)
            );
        """)


init_db()

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Secure File Exchange Portal",
    version="0.1.0",
    description="POC — temporary file sharing with link lifecycle control.",
)


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------
def require_auth(x_api_token: Optional[str] = Header(default=None)):
    if x_api_token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Missing or invalid API token.")
    return x_api_token


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------
class LinkRequest(BaseModel):
    file_id: str
    expires_in_minutes: Optional[int] = EXPIRY_MINS


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """§3.7 — Liveness check. No auth required."""
    return {"status": "ok", "version": "0.1.0"}


# ── Upload ─────────────────────────────────────────────────────────────────

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    _auth: str = Depends(require_auth),
):

    contents = await file.read()

    if len(contents) > MAX_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413, detail=f"File exceeds {MAX_MB} MB limit."
        )

    file_id     = str(uuid.uuid4())
    stored_name = f"{file_id}_{file.filename}"
    dest        = os.path.join(STORAGE_PATH, stored_name)

    with open(dest, "wb") as fh:
        fh.write(contents)

    sha256 = hashlib.sha256(contents).hexdigest()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, file.filename, stored_name,
             len(contents), sha256, datetime.utcnow().isoformat()),
        )

    audit("upload_created",
          file_id=file_id, filename=file.filename,
          size_bytes=len(contents), sha256=sha256)

    return {
        "file_id":    file_id,
        "filename":   file.filename,
        "size_bytes": len(contents),
        "sha256":     sha256,
    }


# ── Create link ────────────────────────────────────────────────────────────

@app.post("/links")
def create_link(
    body: LinkRequest,
    _auth: str = Depends(require_auth),
):

    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM files WHERE id = ?", (body.file_id,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="File not found.")

    token      = str(uuid.uuid4())
    expires_at = (
        datetime.utcnow() + timedelta(minutes=body.expires_in_minutes)
    ).isoformat()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO links VALUES (?, ?, ?, 0, ?)",
            (token, body.file_id, expires_at, datetime.utcnow().isoformat()),
        )

    audit("link_generated",
          token=token, file_id=body.file_id, expires_at=expires_at)

    return {
        "token":        token,
        "expires_at":   expires_at,
        "download_url": f"/download/{token}",
    }


# ── Download ───────────────────────────────────────────────────────────────

@app.get("/download/{token}")
def download_file(token: str):

    with get_db() as conn:
        link = conn.execute(
            "SELECT * FROM links WHERE token = ?", (token,)
        ).fetchone()

    # ── Invalid token
    if not link:
        audit("failed_download", token=token, reason="token_not_found")
        raise HTTPException(status_code=404, detail="Token not found.")

    # ── Revoked
    if link["revoked"]:
        audit("revoked_link_access", token=token, file_id=link["file_id"])
        raise HTTPException(status_code=410, detail="This link has been revoked.")

    # ── Expired
    if datetime.utcnow() > datetime.fromisoformat(link["expires_at"]):
        audit("expired_link_access", token=token, file_id=link["file_id"])
        raise HTTPException(status_code=410, detail="This link has expired.")

    # ── Fetch file record
    with get_db() as conn:
        file_row = conn.execute(
            "SELECT * FROM files WHERE id = ?", (link["file_id"],)
        ).fetchone()

    if not file_row:
        audit("failed_download", token=token, reason="file_record_missing")
        raise HTTPException(status_code=404, detail="File record not found.")

    path = os.path.join(STORAGE_PATH, file_row["stored_name"])
    if not os.path.exists(path):
        audit("failed_download", token=token, reason="file_missing_on_disk")
        raise HTTPException(status_code=404, detail="File not found on storage.")

    audit("successful_download", token=token, file_id=link["file_id"])
    return FileResponse(path, filename=file_row["filename"])


# ── Revoke ─────────────────────────────────────────────────────────────────

@app.post("/revoke/{token}")
def revoke_link(
    token: str,
    _auth: str = Depends(require_auth),
):

    with get_db() as conn:
        link = conn.execute(
            "SELECT * FROM links WHERE token = ?", (token,)
        ).fetchone()

        if not link:
            raise HTTPException(status_code=404, detail="Token not found.")

        if link["revoked"]:
            return {"detail": "Token was already revoked.", "token": token}

        conn.execute(
            "UPDATE links SET revoked = 1 WHERE token = ?", (token,)
        )

    audit("link_revoked", token=token, file_id=link["file_id"])
    return {"detail": "Token successfully revoked.", "token": token}
