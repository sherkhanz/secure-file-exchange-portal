import os
import uuid
import hashlib
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

load_dotenv()

DB_PATH      = os.environ.get("DB_PATH",                   "/data/db/portal.db")
STORAGE_PATH = os.environ.get("STORAGE_PATH",              "/data/files")
API_TOKEN    = os.environ.get("API_TOKEN",                  "supersecret-mock-token")
EXPIRY_MINS  = int(os.environ.get("DEFAULT_EXPIRY_MINUTES", "60"))
MAX_MB       = int(os.environ.get("MAX_UPLOAD_MB",          "20"))
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".csv"}

BLOCKED_IPS: set = set()

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(STORAGE_PATH, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  AUDIT  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("portal")

limiter = Limiter(key_func=get_remote_address)


def get_audit_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TRIGGER IF NOT EXISTS protect_audit_log_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE not permitted');
        END;

        CREATE TRIGGER IF NOT EXISTS protect_audit_log_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: DELETE not permitted');
        END;
    """)
    return conn


def audit(event: str, **kwargs):
    parts = " | ".join(f"{k}={v}" for k, v in kwargs.items())
    log.info(f"event={event} | {parts}")

    detail = str(kwargs)
    try:
        with get_audit_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (event, detail, ts) VALUES (?, ?, ?)",
                (event, detail, datetime.utcnow().isoformat()),
            )
    except Exception as e:
        log.error(f"Failed to persist audit event: {e}")


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

            CREATE TABLE IF NOT EXISTS audit_log (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                event   TEXT NOT NULL,
                detail  TEXT,
                ts      TEXT NOT NULL
            );
        """)


init_db()


def cleanup_expired_files():
    with get_db() as conn:
        expired_files = conn.execute("""
            SELECT id, stored_name FROM files
            WHERE id NOT IN (
                SELECT file_id FROM links
                WHERE revoked = 0
                AND expires_at > datetime('now')
            )
        """).fetchall()

        for file_row in expired_files:
            file_path = os.path.join(STORAGE_PATH, file_row["stored_name"])
            if os.path.exists(file_path):
                os.remove(file_path)
                log.info(f"event=file_deleted | stored_name={file_row['stored_name']}")
            conn.execute("DELETE FROM links WHERE file_id = ?", (file_row["id"],))
            conn.execute("DELETE FROM files WHERE id = ?", (file_row["id"],))


app = FastAPI(
    title="Secure File Exchange Portal",
    version="0.1.0",
    description="POC — temporary file sharing with link lifecycle control.",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class IPBlacklistMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        if client_ip in BLOCKED_IPS:
            audit("blocked_request", ip=client_ip, path=request.url.path)
            return JSONResponse(
                status_code=403,
                content={"detail": f"Access denied. IP {client_ip} is blocked."}
            )
        return await call_next(request)


app.add_middleware(IPBlacklistMiddleware)


def require_auth(x_api_token: Optional[str] = Header(default=None)):
    if x_api_token != API_TOKEN:
        audit("unauthorized_request", reason="invalid_or_missing_token")
        raise HTTPException(status_code=401, detail="Missing or invalid API token.")
    return x_api_token


class LinkRequest(BaseModel):
    file_id: str
    expires_in_minutes: Optional[int] = EXPIRY_MINS


@app.get("/health")
def health():
    cleanup_expired_files()
    return {"status": "ok", "version": "0.1.0"}


@app.post("/block/{ip}")
def block_ip(ip: str, _auth: str = Depends(require_auth)):
    BLOCKED_IPS.add(ip)
    audit("ip_blocked", ip=ip)
    return {"detail": f"IP {ip} has been blocked.", "blocked_ips": list(BLOCKED_IPS)}


@app.post("/unblock/{ip}")
def unblock_ip(ip: str, _auth: str = Depends(require_auth)):
    BLOCKED_IPS.discard(ip)
    audit("ip_unblocked", ip=ip)
    return {"detail": f"IP {ip} has been unblocked.", "blocked_ips": list(BLOCKED_IPS)}


@app.get("/blocked")
def list_blocked(_auth: str = Depends(require_auth)):
    return {"blocked_ips": list(BLOCKED_IPS)}


@app.post("/upload")
@limiter.limit("5/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    _auth: str = Depends(require_auth),
):
    contents = await file.read()

    if len(contents) > MAX_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413, detail=f"File exceeds {MAX_MB} MB limit."
        )

    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=f"File type '{file_ext}' is not allowed. Permitted types: {sorted(ALLOWED_EXTENSIONS)}"
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


@app.get("/download/{token}")
@limiter.limit("5/minute")
def download_file(
    request: Request,
    token: str,
    _auth: str = Depends(require_auth),
):
    with get_db() as conn:
        link = conn.execute(
            "SELECT * FROM links WHERE token = ?", (token,)
        ).fetchone()

    if not link:
        audit("failed_download", token=token, reason="token_not_found")
        raise HTTPException(status_code=404, detail="Token not found.")

    if link["revoked"]:
        audit("revoked_link_access", token=token, file_id=link["file_id"])
        raise HTTPException(status_code=410, detail="This link has been revoked.")

    if datetime.utcnow() > datetime.fromisoformat(link["expires_at"]):
        audit("expired_link_access", token=token, file_id=link["file_id"])
        raise HTTPException(status_code=410, detail="This link has expired.")

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
