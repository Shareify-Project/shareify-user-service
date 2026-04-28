"""
Shareify User Service
- Register user
- Login user (JWT)
- Get user profile
- Get user by ID (inter-service)
"""

import os
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

app = FastAPI(title="Shareify User Service", version="1.0.0")
# -- POSTGRESQL HOTFIX: SQLite Polyfill --------------------------------------
# Automatically translates SQLite conn.execute() and '?' to PostgreSQL syntax
import psycopg2
from psycopg2.extensions import connection

def _sqlite_to_psycopg2_execute(self, query, vars=None):
    if '?' in query:
        query = query.replace('?', '%s')
    cursor = self.cursor()
    cursor.execute(query, vars)
    return cursor

connection.execute = _sqlite_to_psycopg2_execute
# ----------------------------------------------------------------------------
import time
from fastapi import Request
from prometheus_client import make_asgi_app, Counter, Histogram

# -- Prometheus Metrics ------------------------------------------------------
REQUEST_COUNT = Counter("http_requests_total", "Total requests", ["method", "endpoint", "http_status"])
REQUEST_LATENCY = Histogram("http_request_duration_seconds", "Latency", ["method", "endpoint"])

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    method = request.method
    endpoint = request.url.path
    if endpoint == "/metrics":
        return await call_next(request)
        
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    REQUEST_COUNT.labels(method=method, endpoint=endpoint, http_status=response.status_code).inc()
    REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(process_time)
    
    return response


# ── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET", "shareify-secret-key-2024")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "60"))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:shareify-secure-db-pass@postgres-db:5432/user_service")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()


# ── Database ────────────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


# ── Schemas ─────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    name: str
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


# ── Auth Helpers ────────────────────────────────────────────────────────────
def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Endpoints ───────────────────────────────────────────────────────────────
@app.post("/register")
def register(user: UserRegister):
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE email = ?", (user.email,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        user_id = str(uuid.uuid4())
        password_hash = pwd_context.hash(user.password)
        conn.execute(
            "INSERT INTO users (user_id, name, email, password_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, user.name, user.email, password_hash,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return {"message": "User registered successfully", "user_id": user_id}
    finally:
        conn.close()


@app.post("/login")
def login(user: UserLogin):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (user.email,)
        ).fetchone()
        if not row or not pwd_context.verify(user.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_token(row["user_id"], row["email"])
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": row["user_id"],
        }
    finally:
        conn.close()


@app.get("/profile")
def get_profile(payload: dict = Depends(verify_token)):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT user_id, name, email, created_at FROM users WHERE user_id = ?",
            (payload["user_id"],),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return dict(row)
    finally:
        conn.close()


@app.get("/users/{user_id}")
def get_user(user_id: str):
    """Inter-service endpoint – no auth required."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT user_id, name, email, created_at FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return dict(row)
    finally:
        conn.close()


@app.get("/health")
def health():
    return {"status": "healthy", "service": "shareify-user-service"}




