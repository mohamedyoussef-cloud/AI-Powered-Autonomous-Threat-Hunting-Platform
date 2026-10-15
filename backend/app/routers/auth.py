
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel


router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.environ.get("THREATHUNT_AUTH_DB_PATH") or DATA_DIR / "auth.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

JWT_SECRET = os.environ.get(
    "THREATHUNT_AUTH_SECRET",
    "CHANGE_THIS_THREATHUNT_SECRET_IN_PRODUCTION"
)

TOKEN_TTL = 60 * 60 * 8

# Explicit production opt-in. Development demo accounts must never become
# Internet-accessible accounts through a default configuration.
PRODUCTION = os.environ.get("THREATHUNT_ENV", "development").strip().lower() == "production"
if PRODUCTION:
    required_secret = os.environ.get("THREATHUNT_AUTH_SECRET", "")
    if (len(required_secret) < 32 or required_secret in {
        "CHANGE_THIS_THREATHUNT_SECRET_IN_PRODUCTION",
        "change-me-long-random-string",
    }):
        raise RuntimeError("Production requires a unique THREATHUNT_AUTH_SECRET (32+ characters)")


ROLES = {
    "Administrator": {
        "view",
        "investigate",
        "create",
        "validate",
        "admin",
        "manage_users",
        "manage_sources",
        "manage_workspace",
    },
    "Analyst": {
        "view",
        "investigate",
        "create",
        "validate",
        "manage_sources",
    },
    "Monitor": {
        "view",
    },
}


class LoginRequest(BaseModel):
    email: str
    password: str


class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str = "Monitor"


class RoleUpdate(BaseModel):
    role: str


class PasswordUpdate(BaseModel):
    password: str


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        210_000,
    )

    return (
        "pbkdf2_sha256$210000$"
        + base64.urlsafe_b64encode(salt).decode()
        + "$"
        + base64.urlsafe_b64encode(derived).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, hash_b64 = stored.split("$")

        salt = base64.urlsafe_b64decode(
            salt_b64.encode()
        )

        expected = base64.urlsafe_b64decode(
            hash_b64.encode()
        )

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations),
        )

        return hmac.compare_digest(
            actual,
            expected,
        )

    except Exception:
        return False


def b64(data: bytes) -> str:
    return (
        base64.urlsafe_b64encode(data)
        .decode()
        .rstrip("=")
    )


def make_token(user: dict[str, Any]) -> str:

    header = b64(
        json.dumps(
            {"alg": "HS256", "typ": "JWT"},
            separators=(",", ":"),
        ).encode()
    )

    payload = b64(
        json.dumps(
            {
                "sub": user["id"],
                "email": user["email"],
                "role": user["role"],
                "iat": int(time.time()),
                "exp": int(time.time()) + TOKEN_TTL,
            },
            separators=(",", ":"),
        ).encode()
    )

    message = f"{header}.{payload}".encode()

    signature = hmac.new(
        JWT_SECRET.encode(),
        message,
        hashlib.sha256,
    ).digest()

    return f"{header}.{payload}.{b64(signature)}"


def decode_token(token: str) -> dict[str, Any]:

    try:
        header, payload, signature = token.split(".")

        message = f"{header}.{payload}".encode()

        expected = hmac.new(
            JWT_SECRET.encode(),
            message,
            hashlib.sha256,
        ).digest()

        actual = base64.urlsafe_b64decode(
            signature + "=" * (-len(signature) % 4)
        )

        if not hmac.compare_digest(
            actual,
            expected,
        ):
            raise ValueError("Invalid signature")

        data = json.loads(
            base64.urlsafe_b64decode(
                payload + "=" * (-len(payload) % 4)
            )
        )

        if int(data["exp"]) < int(time.time()):
            raise ValueError("Token expired")

        return data

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token",
        )


def seed_database():
    """Bootstrap explicit production admin OR local-only demo accounts.

    Production refuses previously seeded demo passwords. No insecure defaults.
    """
    con = db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        existing = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if existing == 0:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            if PRODUCTION:
                email = os.environ.get("THREATHUNT_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
                password = os.environ.get("THREATHUNT_BOOTSTRAP_ADMIN_PASSWORD", "")
                if (not email or "@" not in email or len(password) < 16
                        or password == "threathunt"):
                    raise RuntimeError(
                        "First production start requires THREATHUNT_BOOTSTRAP_ADMIN_EMAIL "
                        "and THREATHUNT_BOOTSTRAP_ADMIN_PASSWORD (16+ chars)"
                    )
                users = [("Initial Administrator", email, "Administrator", password)]
            else:
                users = [
                    ("Sohila Mahmoud", "admin@enterprise.local", "Administrator", "threathunt"),
                    ("Threat Hunter", "analyst@enterprise.local", "Analyst", "threathunt"),
                    ("Security Monitor", "monitor@enterprise.local", "Monitor", "threathunt"),
                ]
            for name, email, role, password in users:
                con.execute("""
                    INSERT INTO users
                    (name,email,password_hash,role,active,created_at,updated_at)
                    VALUES (?,?,?,?,1,?,?)
                """, (name, email, hash_password(password), role, now, now))
        if PRODUCTION:
            known_demo_emails = (
                "admin@enterprise.local", "analyst@enterprise.local", "monitor@enterprise.local"
            )
            for email in known_demo_emails:
                row = con.execute("SELECT password_hash FROM users WHERE lower(email)=?", (email,)).fetchone()
                if row is not None and verify_password("threathunt", row["password_hash"]):
                    raise RuntimeError("Production refused: replace existing demo account credentials")
        con.commit()
    finally:
        con.close()


seed_database()


def get_current_user(
    authorization: str | None = Header(default=None),
):
    if not authorization:
        raise HTTPException(
            401,
            "Authentication required",
        )

    if not authorization.lower().startswith(
        "bearer "
    ):
        raise HTTPException(
            401,
            "Bearer authentication required",
        )

    token = authorization.split(
        " ",
        1
    )[1]

    claims = decode_token(token)

    con = db()

    row = con.execute(
        """
        SELECT id,name,email,role,active
        FROM users
        WHERE id=?
        """,
        (claims["sub"],),
    ).fetchone()

    con.close()

    if not row or not row["active"]:
        raise HTTPException(
            401,
            "User account is inactive",
        )

    return dict(row)


def require_admin(
    user=Depends(get_current_user),
):
    if user["role"] != "Administrator":
        raise HTTPException(
            403,
            "Administrator privileges required",
        )

    return user


@router.post("/login")
def login(payload: LoginRequest):

    con = db()

    row = con.execute(
        """
        SELECT *
        FROM users
        WHERE lower(email)=lower(?)
        """,
        (payload.email,),
    ).fetchone()

    con.close()

    if not row or not row["active"]:
        raise HTTPException(
            401,
            "Invalid email or password",
        )

    if not verify_password(
        payload.password,
        row["password_hash"],
    ):
        raise HTTPException(
            401,
            "Invalid email or password",
        )

    user = dict(row)

    token = make_token(user)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "permissions": sorted(
                ROLES[user["role"]]
            ),
        },
    }


@router.get("/me")
def me(
    user=Depends(get_current_user),
):
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "permissions": sorted(
            ROLES[user["role"]]
        ),
    }


@router.get("/users")
def list_users(
    user=Depends(require_admin),
):

    con = db()

    rows = con.execute(
        """
        SELECT id,name,email,role,active,created_at,updated_at
        FROM users
        ORDER BY id
        """
    ).fetchall()

    con.close()

    return {
        "items": [
            dict(x)
            for x in rows
        ]
    }


@router.post("/users")
def create_user(
    payload: UserCreate,
    user=Depends(require_admin),
):

    if payload.role not in ROLES:
        raise HTTPException(
            400,
            "Role must be Administrator, Analyst or Monitor",
        )

    if len(payload.password) < 8:
        raise HTTPException(
            400,
            "Password must contain at least 8 characters",
        )

    con = db()

    try:
        now = time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        cur = con.execute(
            """
            INSERT INTO users
            (name,email,password_hash,role,active,created_at,updated_at)
            VALUES (?,?,?,?,1,?,?)
            """,
            (
                payload.name.strip(),
                payload.email.lower(),
                hash_password(
                    payload.password
                ),
                payload.role,
                now,
                now,
            ),
        )

        con.commit()

        return {
            "id": cur.lastrowid,
            "name": payload.name.strip(),
            "email": payload.email.lower(),
            "role": payload.role,
            "active": 1,
        }

    except sqlite3.IntegrityError:
        raise HTTPException(
            409,
            "A user with this email already exists",
        )

    finally:
        con.close()


@router.patch("/users/{user_id}/role")
def change_role(
    user_id: int,
    payload: RoleUpdate,
    user=Depends(require_admin),
):

    if payload.role not in ROLES:
        raise HTTPException(
            400,
            "Invalid role",
        )

    con = db()

    target = con.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,),
    ).fetchone()

    if not target:
        con.close()
        raise HTTPException(
            404,
            "User not found",
        )

    # Do not allow the last Administrator
    # to accidentally remove administrator access.
    if (
        target["role"] == "Administrator"
        and payload.role != "Administrator"
    ):
        count = con.execute(
            """
            SELECT COUNT(*) AS n
            FROM users
            WHERE role='Administrator'
            AND active=1
            """
        ).fetchone()["n"]

        if count <= 1:
            con.close()
            raise HTTPException(
                400,
                "The last active Administrator cannot be demoted",
            )

    con.execute(
        """
        UPDATE users
        SET role=?,updated_at=?
        WHERE id=?
        """,
        (
            payload.role,
            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            user_id,
        ),
    )

    con.commit()
    con.close()

    return {
        "ok": True,
        "user_id": user_id,
        "role": payload.role,
    }


@router.patch("/users/{user_id}/password")
def change_password(
    user_id: int,
    payload: PasswordUpdate,
    user=Depends(require_admin),
):

    if len(payload.password) < 8:
        raise HTTPException(
            400,
            "Password must contain at least 8 characters",
        )

    con = db()

    con.execute(
        """
        UPDATE users
        SET password_hash=?,updated_at=?
        WHERE id=?
        """,
        (
            hash_password(payload.password),
            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            user_id,
        ),
    )

    con.commit()
    con.close()

    return {"ok": True}


@router.patch("/users/{user_id}/status")
def change_status(
    user_id: int,
    payload: dict,
    user=Depends(require_admin),
):

    active = bool(
        payload.get("active")
    )

    con = db()

    target = con.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,),
    ).fetchone()

    if not target:
        con.close()
        raise HTTPException(
            404,
            "User not found",
        )

    if (
        target["id"] == user["id"]
        and not active
    ):
        con.close()
        raise HTTPException(
            400,
            "You cannot deactivate your own active account",
        )

    con.execute(
        """
        UPDATE users
        SET active=?,updated_at=?
        WHERE id=?
        """,
        (
            1 if active else 0,
            time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            user_id,
        ),
    )

    con.commit()
    con.close()

    return {
        "ok": True,
        "user_id": user_id,
        "active": active,
    }


@router.post("/logout")
def logout(
    user=Depends(get_current_user),
):
    # JWT is stateless. The client removes its token.
    # This endpoint provides an explicit authenticated
    # logout action for audit/API consistency.
    return {
        "ok": True,
        "message": "Authenticated session ended on the client.",
    }
