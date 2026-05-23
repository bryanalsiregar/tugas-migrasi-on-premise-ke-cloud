import hashlib
import hmac
import secrets
from http import HTTPStatus

from .responses import error_response

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000
    ).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    salt, digest = stored.split("$", 1)
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000
    ).hex()
    return hmac.compare_digest(candidate, digest)


def admin_dict(row):
    if not row:
        return None
    data = dict(row)
    data.pop("password_hash", None)
    data["is_active"] = bool(data["is_active"])
    return data


def role_name(user):
    if not user:
        return ""
    try:
        value = user["role"]
    except (TypeError, KeyError, IndexError):
        value = getattr(user, "role", "")
    return str(value or "").strip()


def is_admin_role(user):
    return role_name(user) in {"Super Admin", "Admin"}


def require_admin_role(handler, user):
    if not is_admin_role(user):
        error_response(handler, "Admin access required", HTTPStatus.FORBIDDEN)
        return False
    return True

