from functools import wraps
from flask import request, jsonify
from utils import decode_token
from models import get_permissions_of_user, get_user_by_username

def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload:
        return None
    user = get_user_by_username(payload["username"])
    return user

def require_permission(permission_name):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            perms = get_permissions_of_user(user["id"])
            if permission_name not in perms:
                return jsonify({"error": "Forbidden: missing permission"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
