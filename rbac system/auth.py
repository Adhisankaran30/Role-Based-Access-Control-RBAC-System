from flask import Blueprint, request, jsonify
from models import get_user_by_username, create_user, get_role_by_name, assign_role_to_user
from utils import hash_password, verify_password, create_token

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role_name = data.get("role", "staff")  # default role

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    existing = get_user_by_username(username)
    if existing:
        return jsonify({"error": "User already exists"}), 400

    pwd_hash = hash_password(password)
    create_user(username, pwd_hash)

    user = get_user_by_username(username)
    role = get_role_by_name(role_name)
    if role:
        assign_role_to_user(user["id"], role["id"])

    return jsonify({"message": "User registered", "assigned_role": role_name})

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = get_user_by_username(username)
    if not user or not verify_password(password, user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user["id"], username)
    return jsonify({"token": token})
