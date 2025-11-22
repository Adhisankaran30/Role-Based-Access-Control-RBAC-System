from flask import Flask, jsonify, request
from auth import auth_bp
from rbac import require_permission, get_current_user
from models import get_all_users, get_role_by_name, assign_role_to_user, get_permission_by_name, assign_permission_to_role

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix="/auth")

@app.route("/")
def index():
    return jsonify({"message": "RBAC System API is running"})

# Protected route: only users with "view_users" permission can call this
@app.route("/users", methods=["GET"])
@require_permission("view_users")
def list_users():
    users = get_all_users()
    return jsonify(users)

# Protected route: only users with "create_users" permission
@app.route("/admin/assign-role", methods=["POST"])
@require_permission("create_users")
def assign_role():
    data = request.json
    username = data.get("username")
    role_name = data.get("role")

    from models import get_user_by_username
    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    role = get_role_by_name(role_name)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    assign_role_to_user(user["id"], role["id"])
    return jsonify({"message": f"Role {role_name} assigned to {username}"})

# Assign permission to role (admin-level action)
@app.route("/admin/assign-permission", methods=["POST"])
@require_permission("create_users")
def assign_perm():
    data = request.json
    role_name = data.get("role")
    perm_name = data.get("permission")

    role = get_role_by_name(role_name)
    perm = get_permission_by_name(perm_name)
    if not role or not perm:
        return jsonify({"error": "Role or permission not found"}), 404

    assign_permission_to_role(role["id"], perm["id"])
    return jsonify({"message": f"Permission {perm_name} assigned to role {role_name}"})


# Example: a route for reports, needs "view_reports" permission
@app.route("/reports", methods=["GET"])
@require_permission("view_reports")
def view_reports():
    # dummy data
    return jsonify({"report": "This is a sample report"})


# Helper: whoami (see logged in user & permissions)
@app.route("/me", methods=["GET"])
def me():
    from models import get_permissions_of_user
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    perms = list(get_permissions_of_user(user["id"]))
    return jsonify({"username": user["username"], "permissions": perms})

if __name__ == "__main__":
    app.run(debug=True)
