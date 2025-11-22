import mysql.connector
from config import DB_CONFIG

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    conn.close()
    return user

def create_user(username, password_hash):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password_hash))
    conn.commit()
    conn.close()

def assign_role_to_user(user_id, role_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (%s, %s)", (user_id, role_id))
    conn.commit()
    conn.close()

def get_roles_of_user(user_id):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT r.name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = %s
    """, (user_id,))
    roles = [row["name"] for row in cur.fetchall()]
    conn.close()
    return roles

def get_permissions_of_user(user_id):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT p.name FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = %s
    """, (user_id,))
    perms = {row["name"] for row in cur.fetchall()}
    conn.close()
    return perms

def get_role_by_name(name):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM roles WHERE name=%s", (name,))
    role = cur.fetchone()
    conn.close()
    return role

def get_permission_by_name(name):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM permissions WHERE name=%s", (name,))
    perm = cur.fetchone()
    conn.close()
    return perm

def assign_permission_to_role(role_id, permission_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (%s, %s)", (role_id, permission_id))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, username FROM users")
    users = cur.fetchall()
    conn.close()
    return users
