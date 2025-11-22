import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from config import SECRET_KEY, JWT_ALGO

def hash_password(password: str) -> str:
    return generate_password_hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return check_password_hash(hashed, password)

def create_token(user_id: int, username: str):
    payload = {"user_id": user_id, "username": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)
    return token

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
