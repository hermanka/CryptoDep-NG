import ssl
import jwt


def create_ssl_context() -> ssl.SSLContext:
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def create_token(payload: dict, secret: str) -> str:
    return jwt.encode(payload, secret, algorithm="RS256")


def verify_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=["RS256"])
