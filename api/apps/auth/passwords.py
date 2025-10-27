import asyncio
import bcrypt
import hashlib


def _hash_password(password: str, rounds: int = 12) -> str:
    """
    Hash a password using bcrypt.

    :param password: plaintext password
    :param rounds: bcrypt cost factor (default 12)
    :return: hashed password as UTF-8 string
    """
    encoded_password = password.encode("utf-8")
    if len(encoded_password) > 72:
        encoded_password = hashlib.sha256(encoded_password).digest()
    hashed = bcrypt.hashpw(encoded_password, bcrypt.gensalt(rounds))
    return hashed.decode("utf-8")


# Async wrapper for hash_password
async def hash_password(password: str, rounds: int = 12) -> str:
    """
    Async wrapper: hash a password using bcrypt.

    :param password: plaintext password
    :param rounds: bcrypt cost factor (default 12)
    :return: hashed password as UTF-8 string
    """
    return await asyncio.to_thread(_hash_password, password, rounds)


def _verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.

    :param password: plaintext password
    :param hashed: bcrypt hashed password
    :return: True if valid, False otherwise
    """
    encoded_password = password.encode("utf-8")
    if len(encoded_password) > 72:
        encoded_password = hashlib.sha256(encoded_password).digest()
    try:
        result = bcrypt.checkpw(encoded_password, hashed.encode("utf-8"))
    except ValueError:
        # Catch invalid hash errors
        return False
    return result


async def verify_password(password: str, hashed: str) -> bool:
    """
    Async wrapper: verify a password against a bcrypt hash.

    :param password: plaintext password
    :param hashed: bcrypt hashed password
    :return: Future resolving to True if valid, False otherwise
    """
    return await asyncio.to_thread(_verify_password, password, hashed)
