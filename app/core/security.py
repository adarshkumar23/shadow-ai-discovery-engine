"""
PATENT NOTICE
Module: core/security
Part of: Shadow AI Discovery Engine
Patent: System and Method for Inferring Undeclared
Artificial Intelligence Systems and Generating AI
Governance Artifacts from Enterprise Telemetry
Status: Provisional filing in preparation
"""

from cryptography.fernet import Fernet

from app.core.config import settings


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string using Fernet.

    Returns base64 encoded ciphertext string.
    Raises ValueError if SHADOW_AI_FERNET_KEY is not configured.
    """
    if not settings.shadow_ai_fernet_key:
        raise ValueError(
            "SHADOW_AI_FERNET_KEY not configured. "
            "Run: python -c 'from cryptography.fernet "
            "import Fernet; print(Fernet.generate_key().decode())' "
            "and add to .env"
        )
    fernet = Fernet(settings.shadow_ai_fernet_key.encode())
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted ciphertext string.

    Returns plaintext string.
    Raises ValueError on failure. Never logs the plaintext value.
    """
    if not settings.shadow_ai_fernet_key:
        raise ValueError(
            "SHADOW_AI_FERNET_KEY not configured. "
            "Run: python -c 'from cryptography.fernet "
            "import Fernet; print(Fernet.generate_key().decode())' "
            "and add to .env"
        )
    fernet = Fernet(settings.shadow_ai_fernet_key.encode())
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        raise ValueError(
            "Decryption failed. Token may be corrupt "
            "or key may have rotated."
        )
