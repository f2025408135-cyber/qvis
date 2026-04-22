from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)

class EncryptionService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        from backend.config import settings

if not settings.encryption_enabled:
            logger.warning("Encryption is disabled - THIS IS NOT PRODUCTION SAFE")
            self.cipher = None
            self._initialized = True
            return

        password = settings.encryption_password.get_secret_value()
        salt = settings.encryption_salt.get_secret_value()
        
        if not password or not salt:
            logger.critical("encryption_credentials_missing")
            raise ValueError("CRITICAL: ENCRYPTION_PASSWORD and ENCRYPTION_SALT must be provided when encryption is enabled.")

        kdf = PBKDF2HMAC(

            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        self.cipher = Fernet(key)
        self._initialized = True
        logger.info("encryption_service_initialized")

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string value"""
        if not self.cipher:
            return plaintext

        encrypted_bytes = self.cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string value"""
        if not self.cipher or not ciphertext:
            return ciphertext

        try:
            encrypted_bytes = base64.b64decode(ciphertext.encode('utf-8'))
            decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error("decryption_failed", error=str(e))
            raise ValueError("Failed to decrypt data")

class EncryptedFieldMixin:
    """Mixin to add encrypted field support to models"""

    @staticmethod
    def create_encrypted_column(column_name: str, encrypted_column_name: str = None):
        if encrypted_column_name is None:
            encrypted_column_name = f"_encrypted_{column_name}"

        def getter(self):
            encryption_service = EncryptionService()
            encrypted_value = getattr(self, encrypted_column_name, None)
            if encrypted_value:
                return encryption_service.decrypt(encrypted_value)
            return None

        def setter(self, value):
            encryption_service = EncryptionService()
            encrypted_column_name_local = encrypted_column_name
            if value is None:
                setattr(self, encrypted_column_name_local, None)
            else:
                encrypted_value = encryption_service.encrypt(value)
                setattr(self, encrypted_column_name_local, encrypted_value)

        return property(getter, setter)

encryption_service = EncryptionService()
