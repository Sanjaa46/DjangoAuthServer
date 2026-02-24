from django.contrib.auth.hashers import BasePasswordHasher
from passlib.hash import pbkdf2_sha256


class FrappePBKDF2Hasher(BasePasswordHasher):
    algorithm = "pbkdf2-sha256"

    def verify(self, password, encoded):
        if encoded.startswith("$"):
            encoded = encoded[1:]
        return pbkdf2_sha256.verify(password, f"${encoded}")

    def encode(self, password, salt, iterations=None):
        hashed = pbkdf2_sha256.hash(password)
        return hashed.lstrip("$")  # remove leading $
    
    def safe_summary(self, encoded):
        return {"hash": encoded}