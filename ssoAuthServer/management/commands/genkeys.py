from django.core.management.base import BaseCommand
from django.conf import settings
from jwcrypto import jwk
from pathlib import Path
import json
import os

class Command(BaseCommand):
    help = "Generate RSA keypair and write JWKS"

    def handle(self, *args, **options):
        try:
            # Use Django's BASE_DIR for proper path resolution
            keys_dir = Path(settings.BASE_DIR) / "ssoAuthServer" / "keys"
            keys_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate key with kid
            key = jwk.JWK.generate(kty="RSA", size=2048, kid="default-rsa-key")
            
            # Export PEM files
            priv_pem = key.export_to_pem(private_key=True, password=None)
            pub_pem = key.export_to_pem(private_key=False)
            
            # Save PEM files
            priv_path = keys_dir / "private_key.pem"
            pub_path = keys_dir / "public_key.pem"
            
            priv_path.write_bytes(priv_pem)
            pub_path.write_bytes(pub_pem)
            
            # Set restrictive permissions on private key (Unix-like systems)
            if os.name != 'nt':  # Not Windows
                os.chmod(priv_path, 0o600)
            
            # Create JWKS with proper JSON formatting
            jwks = {"keys": [json.loads(key.export_public())]}
            jwks_path = keys_dir / "jwks.json"
            jwks_path.write_text(json.dumps(jwks, indent=2))
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"✓ Generated RSA keypair\n"
                    f"  Private: {priv_path}\n"
                    f"  Public: {pub_path}\n"
                    f"  JWKS: {jwks_path}"
                )
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Failed to generate keys: {str(e)}")
            )
            raise