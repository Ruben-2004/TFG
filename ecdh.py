"""
ecdh.py
-------
Implementación del protocolo de intercambio de claves
Diffie-Hellman sobre curvas elípticas (ECDH).

Incluye:
    - Generación de claves ECC
    - Cálculo del secreto compartido (ECDH)
    - Derivación de clave simétrica a partir del secreto (HKDF)

Curvas soportadas: P-256, P-384, P-521.

Uso:
    from ecdh import ECDH
    alicia  = ECDH(curve="P-256")
    bernardo = ECDH(curve="P-256")
    secreto_a = alicia.shared_secret(bernardo.public_key)
    secreto_b = bernardo.shared_secret(alicia.public_key)
    assert secreto_a == secreto_b
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


class ECDH:
    """Encapsula un par de claves ECC y el protocolo ECDH."""

    def __init__(self, curve: str = "P-256"):
        """
        Genera un par de claves ECC sobre la curva especificada.

        Parámetros
        ----------
        curve : str
            Nombre de la curva: "P-256", "P-384" o "P-521".
        """
        if curve not in CURVES:
            raise ValueError(f"Curva no soportada. Opciones: {list(CURVES)}")
        self.curve_name = curve
        self._private_key = ec.generate_private_key(CURVES[curve], default_backend())
        self._public_key = self._private_key.public_key()

    # ── Propiedades ────────────────────────────────────────────────────────────

    @property
    def public_key(self):
        return self._public_key

    # ── Serialización ──────────────────────────────────────────────────────────

    def export_public_key_pem(self) -> bytes:
        """Devuelve la clave pública en formato PEM."""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def key_sizes(self) -> dict:
        """Devuelve los tamaños en bytes de las claves."""
        priv_der = self._private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_der = self._public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "curve": self.curve_name,
            "private_key_bytes": len(priv_der),
            "public_key_bytes": len(pub_der),
        }

    # ── ECDH ───────────────────────────────────────────────────────────────────

    def shared_secret(self, peer_public_key) -> bytes:
        """
        Calcula el secreto compartido ECDH con la clave pública del par.

        Parámetros
        ----------
        peer_public_key
            Clave pública ECC del interlocutor.

        Devuelve
        --------
        bytes
            Secreto compartido en bruto (coordenada x del punto resultante).
        """
        return self._private_key.exchange(ec.ECDH(), peer_public_key)

    def derive_symmetric_key(self, peer_public_key, length: int = 32,
                              info: bytes = b"tfg-ecc-ecdh") -> bytes:
        """
        Deriva una clave simétrica a partir del secreto ECDH usando HKDF-SHA256.

        Parámetros
        ----------
        peer_public_key
            Clave pública ECC del interlocutor.
        length : int
            Longitud en bytes de la clave derivada (por defecto 32 = AES-256).
        info : bytes
            Contexto de la derivación (etiqueta de aplicación).

        Devuelve
        --------
        bytes
            Clave simétrica derivada.
        """
        raw_secret = self.shared_secret(peer_public_key)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(raw_secret)


# ── Demostración ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== ECDH sobre P-256 ===")
    alicia   = ECDH(curve="P-256")
    bernardo = ECDH(curve="P-256")

    print("Tamaños de clave (Alicia):")
    for k, v in alicia.key_sizes().items():
        print(f"  {k}: {v}")

    secreto_a = alicia.shared_secret(bernardo.public_key)
    secreto_b = bernardo.shared_secret(alicia.public_key)

    print(f"\nSecreto compartido (Alicia)  : {secreto_a.hex()}")
    print(f"Secreto compartido (Bernardo): {secreto_b.hex()}")
    print(f"Coinciden                    : {secreto_a == secreto_b}")

    clave_a = alicia.derive_symmetric_key(bernardo.public_key)
    clave_b = bernardo.derive_symmetric_key(alicia.public_key)
    print(f"\nClave AES-256 derivada (HKDF): {clave_a.hex()}")
    print(f"Coinciden                    : {clave_a == clave_b}")