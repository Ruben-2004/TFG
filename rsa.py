"""
rsa.py
------
Implementación del sistema criptográfico RSA.

Incluye:
    - Generación de claves
    - Cifrado y descifrado (esquema OAEP con SHA-256)
    - Firma y verificación (esquema PSS con SHA-256)

Uso:
    from rsa import RSA
    r = RSA(bits=2048)
    ct = r.encrypt(b"mensaje secreto")
    pt = r.decrypt(ct)
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class RSA:
    """Encapsula un par de claves RSA y las operaciones asociadas."""

    def __init__(self, bits: int = 2048):
        """
        Genera un nuevo par de claves RSA.

        Parámetros
        ----------
        bits : int
            Tamaño del módulo en bits (recomendado: 2048, 3072 o 4096).
        """
        self.bits = bits
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    # ── Propiedades ────────────────────────────────────────────────────────────

    @property
    def public_key(self):
        return self._public_key

    @property
    def private_key(self):
        return self._private_key

    # ── Serialización ──────────────────────────────────────────────────────────

    def export_public_key_pem(self) -> bytes:
        """Devuelve la clave pública en formato PEM."""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_key_pem(self) -> bytes:
        """Devuelve la clave privada en formato PEM (sin contraseña)."""
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def key_sizes(self) -> dict:
        """Devuelve los tamaños en bytes de la clave privada y el módulo."""
        priv_der = self._private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return {
            "modulus_bits": self.bits,
            "private_key_bytes": len(priv_der),
            "modulus_bytes": self.bits // 8,
        }

    # ── Cifrado / Descifrado ───────────────────────────────────────────────────

    @staticmethod
    def _oaep_padding():
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Cifra un mensaje con la clave pública (OAEP-SHA256).

        Parámetros
        ----------
        plaintext : bytes
            Mensaje a cifrar. Longitud máxima: bits/8 - 66 bytes.

        Devuelve
        --------
        bytes
            Criptograma.
        """
        return self._public_key.encrypt(plaintext, self._oaep_padding())

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Descifra un criptograma con la clave privada (OAEP-SHA256).

        Parámetros
        ----------
        ciphertext : bytes
            Criptograma producido por encrypt().

        Devuelve
        --------
        bytes
            Mensaje original.
        """
        return self._private_key.decrypt(ciphertext, self._oaep_padding())

    # ── Firma / Verificación ───────────────────────────────────────────────────

    @staticmethod
    def _pss_padding():
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

    def sign(self, message: bytes) -> bytes:
        """
        Firma un mensaje con la clave privada (PSS-SHA256).

        Parámetros
        ----------
        message : bytes
            Mensaje a firmar (longitud arbitraria).

        Devuelve
        --------
        bytes
            Firma digital.
        """
        return self._private_key.sign(message, self._pss_padding(), hashes.SHA256())

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verifica una firma RSA-PSS.

        Devuelve True si la firma es válida, False en caso contrario.
        """
        try:
            self._public_key.verify(signature, message, self._pss_padding(), hashes.SHA256())
            return True
        except Exception:
            return False


# ── Demostración ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== RSA-2048: generación de claves ===")
    r = RSA(bits=2048)
    sizes = r.key_sizes()
    print(f"  Módulo       : {sizes['modulus_bits']} bits")
    print(f"  Clave privada: {sizes['private_key_bytes']} bytes (DER)")

    mensaje = b"Criptografia RSA sobre teoria de numeros."
    print(f"\nMensaje original : {mensaje.decode()}")

    ct = r.encrypt(mensaje)
    print(f"Criptograma      : {ct.hex()[:64]}...")

    pt = r.decrypt(ct)
    print(f"Descifrado       : {pt.decode()}")
    print(f"Coincide         : {pt == mensaje}")

    print("\n=== Firma y verificación ===")
    sig = r.sign(mensaje)
    print(f"Firma  : {sig.hex()[:64]}...")
    print(f"Válida : {r.verify(sig, mensaje)}")
    print(f"Inválida (mensaje alterado): {r.verify(sig, b'otro mensaje')}")