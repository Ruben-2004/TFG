"""
Implementación del algoritmo de firma digital sobre curvas elípticas
(ECDSA - Elliptic Curve Digital Signature Algorithm).

Incluye:
    - Generación de claves ECC
    - Firma de mensajes (ECDSA con SHA-256)
    - Verificación de firmas
    - Exportación de claves en PEM

Curvas soportadas: P-256, P-384, P-521.

Uso:
    from ecdsa import ECDSA
    firmante = ECDSA(curve="P-256")
    firma = firmante.sign(b"mensaje a firmar")
    valida = firmante.verify(firma, b"mensaje a firmar")
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


class ECDSA:
    """Encapsula un par de claves ECC y las operaciones de firma ECDSA."""

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

    # ── Firma / Verificación ───────────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        """
        Firma un mensaje con la clave privada (ECDSA-SHA256).

        Parámetros
        ----------
        message : bytes
            Mensaje de longitud arbitraria.

        Devuelve
        --------
        bytes
            Firma en formato DER (par (r, s) codificado).
        """
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, signature: bytes, message: bytes) -> bool:
        """
        Verifica una firma ECDSA sobre un mensaje.

        Parámetros
        ----------
        signature : bytes
            Firma producida por sign().
        message : bytes
            Mensaje original.

        Devuelve
        --------
        bool
            True si la firma es válida, False en caso contrario.
        """
        try:
            self._public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def signature_size(self, message: bytes = b"test") -> int:
        """Devuelve el tamaño en bytes de una firma típica para esta curva."""
        return len(self.sign(message))


# ── Demostración ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== ECDSA sobre P-256 ===")
    firmante = ECDSA(curve="P-256")

    print("Tamaños de clave:")
    for k, v in firmante.key_sizes().items():
        print(f"  {k}: {v}")

    mensaje = b"Criptografia de curvas elipticas sobre cuerpos finitos."
    firma = firmante.sign(mensaje)

    print(f"\nMensaje : {mensaje.decode()}")
    print(f"Firma   : {firma.hex()[:64]}...")
    print(f"Tamaño firma: {len(firma)} bytes")

    print(f"\nVerificación (mensaje original)  : {firmante.verify(firma, mensaje)}")
    print(f"Verificación (mensaje alterado)  : {firmante.verify(firma, b'otro mensaje')}")
    print(f"Verificación (firma manipulada)  : {firmante.verify(b'firma_falsa', mensaje)}")

    print("\n=== Verificación cruzada (firmante distinto) ===")
    otro = ECDSA(curve="P-256")
    print(f"Firma de 'firmante' verificada con clave de 'otro': "
          f"{otro.public_key.verify if False else otro.verify(firma, mensaje)}")