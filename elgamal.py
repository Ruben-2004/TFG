"""
elgamal.py
----------
Implementación del esquema de cifrado ElGamal sobre curvas elípticas
(EC-ElGamal).

El mensaje se cifra mediante un esquema híbrido:
    1. Se acuerda un secreto ECDH efímero.
    2. El secreto se convierte en clave AES-256-GCM mediante HKDF.
    3. El mensaje se cifra con AES-256-GCM.

Esto evita la necesidad de codificar el mensaje como punto de la curva,
que es la aproximación habitual en implementaciones prácticas.

Curvas soportadas: P-256, P-384, P-521.

Uso:
    from elgamal import ECElGamal
    bob = ECElGamal(curve="P-256")           # genera clave pública/privada
    ct  = bob.encrypt(b"mensaje", bob.public_key)
    pt  = bob.decrypt(ct)
"""

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


class ECElGamal:
    """
    Cifrado EC-ElGamal híbrido (ECDH efímero + AES-256-GCM).

    El destinatario genera un par de claves estático. El emisor usa
    una clave efímera por cada cifrado, garantizando confidencialidad
    hacia adelante (forward secrecy) a nivel de mensaje.
    """

    def __init__(self, curve: str = "P-256"):
        """
        Genera un par de claves ECC (clave estática del destinatario).

        Parámetros
        ----------
        curve : str
            Nombre de la curva: "P-256", "P-384" o "P-521".
        """
        if curve not in CURVES:
            raise ValueError(f"Curva no soportada. Opciones: {list(CURVES)}")
        self.curve_name = curve
        self._curve = CURVES[curve]
        self._private_key = ec.generate_private_key(self._curve, default_backend())
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

    # ── Derivación de clave simétrica ──────────────────────────────────────────

    @staticmethod
    def _derive_key(shared_secret: bytes, length: int = 32) -> bytes:
        """Deriva una clave AES a partir del secreto ECDH usando HKDF-SHA256."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b"ec-elgamal-hybrid",
            backend=default_backend(),
        ).derive(shared_secret)

    # ── Cifrado / Descifrado ───────────────────────────────────────────────────

    def encrypt(self, plaintext: bytes, recipient_public_key) -> dict:
        """
        Cifra un mensaje para el destinatario (EC-ElGamal híbrido).

        Parámetros
        ----------
        plaintext : bytes
            Mensaje a cifrar (longitud arbitraria).
        recipient_public_key
            Clave pública ECC del destinatario.

        Devuelve
        --------
        dict con claves:
            "ephemeral_public_key_pem" : bytes  — clave pública efímera (C1)
            "nonce"                    : bytes  — nonce AES-GCM (12 bytes)
            "ciphertext"               : bytes  — mensaje cifrado + tag GCM (C2)
        """
        # Clave efímera del emisor (equivale al r aleatorio del esquema teórico)
        ephemeral_key = ec.generate_private_key(self._curve, default_backend())
        ephemeral_public = ephemeral_key.public_key()

        # Secreto compartido ECDH efímero: r·B
        shared_secret = ephemeral_key.exchange(ec.ECDH(), recipient_public_key)

        # Derivar clave AES-256 y cifrar
        aes_key = self._derive_key(shared_secret)
        nonce = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        return {
            "ephemeral_public_key_pem": ephemeral_public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

    def decrypt(self, ciphertext_bundle: dict) -> bytes:
        """
        Descifra un criptograma producido por encrypt().

        Parámetros
        ----------
        ciphertext_bundle : dict
            Diccionario devuelto por encrypt().

        Devuelve
        --------
        bytes
            Mensaje original descifrado.
        """
        # Recuperar clave pública efímera (C1)
        ephemeral_public_key = serialization.load_pem_public_key(
            ciphertext_bundle["ephemeral_public_key_pem"],
            backend=default_backend(),
        )

        # Secreto compartido ECDH: b·C1 = b·(r·G) = r·(b·G) = r·B
        shared_secret = self._private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derivar clave AES-256 y descifrar
        aes_key = self._derive_key(shared_secret)
        return AESGCM(aes_key).decrypt(
            ciphertext_bundle["nonce"],
            ciphertext_bundle["ciphertext"],
            None,
        )

    def ciphertext_size(self, plaintext: bytes) -> dict:
        """Devuelve los tamaños en bytes del criptograma para un mensaje dado."""
        bundle = self.encrypt(plaintext, self._public_key)
        return {
            "ephemeral_pubkey_bytes": len(bundle["ephemeral_public_key_pem"]),
            "nonce_bytes": len(bundle["nonce"]),
            "ciphertext_bytes": len(bundle["ciphertext"]),
            "total_bytes": sum(len(v) for v in bundle.values()),
        }


# ── Demostración ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== EC-ElGamal híbrido sobre P-256 ===")
    bob = ECElGamal(curve="P-256")

    print("Tamaños de clave (Bob):")
    for k, v in bob.key_sizes().items():
        print(f"  {k}: {v}")

    mensaje = b"Mensaje confidencial cifrado con EC-ElGamal hibrido."
    print(f"\nMensaje original : {mensaje.decode()}")

    bundle = bob.encrypt(mensaje, bob.public_key)
    print(f"Nonce (hex)      : {bundle['nonce'].hex()}")
    print(f"Criptograma      : {bundle['ciphertext'].hex()[:64]}...")

    descifrado = bob.decrypt(bundle)
    print(f"\nDescifrado       : {descifrado.decode()}")
    print(f"Coincide         : {descifrado == mensaje}")

    print("\nTamaños del criptograma:")
    for k, v in bob.ciphertext_size(mensaje).items():
        print(f"  {k}: {v}")

    print("\n=== Verificación de integridad (GCM) ===")
    bundle_mod = dict(bundle)
    bundle_mod["ciphertext"] = b"datos_manipulados" + bundle["ciphertext"][17:]
    try:
        bob.decrypt(bundle_mod)
        print("ERROR: no detectó la manipulación")
    except Exception:
        print("Correcto: manipulación detectada por AES-GCM")