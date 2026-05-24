# Criptografía moderna basada en teoría de números
### Trabajo de Fin de Grado — Rubén Torres Rodríguez

Implementación en Python de los sistemas criptográficos RSA y ECC estudiados en el TFG.

---

## Estructura del repositorio

```
├── rsa.py          # Sistema RSA (generación de claves, cifrado OAEP, firma PSS)
├── ecdh.py         # Protocolo ECDH (intercambio de claves + derivación HKDF)
├── ecdsa.py        # Algoritmo de firma ECDSA
├── elgamal.py      # Cifrado EC-ElGamal híbrido (ECDH efímero + AES-256-GCM)
├── benchmarks.py   # Análisis comparativo de rendimiento RSA vs ECC
└── README.md
```

---

## Requisitos

- Python 3.8 o superior
- Biblioteca `cryptography`

```bash
pip install cryptography
```

---

## Uso

Cada archivo puede ejecutarse de forma independiente para ver una demostración:

```bash
python rsa.py
python ecdh.py
python ecdsa.py
python elgamal.py
```

Para ejecutar el benchmark completo (20 repeticiones por defecto):

```bash
python benchmarks.py
```

Se puede ajustar el número de repeticiones y la ruta del CSV de salida:

```bash
python benchmarks.py --reps 50 --csv mis_resultados.csv
```

---

## Descripción de cada módulo

### `rsa.py` — Sistema RSA

Clase `RSA` que encapsula un par de claves RSA y expone:

| Método | Descripción |
|--------|-------------|
| `RSA(bits)` | Genera un par de claves de `bits` bits (1024–4096) |
| `encrypt(plaintext)` | Cifrado OAEP-SHA256 con la clave pública |
| `decrypt(ciphertext)` | Descifrado OAEP-SHA256 con la clave privada |
| `sign(message)` | Firma PSS-SHA256 con la clave privada |
| `verify(sig, msg)` | Verificación PSS-SHA256 con la clave pública |
| `export_public_key_pem()` | Exporta la clave pública en PEM |
| `key_sizes()` | Tamaños en bytes del módulo y la clave privada |

### `ecdh.py` — Intercambio de claves ECDH

Clase `ECDH` que implementa el protocolo Diffie-Hellman sobre curvas elípticas:

| Método | Descripción |
|--------|-------------|
| `ECDH(curve)` | Genera un par de claves sobre P-256, P-384 o P-521 |
| `shared_secret(peer_pub)` | Secreto compartido ECDH en bruto |
| `derive_symmetric_key(peer_pub)` | Clave AES-256 derivada mediante HKDF-SHA256 |

### `ecdsa.py` — Firma digital ECDSA

Clase `ECDSA` para firma y verificación sobre curvas elípticas:

| Método | Descripción |
|--------|-------------|
| `ECDSA(curve)` | Genera un par de claves sobre P-256, P-384 o P-521 |
| `sign(message)` | Firma ECDSA-SHA256 (formato DER) |
| `verify(sig, msg)` | Verificación; devuelve `True`/`False` |

### `elgamal.py` — Cifrado EC-ElGamal híbrido

Clase `ECElGamal` que implementa cifrado híbrido (ECDH efímero + AES-256-GCM):

| Método | Descripción |
|--------|-------------|
| `ECElGamal(curve)` | Genera el par de claves estático del destinatario |
| `encrypt(plaintext, pub)` | Cifra con clave pública del destinatario |
| `decrypt(bundle)` | Descifra con la clave privada propia |

El criptograma es un diccionario con tres campos: `ephemeral_public_key_pem`, `nonce` y `ciphertext`.

### `benchmarks.py` — Análisis de rendimiento

Compara RSA (1024/2048/3072/4096 bits) y ECC (P-256/P-384/P-521) midiendo:

- Tiempo de generación de claves
- Tiempo de cifrado / ECDH
- Tiempo de descifrado
- Tiempo de firma y verificación
- Tamaño de clave privada, criptograma y firma

Los resultados se muestran en tablas por consola y se exportan a CSV.

---

## Curvas soportadas

| Nombre | Tamaño | Seguridad equivalente (bits) |
|--------|--------|------------------------------|
| P-256 (secp256r1) | 256 bits | 128 bits |
| P-384 (secp384r1) | 384 bits | 192 bits |
| P-521 (secp521r1) | 521 bits | 260 bits |

---

## Licencia

Código desarrollado con fines académicos en el marco del TFG.