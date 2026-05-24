"""
benchmarks.py
-------------
Análisis comparativo de rendimiento entre RSA y ECC.

Importa y utiliza directamente las clases definidas en:
    rsa.py, ecdh.py, ecdsa.py, elgamal.py

Mide y muestra:
    - Tiempos de generación de claves
    - Tiempos de cifrado y descifrado (RSA) / ECDH (ECC)
    - Tiempos de firma y verificación
    - Tamaños de claves, criptogramas y firmas

Los resultados se presentan en tablas por consola y se guardan
en un fichero CSV (resultados_benchmark.csv).

Uso:
    python benchmarks.py
    python benchmarks.py --reps 50 --csv mis_resultados.csv
"""

import argparse
import csv
import statistics
import time

from rsa import RSA
from ecdh import ECDH
from ecdsa import ECDSA
from elgamal import ECElGamal

# ── Constantes ────────────────────────────────────────────────────────────────

MESSAGE     = b"Mensaje de prueba para benchmarks de RSA y ECC en TFG."
RSA_SIZES   = [1024, 2048, 3072, 4096]
ECC_CURVES  = ["P-256", "P-384", "P-521"]

# ── Utilidades ────────────────────────────────────────────────────────────────

def _mean_ms(times: list) -> float:
    return round(statistics.mean(times) * 1000, 3)

def _stdev_ms(times: list) -> float:
    return round(statistics.stdev(times) * 1000, 3) if len(times) > 1 else 0.0

def _timeit(fn, reps: int) -> list:
    """Ejecuta fn() reps veces y devuelve la lista de tiempos en segundos."""
    times = []
    for _ in range(reps):
        t0 = time.perf_counter()
        result = fn()
        times.append(time.perf_counter() - t0)
    return times, result

# ── Benchmarks RSA ─────────────────────────────────────────────────────────────

def benchmark_rsa(bits: int, reps: int) -> dict:
    """Benchmark para RSA-{bits}."""

    # Generación de claves
    gen_times, r = _timeit(lambda: RSA(bits=bits), reps)

    # Usamos la última instancia generada para el resto
    rsa_instance = r

    # Cifrado
    enc_times, ct = _timeit(lambda: rsa_instance.encrypt(MESSAGE), reps)

    # Descifrado
    dec_times, _ = _timeit(lambda: rsa_instance.decrypt(ct), reps)

    # Firma
    sign_times, sig = _timeit(lambda: rsa_instance.sign(MESSAGE), reps)

    # Verificación
    verify_times, _ = _timeit(lambda: rsa_instance.verify(sig, MESSAGE), reps)

    sizes = rsa_instance.key_sizes()

    return {
        "sistema":    f"RSA-{bits}",
        "bits":       bits,
        "gen_ms":     _mean_ms(gen_times),
        "gen_std_ms": _stdev_ms(gen_times),
        "enc_ms":     _mean_ms(enc_times),
        "dec_ms":     _mean_ms(dec_times),
        "sign_ms":    _mean_ms(sign_times),
        "verify_ms":  _mean_ms(verify_times),
        "priv_bytes": sizes["private_key_bytes"],
        "ct_bytes":   len(ct),
        "sig_bytes":  len(sig),
    }

# ── Benchmarks ECC ─────────────────────────────────────────────────────────────

def benchmark_ecc(curve: str, reps: int) -> dict:
    """Benchmark para ECC sobre {curve} usando ECDH, ECDSA y ElGamal."""

    # Generación de claves (ECDH, reutilizable para todas las clases)
    gen_times, instance = _timeit(lambda: ECDH(curve=curve), reps)
    ecdh_instance = instance

    # ECDH: secreto compartido con un par efímero
    peer = ECDH(curve=curve)
    ecdh_times, _ = _timeit(
        lambda: ecdh_instance.shared_secret(peer.public_key), reps
    )

    # ECDSA: firma y verificación
    ecdsa_instance = ECDSA(curve=curve)
    sign_times, sig = _timeit(lambda: ecdsa_instance.sign(MESSAGE), reps)
    verify_times, _ = _timeit(
        lambda: ecdsa_instance.verify(sig, MESSAGE), reps
    )

    # EC-ElGamal: cifrado y descifrado
    elgamal_instance = ECElGamal(curve=curve)
    enc_times, bundle = _timeit(
        lambda: elgamal_instance.encrypt(MESSAGE, elgamal_instance.public_key),
        reps,
    )
    dec_times, _ = _timeit(lambda: elgamal_instance.decrypt(bundle), reps)

    ecdh_sizes    = ecdh_instance.key_sizes()
    ecdsa_sizes   = ecdsa_instance.key_sizes()

    return {
        "sistema":       f"ECC-{curve}",
        "bits":          int(curve.split("-")[1]),
        "gen_ms":        _mean_ms(gen_times),
        "gen_std_ms":    _stdev_ms(gen_times),
        "ecdh_ms":       _mean_ms(ecdh_times),
        "enc_elgamal_ms":_mean_ms(enc_times),
        "dec_elgamal_ms":_mean_ms(dec_times),
        "sign_ms":       _mean_ms(sign_times),
        "verify_ms":     _mean_ms(verify_times),
        "priv_bytes":    ecdh_sizes["private_key_bytes"],
        "pub_bytes":     ecdh_sizes["public_key_bytes"],
        "sig_bytes":     len(sig),
    }

# ── Presentación ───────────────────────────────────────────────────────────────

def print_rsa_table(results: list):
    w = 76
    print("\n" + "=" * w)
    print("RSA — Tiempos (ms) y tamaños (bytes)")
    print("=" * w)
    header = (f"{'Sistema':<12} {'Gen':>8} {'Cifr':>8} {'Descifr':>8} "
              f"{'Firma':>8} {'Verif':>8} {'Priv(B)':>8} {'CT(B)':>7}")
    print(header)
    print("-" * w)
    for r in results:
        print(f"{r['sistema']:<12} {r['gen_ms']:>8.2f} {r['enc_ms']:>8.3f} "
              f"{r['dec_ms']:>8.2f} {r['sign_ms']:>8.3f} {r['verify_ms']:>8.3f} "
              f"{r['priv_bytes']:>8} {r['ct_bytes']:>7}")

def print_ecc_table(results: list):
    w = 88
    print("\n" + "=" * w)
    print("ECC — Tiempos (ms) y tamaños (bytes)")
    print("=" * w)
    header = (f"{'Sistema':<12} {'Gen':>7} {'ECDH':>7} {'ElGamal enc':>12} "
              f"{'ElGamal dec':>12} {'Firma':>7} {'Verif':>7} "
              f"{'Priv(B)':>8} {'Sig(B)':>7}")
    print(header)
    print("-" * w)
    for r in results:
        print(f"{r['sistema']:<12} {r['gen_ms']:>7.3f} {r['ecdh_ms']:>7.3f} "
              f"{r['enc_elgamal_ms']:>12.3f} {r['dec_elgamal_ms']:>12.3f} "
              f"{r['sign_ms']:>7.3f} {r['verify_ms']:>7.3f} "
              f"{r['priv_bytes']:>8} {r['sig_bytes']:>7}")

def save_csv(rsa_results: list, ecc_results: list, path: str):
    rows = []
    for r in rsa_results:
        rows.append({
            "sistema":      r["sistema"],
            "bits":         r["bits"],
            "gen_ms":       r["gen_ms"],
            "gen_std_ms":   r["gen_std_ms"],
            "ecdh_ms":      "",
            "enc_ms":       r["enc_ms"],
            "dec_ms":       r["dec_ms"],
            "sign_ms":      r["sign_ms"],
            "verify_ms":    r["verify_ms"],
            "priv_bytes":   r["priv_bytes"],
            "ct_sig_bytes": r["ct_bytes"],
        })
    for r in ecc_results:
        rows.append({
            "sistema":      r["sistema"],
            "bits":         r["bits"],
            "gen_ms":       r["gen_ms"],
            "gen_std_ms":   r["gen_std_ms"],
            "ecdh_ms":      r["ecdh_ms"],
            "enc_ms":       r["enc_elgamal_ms"],
            "dec_ms":       r["dec_elgamal_ms"],
            "sign_ms":      r["sign_ms"],
            "verify_ms":    r["verify_ms"],
            "priv_bytes":   r["priv_bytes"],
            "ct_sig_bytes": r["sig_bytes"],
        })
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nResultados guardados en: {path}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Benchmark RSA vs ECC")
    parser.add_argument("--reps", type=int, default=20,
                        help="Repeticiones por operación (default: 20)")
    parser.add_argument("--csv", type=str, default="resultados_benchmark.csv",
                        help="Ruta del fichero CSV de salida")
    args = parser.parse_args()

    reps = args.reps
    print(f"Benchmark RSA vs ECC — {reps} repeticiones por operación")
    print(f"Mensaje: {MESSAGE.decode()!r} ({len(MESSAGE)} bytes)\n")

    rsa_results = []
    for bits in RSA_SIZES:
        print(f"  RSA-{bits}...", end=" ", flush=True)
        rsa_results.append(benchmark_rsa(bits, reps))
        print("listo")

    ecc_results = []
    for curve in ECC_CURVES:
        print(f"  ECC-{curve}...", end=" ", flush=True)
        ecc_results.append(benchmark_ecc(curve, reps))
        print("listo")

    print_rsa_table(rsa_results)
    print_ecc_table(ecc_results)
    save_csv(rsa_results, ecc_results, args.csv)


if __name__ == "__main__":
    main()