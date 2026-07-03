#!/usr/bin/env python3
"""Compacta client_flow_aggs, removendo a duplicidade retroativa introduzida pela
porta efêmera do cliente antes do fix em clientguard.py/storage.bucket_client_port
(mesma classe de achado do flow_aggs no FlowGuard). Só faz sentido rodar UMA VEZ,
sobre um banco já bloatado por essa causa — depois do fix em produção, novos ciclos
já gravam a chave bucketizada e não precisam de compactação recorrente.

Rodar com o daemon PARADO (evita que o daemon escreva na mesma tabela durante o
rebuild, e evita concorrência pelo mesmo arquivo/lock):

  systemctl stop clientguard.service
  venv/bin/python tools/compact_client_flow_aggs.py [--config config.yaml]
  systemctl start clientguard.service
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import storage  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=str(Path(__file__).resolve().parent.parent / "config.yaml"))
    parser.add_argument("--skip-vacuum", action="store_true",
                         help="pula o VACUUM final (mais rápido, mas não libera espaço em disco)")
    args = parser.parse_args()

    config = yaml.safe_load(open(args.config, encoding="utf-8"))
    amplifier_ports = set(config["detection"]["amplifier_ports"])
    db_path = config["database"]["path"]

    print(f"Compactando {db_path} (portas preservadas: {sorted(amplifier_ports)})...")
    conn = storage.connect(db_path)
    total_before = conn.execute("SELECT SUM(bytes) FROM client_flow_aggs").fetchone()[0] or 0

    t0 = time.monotonic()
    before, after = storage.compact_client_flow_aggs(conn, amplifier_ports)
    elapsed = time.monotonic() - t0

    total_after = conn.execute("SELECT SUM(bytes) FROM client_flow_aggs").fetchone()[0] or 0
    if total_before != total_after:
        conn.close()
        raise SystemExit(
            f"ABORTADO: soma de bytes não bate (antes={total_before}, depois={total_after}) — "
            "não deveria acontecer, banco preservado como estava, investigar antes de rodar de novo."
        )

    reduction = 100 * (1 - after / before) if before else 0.0
    print(f"{before} -> {after} linhas ({reduction:.1f}% de redução) em {elapsed:.1f}s — soma de bytes preservada.")

    if not args.skip_vacuum:
        print("Rodando VACUUM (libera o espaço em disco das linhas removidas)...")
        t0 = time.monotonic()
        conn.execute("VACUUM")
        print(f"VACUUM concluído em {time.monotonic() - t0:.1f}s")

    conn.close()


if __name__ == "__main__":
    main()
