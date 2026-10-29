"""Пересобрать встроенные справочники из локальных исходников.

    python scripts/build_reference_data.py --mitre enterprise-attack.json --lolbas-dir LOLBAS/yml

enterprise-attack.json: https://github.com/mitre/cti (enterprise-attack/enterprise-attack.json)
LOLBAS/yml: git clone https://github.com/LOLBAS-Project/LOLBAS
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from soc_toolkit.reference.updater import convert_lolbas_yml, convert_mitre, write_gz

DATA = Path(__file__).resolve().parent.parent / "src" / "soc_toolkit" / "reference" / "data"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mitre", type=Path, help="enterprise-attack.json")
    ap.add_argument("--lolbas-dir", type=Path, help="папка yml из репозитория LOLBAS")
    args = ap.parse_args()
    if args.mitre:
        data = convert_mitre(json.loads(args.mitre.read_text(encoding="utf-8")))
        write_gz(DATA / "mitre.json.gz", data)
        print(f"MITRE {data['version']}: {len(data['techniques'])} техник, {len(data['groups'])} групп")
    if args.lolbas_dir:
        entries = convert_lolbas_yml(sorted(args.lolbas_dir.rglob("*.yml")))
        write_gz(DATA / "lolbas.json.gz", entries)
        print(f"LOLBAS: {len(entries)} записей")


if __name__ == "__main__":
    main()
