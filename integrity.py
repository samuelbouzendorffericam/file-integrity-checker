#!/usr/bin/env python3
"""integrity : vérifie l'intégrité d'un dossier avec des empreintes SHA-256.

Principe (comme les outils FIM de type Tripwire) :
  1. `init`  enregistre l'empreinte SHA-256 de chaque fichier (la "baseline") ;
  2. `check` recalcule les empreintes et signale ce qui a été ajouté,
     supprimé ou modifié depuis la baseline.
Code de sortie de `check` : 0 = rien n'a changé, 1 = changements détectés.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_BASELINE = "baseline.json"


def sha256_file(path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(root, ignore=()) -> dict:
    """Retourne {chemin_relatif: sha256} pour tous les fichiers sous `root`."""
    root = Path(root).resolve()
    ignored = {Path(p).resolve() for p in ignore}
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or path.resolve() in ignored:
                continue
            try:
                files[path.relative_to(root).as_posix()] = sha256_file(path)
            except OSError as err:
                print(f"Avertissement : {path} illisible ({err.strerror})", file=sys.stderr)
    return files


def save_baseline(files: dict, baseline_path, root) -> None:
    data = {
        "version": 1,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": str(Path(root).resolve()),
        "files": files,
    }
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def load_baseline(baseline_path) -> dict:
    try:
        with open(baseline_path, encoding="utf-8") as f:
            return json.load(f)["files"]
    except FileNotFoundError:
        raise SystemExit(f"Baseline introuvable : {baseline_path} (lancez d'abord `init`).")


def compare(old: dict, new: dict) -> dict:
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "modified": sorted(k for k in set(old) & set(new) if old[k] != new[k]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Vérification d'intégrité par SHA-256.")
    parser.add_argument("command", choices=["init", "check"])
    parser.add_argument("directory")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE, help="fichier baseline JSON")
    parser.add_argument("--force", action="store_true", help="écrase une baseline existante")
    args = parser.parse_args()

    files = scan(args.directory, ignore=[args.baseline])
    if args.command == "init":
        if Path(args.baseline).exists() and not args.force:
            raise SystemExit(f"{args.baseline} existe déjà (utilisez --force pour l'écraser).")
        save_baseline(files, args.baseline, args.directory)
        print(f"Baseline créée : {len(files)} fichier(s) enregistré(s) dans {args.baseline}")
        return 0

    changes = compare(load_baseline(args.baseline), files)
    if not any(changes.values()):
        print("OK : aucun changement depuis la baseline.")
        return 0
    labels = {"added": "AJOUTÉ", "removed": "SUPPRIMÉ", "modified": "MODIFIÉ"}
    for key in ("modified", "added", "removed"):
        for name in changes[key]:
            print(f"{labels[key]:9} {name}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
