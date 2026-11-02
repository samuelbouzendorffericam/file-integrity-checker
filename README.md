# file-integrity-checker

Outil en ligne de commande (Python, bibliothèque standard) qui détecte les **fichiers ajoutés, supprimés ou modifiés** dans un dossier grâce à des empreintes SHA-256. C'est le principe des outils de surveillance d'intégrité de type Tripwire ou AIDE.

## Fonctionnement

1. `init` enregistre l'empreinte SHA-256 de chaque fichier dans une *baseline* (`baseline.json`).
2. `check` recalcule les empreintes et compare avec la baseline.

```bash
python3 integrity.py init data
# Baseline créée : 2 fichier(s) enregistré(s) dans baseline.json

# ... des fichiers changent ...

python3 integrity.py check data
# MODIFIÉ   a.txt
# AJOUTÉ    c.txt
# SUPPRIMÉ  b.txt
```

Le code de sortie de `check` vaut `0` si rien n'a changé et `1` sinon, ce qui permet de l'utiliser dans un script ou une tâche planifiée.

Options : `--baseline fichier.json` pour choisir l'emplacement de la baseline, `--force` pour écraser une baseline existante.

## Concepts illustrés

- **Fonction de hachage** : la moindre modification d'un fichier change complètement son empreinte SHA-256.
- **Intégrité** (le « I » de la triade Confidentialité / Intégrité / Disponibilité).
- Lecture par blocs pour hacher de gros fichiers sans les charger en mémoire.

## Tests

```bash
python3 -m unittest -v
```

Les tests vérifient notamment l'empreinte de `abc` contre le vecteur de test officiel SHA-256.

## Limites

- Si un attaquant peut écrire dans la baseline, il peut la modifier : en pratique elle doit être stockée hors de la machine surveillée ou protégée.
- Seul le contenu est vérifié : pas les permissions, le propriétaire ni les dates.

## Pistes d'amélioration

- Signer la baseline (HMAC) pour détecter sa falsification.
- Enregistrer aussi les permissions et la taille.
- Ajouter des motifs d'exclusion (`*.log`, `.git/`).
- Exporter le rapport en JSON.

## Licence

MIT, voir [LICENSE](LICENSE).

---

*Réalisé avec l'aide de Claude (IA), relu et testé par l'auteur.*
