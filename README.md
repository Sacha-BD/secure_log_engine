# SecureLog Engine

Projet pédagogique ING3 — analyse progressive de logs d'une salle informatique.
Python **3.10+**, bibliothèque standard uniquement. Le programme lit, valide,
normalise, compte et détecte des événements suspects sans charger les fichiers
complets en mémoire. Toutes les données fournies sont fictives.

## Démarrer sur ce Mac

Le projet et son environnement isolé sont déjà créés. Dans un terminal :

```bash
cd /Users/sacha/VSCodeProjects/secure_log_engine
source .venv/bin/activate
python main.py
python -m unittest discover -s tests -v
```

Dans VS Code : ouvrir ce dossier, sélectionner l'interpréteur
`.venv/bin/python`, puis lancer `main.py`. Le rapport déjà exécuté se trouve
dans `report/rapport.ipynb` et peut se lire sans relancer ses cellules.

## Réinstaller ailleurs

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Sous Windows, activer avec `.venv\Scripts\Activate.ps1` dans PowerShell.
`requirements.txt` est volontairement **vide** : il a été généré par
`python -m pip freeze` dans l'environnement neuf. Le moteur, les tests et
les cellules du rapport n'importent que la bibliothèque standard.
Ne pas inclure `.venv` dans le dépôt ou le rendu. Après ajout d'une dépendance,
regénérer ce fichier avec `python -m pip freeze > requirements.txt`.
Un éditeur de notebooks et son noyau sont des outils de lecture/exécution
optionnels ; les résultats enregistrés sont consultables sans installer Jupyter.

## Fichiers à comprendre

```text
secure_log_engine/
├── main.py                 point d'entrée et enchaînement des étapes
├── requirements.txt        dépendances exportées par pip freeze
├── README.md               installation, démonstration et choix techniques
├── .gitignore              exclut environnement, caches et résultats
├── data/
│   ├── auth.log            connexions SSH réussies et échouées
│   ├── network.log         connexions réseau et erreurs applicatives
│   └── blacklist.txt       IP de test à surveiller
├── src/
│   ├── __init__.py         fait de src un package Python
│   ├── ingestion.py        yield, yield from et lecture de la blacklist
│   ├── parser.py           validation et dictionnaire Log typé
│   ├── processing.py       filter, lambda, map et match-case
│   ├── analyzer.py         compteurs et opérations sur les ensembles
│   ├── rules.py            trois règles et moteur extensible
│   └── audit.py            noms, types et tailles des variables en mémoire
├── tests/
│   └── test_engine.py      tests des comportements et du pipeline complet
└── report/
    └── rapport.ipynb       rapport synthétique avec résultats exécutés
```

`results/` est créé à l'exécution et ignoré par Git.
L'ordre de lecture conseillé est `main.py`, puis `ingestion.py`, `parser.py`,
`processing.py`, `analyzer.py`, `rules.py` et `audit.py`.

