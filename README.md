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

## Démonstration et options

```bash
python main.py
python main.py --threshold 3 --output results/seuil3
python main.py data/auth.log data/network.log --blacklist data/blacklist.txt
python main.py --help
python main.py --strict --output results/strict
```

La dernière commande s'arrête volontairement : le jeu de test comprend trois
lignes invalides. Le mode normal les signale sur la sortie d'erreur et continue.
Le mode strict retourne le code 1 ; les arguments invalides retournent 2.
Une exécution réussie retourne 0. Un fichier absent, un encodage autre que UTF-8
ou une blacklist invalide arrête également l'analyse.
Les chemins fournis sont relatifs au terminal ; les chemins par défaut sont
relatifs au projet. Le programme fonctionne donc aussi depuis un autre dossier.

Résultats attendus avec le seuil par défaut de 5 :

| Mesure | Résultat |
|---|---:|
| Lignes lues, commentaires compris | 28 |
| Lignes vides ou commentaires ignorés | 3 |
| Logs valides analysés | 22 |
| Lignes invalides rejetées | 3 |
| INFO / WARNING / ERROR / CRITICAL | 5 / 5 / 11 / 1 |
| Alertes BRUTE_FORCE | 2 |
| Alertes BLACKLIST | 12 |
| Alertes CRITICAL | 1 |

Une même ligne peut déclencher plusieurs règles. Une alerte BLACKLIST est
émise **par événement**, et non par IP unique.
Les adresses `203.0.113.66` (admin) et `198.51.100.24` (root) produisent chacune
un bloc de cinq échecs. Les essais de bob sont séparés par un succès : ils ne
produisent aucune alerte de brute force au seuil de 5.

### Fichiers produits

- `summary.json` : compteurs, IP uniques et quatre opérations d'ensembles.
- `alerts.jsonl` : une alerte JSON par ligne, écrite dès sa détection.
- `audit.json` : noms, types et tailles des variables des portées du pipeline
  et du module d'audit, sans recopier leurs valeurs.

Les sorties sont préparées dans un dossier temporaire, puis remplacées après
une analyse réussie. Une erreur de parsing conserve les anciens résultats.
Le remplacement des trois fichiers n'est pas une transaction : une panne au
moment des remplacements peut laisser un mélange de deux exécutions.
Ne pas lancer deux analyses simultanées vers le même dossier de résultats.

## Format des logs

Les fichiers sont encodés en UTF-8. Deux représentations sont acceptées :

```text
2026-09-29 08:00:00|INFO|192.0.2.10|alice|LOGIN_SUCCESS|Session ouverte
2026-09-29 08:00:01|INFO|192.0.2.10|alice|CONNECTION|["192.0.2.100",443,"TCP"]
```

```json
{"timestamp":"2026-09-29 08:00:02","level":"ERROR","ip":"192.0.2.30","user":"service","event":"TIMEOUT","payload":{"level":"ERROR","code":504}}
```

Le format texte comporte six champs : date, niveau, IP source, utilisateur,
événement, payload. La séparation est limitée aux cinq premiers `|` pour que
le message puisse en contenir. Le payload accepte une chaîne, un objet JSON
ou une liste `[IP destination, port, protocole]`, convertie en tuple immuable.
Une chaîne commençant par `{` ou `[` est interprétée comme du JSON.
Les dates ISO locales sans fuseau sont converties en `datetime`. Les IP sont
validées et normalisées (IPv4 ou IPv6), les ports vont de 1 à 65535 et les
protocoles autorisés sont TCP et UDP. L'utilisateur reste sensible à la casse ;
le niveau, le protocole et l'événement passent en majuscules.

`match-case` route le payload normalisé : texte brut, dictionnaire d'erreur
ou générique, tuple de connexion. Le dictionnaire principal conserve également
la provenance fixe `(fichier, numéro de ligne)` et un message lisible.

