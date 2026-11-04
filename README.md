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

## Détection de brute force

Une identité est un tuple `(IP source, utilisateur)`. Pour chaque identité,
un `deque(maxlen=threshold)` conserve les derniers résultats d'authentification
sous forme de booléens. Les événements réseau sont ignorés par cette règle.
La boucle `while` enlève les succès en tête ; la boucle `for` vérifie les essais.
`continue` passe au prochain échec ; `break` interrompt la validation sur un
succès intérieur ; `for...else` confirme que la fenêtre ne contient que des
échecs. Si elle atteint le seuil, une alerte est émise et la fenêtre supprimée.

On obtient une alerte par **bloc disjoint** de X échecs : douze échecs au seuil 5
donnent deux alertes et deux essais restants. Un succès empêche d'additionner les
échecs qui le précèdent avec ceux qui le suivent. Il n'y a pas de fenêtre de temps :
les événements sont considérés dans l'ordre de lecture fourni. Les fichiers
sont lus successivement, sans tri chronologique global. Une ligne rejetée est
ignorée ; un succès contenu dans une ligne invalide ne peut donc pas réinitialiser
la détection. Ce choix et les alertes nécessitent une interprétation humaine.

## Ajouter une règle

Une règle reçoit un `Log` et les options nommées ; elle retourne un dictionnaire
d'alerte ou `None`. Exemple à placer dans `src/rules.py` :

```python
def detect_admin(log: Log, **config: Any) -> Alert | None:
    if log["user"] == "admin" and log["event"] == "LOGIN_SUCCESS":
        return make_alert(log, "ADMIN_LOGIN", "Connexion administrateur")
    return None
```

Importer cette fonction dans `main.py` et la passer à `apply_security_rules`
avec les trois autres fonctions. `*args` reçoit les fonctions elles-mêmes ;
`**kwargs` transmet notamment `threshold`, `histories` et `blacklist`.
L'état `histories` appartient à une seule analyse et son seuil reste fixe.

## Correspondance avec l'énoncé

| Exigence | Mise en œuvre |
|---|---|
| Python 3.10+, environnement, dépendances | garde de version, `.venv`, `requirements.txt` |
| Package et démonstration | `src/__init__.py` et `main.py` |
| `yield`, `yield from` | `read_logs`, `read_multiple_logs` |
| Dictionnaires, types variés, tuples | `Log`, `parse_log`, `connection`, `source` |
| `filter`, `lambda`, `map` | `process_logs` |
| `match-case` texte/dict/tuple | `describe_payload` |
| `set`, `frozenset`, `\|`, `&`, `-`, `^` | `Analyzer.summary`, `load_blacklist` |
| `defaultdict` | compteurs par niveau, utilisateur et règle |
| `for`, `while`, `break`, `continue`, `else` | `detect_bruteforce` |
| `*args`, `**kwargs`, fonctions objets | `apply_security_rules` |
| `globals()`, `locals()` | `run`, `export_audit` |
| Typage, exceptions, PEP8 | annotations, erreurs contrôlées, tests et contrôle de style |
| Dépôt et rapport | dépôt Git local, `report/rapport.ipynb` exécuté |

## Mémoire et limites

La lecture, le parsing, le filtrage et les transformations sont paresseux.
Les alertes sont écrites au fil de l'eau. La mémoire dépend de la taille d'une
ligne, du nombre d'IP/utilisateurs distincts, de la blacklist et des fenêtres
d'authentification, **pas de la totalité des lignes**. Avec U IP, V utilisateurs,
P couples actifs et un seuil X, l'état principal est de l'ordre de
`O(U + V + P × X + taille_blacklist)`. Les ensembles exacts ne peuvent pas rester
constants si chaque nouvelle ligne introduit une nouvelle IP. Une ligne unique
immense peut elle aussi consommer beaucoup de mémoire.

Le programme analyse un flux fini et émet les alertes progressivement ; il ne
surveille pas en continu un fichier en cours d'écriture (`tail -f`). Il n'effectue
aucun blocage réseau et n'est pas un SIEM de production. Ces limites gardent le
projet lisible pour un débutant et sont distinctes des notions évaluées.

## Validation et présentation orale

22 tests couvrent le parsing, les erreurs, la lecture à la demande, les ensembles,
les règles, les seuils, les identités séparées, l'audit et les exports complets.
Exécution vérifiée sur Python 3.14.7 ; syntaxe vérifiée pour Python 3.10.
Le contrôle PEP8 est réalisé avec un outil de qualité dans un environnement
séparé, sans ajouter de dépendance au programme livré.

Pour une démonstration en cinq minutes :

1. Lancer `python main.py` et ouvrir `results/summary.json`.
2. Expliquer une ligne de `data/auth.log` et son dictionnaire après parsing.
3. Montrer que `yield` livre une seule ligne puis suspend la fonction.
4. Montrer les deux alertes BRUTE_FORCE dans `results/alerts.jsonl`.
5. Expliquer le rôle du succès de bob et du `for...else`.
6. Présenter le tableau de conformité et les résultats du Notebook.

Le rapport reprend les choix et les limites. Les membres du trinôme peuvent
ajouter leurs noms et reformuler leurs explications après avoir étudié le code.
