# SecureLog Engine

Projet Python ING3 réalisé par Lukas MAUFFRÉ, Sacha BEHLOULI-DROLLÉE et
Jeanne TONDA.

Notre programme analyse des fichiers de logs système et réseau. Il lit les
lignes une par une, transforme les informations utiles, calcule des
statistiques et signale quelques événements suspects.

Nous avons utilisé uniquement la bibliothèque standard de Python afin de
garder un projet simple à installer et à comprendre. Les données présentes
dans `data/` sont fictives.

## Fonctionnement général

Le programme suit ces étapes :

```text
lecture des fichiers
        ↓
transformation des lignes en dictionnaires
        ↓
filtrage et normalisation
        ↓
calcul des statistiques
        ↓
application des règles de sécurité
        ↓
création des fichiers de résultats
```

Les trois règles de sécurité détectent :

- une série de cinq échecs de connexion pour la même IP et le même utilisateur ;
- une activité provenant d'une IP présente dans la blacklist ;
- un événement dont le niveau est `CRITICAL`.

## Installation

Le projet demande Python 3.10 ou une version plus récente.

```bash
git clone https://github.com/Sacha-BD/secure_log_engine.git
cd secure_log_engine
```

Sur macOS ou Linux :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Sur Windows avec PowerShell :

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Le fichier `requirements.txt` est vide car aucune bibliothèque externe n'est
utilisée. L'environnement `.venv` reste sur l'ordinateur de chaque membre et
n'est pas envoyé sur GitHub.

## Résultat de la démonstration

Avec les fichiers fournis, la commande `python main.py` doit afficher :

```text
SECURELOG ENGINE
Logs analysés : 22
Lignes rejetées : 3
Par niveau : {'CRITICAL': 1, 'ERROR': 11, 'INFO': 5, 'WARNING': 5}
Alertes : {'BLACKLIST': 12, 'BRUTE_FORCE': 2, 'CRITICAL': 1}
```

Trois avertissements apparaissent avant ce résumé. C'est volontaire : nous
avons placé trois mauvaises lignes dans les fichiers de test pour vérifier que
le programme les refuse sans arrêter toute l'analyse.

Les deux alertes de force brute correspondent aux utilisateurs `admin` et
`root`. Les échecs de `bob` sont séparés par une connexion réussie, donc ils ne
forment pas une série de cinq.

## Organisation des fichiers

```text
secure_log_engine/
├── main.py
├── requirements.txt
├── data/
│   ├── auth.log
│   ├── network.log
│   └── blacklist.txt
├── src/
│   ├── ingestion.py
│   ├── parser.py
│   ├── processing.py
│   ├── analyzer.py
│   ├── rules.py
│   └── audit.py
├── tests/
│   └── test_engine.py
└── report/
    └── rapport.ipynb
```

- `main.py` relie toutes les étapes et gère les options de la commande.
- `ingestion.py` lit un ou plusieurs fichiers ligne par ligne.
- `parser.py` vérifie les champs et crée les dictionnaires de logs.
- `processing.py` filtre et normalise les données.
- `analyzer.py` calcule les compteurs et les ensembles d'IP.
- `rules.py` contient les règles de sécurité.
- `audit.py` crée un rapport simple sur les variables utilisées.
- `rapport.ipynb` présente le fonctionnement et les résultats du projet.

Nous conseillons de lire les fichiers dans cet ordre : `main.py`, puis les
modules de `src/` dans l'ordre de la liste ci-dessus.

## Choix réalisés

### Lecture des logs

Nous utilisons `yield` pour renvoyer une seule ligne à la fois. Le fichier
complet n'est donc pas placé en mémoire. `yield from` permet ensuite de lire
plusieurs fichiers à la suite.

Chaque ligne valide devient un dictionnaire. Une connexion réseau est aussi
représentée par un tuple `(IP, port, protocole)`, car ces trois informations ne
doivent pas changer pendant le traitement.

### Détection de force brute

Nous avons choisi un seuil de cinq échecs consécutifs. Le suivi se fait pour le
couple `(IP, utilisateur)`. Une connexion réussie remet la série à zéro.

Cette partie utilise volontairement `while`, `for`, `continue`, `break` et la
clause `else` de la boucle, car ces instructions sont demandées dans l'énoncé.

### Moteur de règles

La fonction `apply_security_rules(*args, **kwargs)` reçoit les fonctions de
sécurité dans `*args` et leur configuration dans `**kwargs`. Il est donc
possible d'ajouter une nouvelle règle sans réécrire le moteur.

## Notions Python demandées

| Notion | Emplacement principal |
|---|---|
| `yield` et `yield from` | `src/ingestion.py` |
| dictionnaires et tuples | `src/parser.py` |
| `filter`, `lambda` et `map` | `src/processing.py` |
| `match-case` | `src/processing.py` |
| `set` et `frozenset` | `src/analyzer.py`, `src/ingestion.py` |
| union, intersection et différences | `src/analyzer.py` |
| `defaultdict` | `src/analyzer.py`, `main.py` |
| boucles et clause `else` | `src/rules.py` |
| `*args` et `**kwargs` | `src/rules.py` |
| `globals()` et `locals()` | `src/audit.py`, `main.py` |
| typage et exceptions | ensemble des modules |

## Autres commandes utiles

```bash
# Afficher les options
python main.py --help

# Changer le seuil de détection
python main.py --threshold 3

# Choisir les fichiers à analyser
python main.py data/auth.log data/network.log

# Arrêter le programme dès la première ligne incorrecte
python main.py --strict
```

Le dossier `results/` contient ensuite :

- `summary.json` : les statistiques générales ;
- `alerts.jsonl` : les alertes détectées, une par ligne ;
- `audit.json` : les noms et types des variables observées pendant l'exécution.

## Tests

```bash
python -m unittest discover -s tests -v
```

Les 22 tests vérifient notamment le parsing, les lignes invalides, la
blacklist, les opérations sur les ensembles, la détection de force brute et
l'exécution complète du programme.

## Limites

Ce projet est une démonstration pédagogique. Il analyse des fichiers déjà
créés, mais ne surveille pas un fichier en continu. Les alertes indiquent une
activité à examiner : elles ne bloquent aucune connexion automatiquement.

Les fichiers sont traités dans l'ordre donné à la commande. Le programme ne les
reclasse pas par date, car cela demanderait de conserver beaucoup plus de
données en mémoire.
