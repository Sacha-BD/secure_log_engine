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
lecture des fichiers ou de l'entrée standard
        ↓
filtrage des lignes vides et des commentaires
        ↓
parsing, normalisation et rejet des lignes invalides
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

Le fichier `requirements.txt` contient le résultat de `python -m pip freeze`
dans un environnement virtuel neuf. Il est vide car le moteur utilise
uniquement la bibliothèque standard. L'environnement `.venv` reste local.

## Résultat de la démonstration

Avec les fichiers fournis, la commande `python main.py` affiche ce résumé,
suivi du chemin du dossier des résultats :

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
├── .gitignore
├── README.md
├── main.py
├── requirements.txt
├── data/
│   ├── auth.log
│   ├── network.log
│   └── blacklist.txt
├── src/
│   ├── __init__.py
│   ├── addresses.py
│   ├── ingestion.py
│   ├── parser.py
│   ├── processing.py
│   ├── analyzer.py
│   ├── rules.py
│   └── audit.py
├── tests/
│   ├── __init__.py
│   ├── test_engine.py
│   └── benchmark_memory.py
└── report/
    └── rapport.ipynb
```

- `main.py` relie toutes les étapes et gère les options de la commande.
- `addresses.py` fournit une notation IP commune aux logs et à la blacklist.
- `ingestion.py` lit les fichiers et les flux texte ligne par ligne.
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

Deux formats sont acceptés en UTF-8.

```text
2026-09-29 08:00:00|INFO|192.0.2.10|alice|LOGIN_SUCCESS|Session ouverte
{"timestamp":"2026-09-29 08:00:20","level":"INFO","ip":"192.0.2.10","user":"alice","event":"CONNECTION","payload":["192.0.2.100",443,"TCP"]}
```

Les champs texte obligatoires sont `timestamp`, `level`, `ip`, `user` et
`event`. Le format du projet utilise des dates locales sans fuseau, des IP
IPv4 ou IPv6 et les niveaux `INFO`, `WARNING`, `ERROR` et `CRITICAL`. Le
payload peut être du texte, un objet JSON ou une connexion sous la forme
`[IP, port, protocole]` avec `TCP` ou `UDP`.
Pour comparer les IP, le moteur ramène les IPv4 mappées en IPv6 à leur
notation IPv4 et ignore les identifiants de zone IPv6.
Les nombres JSON non finis (`NaN`, `Infinity`, débordements) et les chaînes
Unicode invalides sont rejetés, tout comme les clés JSON répétées, même dans
les objets imbriqués.

### Détection de force brute

Le seuil par défaut est de cinq échecs consécutifs, modifiable avec
`--threshold`. Le suivi se fait pour le
couple `(IP, utilisateur)`. Une connexion réussie remet la série à zéro.
Chaque bloc disjoint de cinq échecs produit une alerte avec le seuil par défaut :
dix échecs consécutifs produisent donc deux alertes.

Quand la file d'une identité atteint le seuil, la boucle `for` examine les
tentatives en les retirant. Elle passe à la suivante avec `continue` après un
échec et s'interrompt avec `break` après un succès. Le `else` déclenche l'alerte
si toutes les tentatives examinées étaient des échecs. La boucle `while`
traite la file dès qu'elle atteint le seuil ou qu'un succès doit l'annuler.
Un succès libère immédiatement l'historique de l'identité, même si le seuil
n'était pas atteint.

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

# Simuler un flux et afficher les alertes à mesure qu'elles sont détectées
cat data/auth.log data/network.log | python main.py --stream-alerts -

# Arrêter le programme dès la première ligne incorrecte
python main.py --strict
```

Le caractère `-` représente l'entrée standard UTF-8 et peut être placé parmi
les fichiers une seule fois. Avec `--stream-alerts`, la sortie standard
contient uniquement les alertes JSONL. Le résumé s'affiche sur la sortie
d'erreur. Les fichiers de résultats sont publiés quand l'analyse se termine
avec succès. En mode strict, les alertes déjà émises restent visibles si une
ligne invalide interrompt ensuite le flux.

Le dossier `results/` contient ensuite :

- `summary.json` : les statistiques générales ;
- `alerts.jsonl` : les alertes détectées, une par ligne ;
- `audit.json` : les noms et types des variables observées pendant l'exécution.

## Tests

```bash
python -m unittest discover -s tests -v
```

Les 45 tests couvrent notamment le parsing, les lignes invalides, la
blacklist, les opérations sur les ensembles, la détection de force brute et
le passage d'un flux par la CLI. Ils vérifient aussi qu'une alerte est émise
avant la fermeture de l'entrée standard et que les sorties du notebook
correspondent à une nouvelle exécution de ses cellules. Les échecs de
publication sont simulés dans 48 cas : chaque étape de sauvegarde et de
remplacement, avec toutes les combinaisons de résultats préexistants.
Les tests contrôlent également la conservation des anciens résultats en cas
d'erreur d'export et le traitement des octets UTF-8 invalides sur l'entrée
standard, en modes normal et strict. Les tests et les
cellules utilisent uniquement la bibliothèque standard ; l'installation de
Jupyter n'est pas nécessaire. Le notebook peut être consulté sur GitHub
avec ses sorties sauvegardées.

La suite passe sous Python 3.10.22, 3.12.16, 3.14.10 et 3.15.2.

Pour reproduire les mesures mémoire du rapport :

```bash
python -m tests.benchmark_memory --lines 10000 100000 1000000
python -m tests.benchmark_memory --lines 10000 --distinct
```

Le benchmark génère les fichiers ligne par ligne, puis mesure le pipeline
avec `tracemalloc`. Il contrôle aussi les nombres d'événements et d'alertes.
La mesure porte sur les allocations Python, pas sur toute la mémoire du
processus. Les données temporaires sont automatiquement supprimées.

## Limites

Les sources sont traitées dans l'ordre donné à la commande, sans tri par
horodatage. Pour surveiller un fichier qui continue de grandir, il faut
rediriger les nouvelles lignes vers l'entrée standard avec un outil comme
`tail -f`. Les alertes signalent une activité à examiner.

La mémoire dépend de la taille des lignes, de la diversité des IP et des
utilisateurs, ainsi que du nombre d'échecs en attente pour les couples suivis
par la règle de force brute. Le seuil borne le nombre d'échecs en attente par
couple.

Une seule analyse peut publier dans un dossier de résultats à la fois. En cas
d'erreur d'écriture pendant la publication, les résultats précédents sont
restaurés. Les fichiers restent remplacés individuellement. Pour conserver
les résultats de chaque analyse parallèle, utilisez des dossiers `--output`
distincts. Après une interruption brutale pendant la publication, le dossier
`.securelog-publish` peut contenir les sauvegardes à restaurer avant de relancer.
