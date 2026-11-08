# Vérification avant rendu

Contrôle du 8 novembre 2026 à partir de l'énoncé « Engine de traitement et
d'analyse de flux de données sécurisé en temps réel », niveau ING3.

## Correspondance avec les consignes

| Exigence | Réalisation et vérification |
|---|---|
| Python 3.10+, environnement isolé | Installation et tests dans des venv Python 3.10.22 et 3.12.16 ; tests également dans le venv du projet, Python 3.14.10. |
| Dépendances reproductibles | `requirements.txt` régénéré avec `python -m pip freeze` dans le venv 3.10 neuf. Fichier vide : le moteur, les tests, le benchmark et les cellules du rapport n'importent que la bibliothèque standard et le package du projet. |
| Package et point d'entrée | Package `src/` avec `__init__.py`, modules séparés et orchestration par `main.py`. |
| Notebook réservé à la démonstration | `report/rapport.ipynb` appelle le moteur des fichiers `.py`, affiche ses résultats et explique les mesures. Aucun traitement métier n'est implémenté uniquement dans le notebook. |
| Lecture progressive avec `yield` | `read_stream()` produit une ligne à la fois ; `read_logs()` lui délègue la lecture du fichier. Test d'ouverture à la demande et essai d'un million de lignes. |
| Plusieurs sources avec `yield from` | `read_multiple_logs()` enchaîne fichiers et entrée standard dans l'ordre donné. Test CLI mêlant fichier et flux. |
| Dictionnaires et types variés | `Log` est un `TypedDict` avec date `datetime`, niveau, IP, utilisateur, événement et payload texte/JSON. Tests des formats, champs incorrects et normalisation. |
| Métadonnées immuables | Connexion `(IP, port, protocole)` et provenance `(source, numéro)` sous forme de tuples. |
| `filter`, `lambda`, `map` | `process_logs()` filtre les commentaires et lignes vides, puis applique parsing et normalisation avec `map`. Les rejets sont filtrés avec `filter(None, ...)`. |
| `match-case` | `describe_payload()` distingue texte, dictionnaire d'erreur, dictionnaire général et tuple de connexion. |
| `set` et `frozenset` | IP actives et IP ayant émis ERROR/CRITICAL dans des ensembles ; blacklist immuable. |
| `\|`, `&`, `-`, `^` | Les quatre opérations apparaissent dans `Analyzer.summary()` et sont vérifiées sur des ensembles attendus. |
| `defaultdict` | Compteurs par niveau, utilisateur et règle sans initialisation manuelle des clés. |
| Force brute, `while`, `for`, `break`, `continue`, `else` | `detect_bruteforce()` examine des blocs d'échecs par couple IP/utilisateur. Un succès interrompt la boucle et supprime l'historique. Comparaison exhaustive de 256 séquences de huit tentatives pour cinq seuils. |
| `apply_security_rules(*args, **kwargs)` | Fonctions de règles passées dans `*args`, configuration dynamique dans `**kwargs`. Test avec une règle personnalisée et validation du seuil. |
| `globals()` et `locals()` | Audit des portées du pipeline et du module d'audit. Export des noms, types et tailles sans les valeurs sensibles. |
| PEP 8, typage et exceptions | Contrôle `pycodestyle` sans écart sur `main.py`, `src/` et `tests/`. Annotations sur le moteur et le benchmark ; erreurs de données contextualisées par source et ligne. |
| Démonstration et données fournies | `main.py` sans argument analyse `data/auth.log` puis `data/network.log`. 22 événements valides et 15 alertes. |
| Rapport synthétique | Notebook fourni avec sorties régénérées et comparaison automatisée de ces sorties depuis la racine et `report/`. |

## Inventaire des fichiers

| Fichier | Contrôle |
|---|---|
| `.gitignore` | Venv, caches, résultats et fichiers locaux exclus ; exemples `.log` explicitement conservés. |
| `README.md` | Installation, commandes, formats, résultats attendus, architecture et limites alignés sur le code. |
| `requirements.txt` | Installation réussie dans un venv neuf ; aucune dépendance tierce requise. |
| `main.py` | Options CLI, validations, pipeline complet, écriture temporaire des résultats et publication finale. |
| `src/__init__.py` | Package importable. |
| `src/ingestion.py` | Lecture paresseuse, flux, ordre des sources et blacklist validée. |
| `src/parser.py` | Dates, niveaux, IP, connexions, champs obligatoires et validité du JSON. |
| `src/processing.py` | Normalisation, routage des payloads, compteurs et modes strict/tolérant. |
| `src/analyzer.py` | Comptages, IP uniques et opérations ensemblistes. |
| `src/rules.py` | Trois règles, configuration variable et détection par identité. |
| `src/audit.py` | Export JSON des métadonnées des portées, sans leurs valeurs. |
| `data/auth.log` | Scénarios de force brute, succès intermédiaire et deux lignes volontairement invalides. |
| `data/network.log` | Formats texte/JSON, tuples réseau, événement critique et JSON volontairement tronqué. |
| `data/blacklist.txt` | Trois IP de documentation valides, chargées dans un `frozenset`. |
| `tests/__init__.py` | Package permettant l'exécution des tests et du benchmark comme modules. |
| `tests/test_engine.py` | 37 tests unitaires et d'intégration, sans bibliothèque tierce. |
| `tests/benchmark_memory.py` | Mesures reproductibles avec données générées progressivement et contrôle des résultats. |
| `report/rapport.ipynb` | Quatre cellules de démonstration réexécutées ; métadonnées et mesures actualisées. |
| `report/verification.md` | Présent compte rendu et correspondance avec le cahier des charges. |

## Résultats vérifiés

```text
Lignes lues : 28
Lignes ignorées : 3
Lignes rejetées : 3
Événements valides : 22
Niveaux : CRITICAL=1, ERROR=11, INFO=5, WARNING=5
Alertes : BLACKLIST=12, BRUTE_FORCE=2, CRITICAL=1
```

Les trois rejets sont intentionnels. Le mode normal termine avec le code 0 ;
`--strict` échoue avec le code 1 sans remplacer les résultats précédents.
Les erreurs d'arguments ont le code 2. Les alertes JSONL peuvent être émises
avant la fermeture du flux. Le résumé et l'audit sont publiés en fin d'analyse.

Deux défauts ont été corrigés pendant cette vérification : conservation
inutile d'un historique après un succès, et acceptation de nombres JSON non
finis ou de chaînes Unicode invalides dans certains champs. Les tests de
régression couvrent ces deux cas.

Les 37 tests passent sur les trois versions Python indiquées. Les cellules
du notebook sont exécutées par ces tests avec Python seul : ni Jupyter ni un
paquet global ne sont nécessaires. Un lecteur de notebooks peut afficher les
sorties sauvegardées sans exécuter de code.

### Mémoire

Mesures avec Python 3.12.16 et `tracemalloc`, après génération du fichier,
avec écriture effective des sorties. Une identité répétée, blacklist vide,
seuil de cinq échecs :

| Lignes | Fichier (octets) | Pic Python (octets) | Durée (s) | Alertes |
|---:|---:|---:|---:|---:|
| 10 000 | 590 000 | 65 715 | 0,503 | 2 000 |
| 100 000 | 5 900 000 | 65 252 | 4,707 | 20 000 |
| 1 000 000 | 59 000 000 | 65 477 | 48,676 | 200 000 |

Avec 10 000 identités toutes distinctes, le pic atteint 17 265 159 octets.
Ces chiffres mesurent les allocations Python suivies, pas la mémoire RSS.
Ils dépendent de la machine et de la diversité des données.

```bash
python -m unittest discover -s tests -v
python -m tests.benchmark_memory --lines 10000 100000 1000000
python -m tests.benchmark_memory --lines 10000 --distinct
```

## Limites conservées et explicites

- Les fichiers ne sont jamais chargés intégralement, mais une ligne est lue
  en entier. Les agrégats croissent avec les IP et utilisateurs distincts ;
  les historiques dépendent aussi du seuil de détection.
- La détection suit l'ordre des sources, sans tri global ni fenêtre temporelle.
  Elle produit une alerte par bloc disjoint de X échecs consécutifs.
- Un fichier qui grandit doit être transmis comme flux, par exemple via
  `tail -f`. Le moteur ne surveille pas lui-même le système de fichiers.
- Les fichiers de sortie sont remplacés individuellement. Une panne pendant
  leur publication n'offre pas une transaction atomique sur les trois fichiers.
  Les analyses simultanées doivent avoir des dossiers de sortie distincts.
- Les tests ont été exécutés sur macOS ; l'exécution native sous Windows
  n'a pas été vérifiée lors de ce contrôle.
