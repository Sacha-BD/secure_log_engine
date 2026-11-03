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

