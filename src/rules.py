"""Règles indépendantes passées comme objets au moteur de sécurité."""

from collections import deque
from collections.abc import Callable, Iterator
from typing import Any

from .parser import Log

Alert = dict[str, Any]
Rule = Callable[..., Alert | None]
History = dict[tuple[str, str], deque[bool]]


def make_alert(log: Log, rule: str, message: str) -> Alert:
    """Conserver la provenance exacte de l'événement déclencheur."""
    return {
        "rule": rule,
        "timestamp": log["timestamp"].isoformat(sep=" "),
        "ip": log["ip"],
        "user": log["user"],
        "source": log["source"],
        "message": message,
    }


def detect_bruteforce(log: Log, **config: Any) -> Alert | None:
    """Détecter un bloc de X échecs consécutifs pour (IP, utilisateur).

    Une fenêtre ne contient que X booléens au maximum. Les événements
    réseau ne modifient pas les séries d'authentification. L'ordre utilisé
    est celui des fichiers fournis, sans tri global en mémoire.
    """
    if log["event"] not in {"LOGIN_FAILED", "LOGIN_SUCCESS"}:
        return None
    threshold = config["threshold"]
    histories: History = config["histories"]
    identity = (log["ip"], log["user"])
    if identity not in histories:
        histories[identity] = deque(maxlen=threshold)
    history = histories[identity]
    history.append(log["event"] == "LOGIN_FAILED")

    # Retirer les succès en tête de fenêtre, devenus inutiles.
    while history and not history[0]:
        history.popleft()

    # Vérifier le cycle complet. Un succès intérieur interrompt le cycle.
    for failed in history:
        if failed:
            continue
        break
    else:
        # Exécuté seulement si aucun break : tous les essais sont en échec.
        if len(history) == threshold:
            del histories[identity]
            return make_alert(
                log, "BRUTE_FORCE", f"{threshold} échecs consécutifs"
            )
    if not history:
        histories.pop(identity, None)
    return None


def detect_blacklisted_ip(log: Log, **config: Any) -> Alert | None:
    """Signaler chaque événement issu d'une adresse blacklistée."""
    if log["ip"] in config["blacklist"]:
        return make_alert(log, "BLACKLIST", "IP présente dans la blacklist")
    return None


def detect_critical_event(log: Log, **config: Any) -> Alert | None:
    """Signaler chaque événement de gravité maximale."""
    if log["level"] == "CRITICAL":
        return make_alert(log, "CRITICAL", log["message"])
    return None


def apply_security_rules(*args: Rule, **kwargs: Any) -> Iterator[Alert]:
    """Recevoir N fonctions et leur transmettre une configuration nommée."""
    log = kwargs.pop("log")
    threshold = kwargs.get("threshold", 5)
    if type(threshold) is not int or threshold < 1:
        raise ValueError("le seuil doit être un entier strictement positif")
    kwargs["threshold"] = threshold
    for rule in args:
        if not callable(rule):
            raise TypeError("chaque règle doit être une fonction")
        alert = rule(log, **kwargs)
        if alert is not None:
            yield alert
