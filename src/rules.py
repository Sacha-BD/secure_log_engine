"""Règles utilisées pour détecter des événements suspects."""

from collections import deque
from collections.abc import Callable, Iterator
from typing import Any

from .parser import Log

Alert = dict[str, Any]
Rule = Callable[..., Alert | None]
History = dict[tuple[str, str], deque[bool]]


def make_alert(log: Log, rule: str, message: str) -> Alert:
    """Créer le dictionnaire d'une alerte."""
    return {
        "rule": rule,
        "timestamp": log["timestamp"].isoformat(sep=" "),
        "ip": log["ip"],
        "user": log["user"],
        "source": log["source"],
        "message": message,
    }


def detect_bruteforce(log: Log, **config: Any) -> Alert | None:
    """Détecter X échecs consécutifs pour une IP et un utilisateur."""
    if log["event"] not in {"LOGIN_FAILED", "LOGIN_SUCCESS"}:
        return None
    threshold = config["threshold"]
    histories: History = config["histories"]
    identity = (log["ip"], log["user"])
    if identity not in histories:
        histories[identity] = deque(maxlen=threshold)
    history = histories[identity]
    history.append(log["event"] == "LOGIN_FAILED")

    # Une réussite remet la série d'échecs à zéro.
    while history and not history[0]:
        history.popleft()

    # La boucle doit aller jusqu'au bout pour confirmer la série d'échecs.
    for failed in history:
        if failed:
            continue
        break
    else:
        # Ce else est exécuté seulement si aucun break n'a été rencontré.
        if len(history) == threshold:
            del histories[identity]
            return make_alert(
                log, "BRUTE_FORCE", f"{threshold} échecs consécutifs"
            )
    if not history:
        histories.pop(identity, None)
    return None


def detect_blacklisted_ip(log: Log, **config: Any) -> Alert | None:
    """Signaler un événement provenant d'une IP blacklistée."""
    if log["ip"] in config["blacklist"]:
        return make_alert(log, "BLACKLIST", "IP présente dans la blacklist")
    return None


def detect_critical_event(log: Log, **config: Any) -> Alert | None:
    """Signaler un événement de niveau CRITICAL."""
    if log["level"] == "CRITICAL":
        return make_alert(log, "CRITICAL", log["message"])
    return None


def apply_security_rules(*args: Rule, **kwargs: Any) -> Iterator[Alert]:
    """Appliquer toutes les fonctions reçues dans args."""
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
