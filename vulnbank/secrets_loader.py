"""Lecture des secrets de l'application (TP3).

Ordre de recherche d'un secret `nom` :
  1. le fichier  $SECRETS_DIR/nom   (volume Kubernetes Secret monte en lecture
     seule, sur un tmpfs : le secret n'est jamais ecrit sur le disque du noeud) ;
  2. la variable d'environnement  NOM  (pratique en developpement local).

Pourquoi preferer le fichier a la variable d'environnement ?
  - une variable d'environnement est visible dans `kubectl describe pod`,
    dans /proc/<pid>/environ, et elle est heritee par tous les processus fils ;
  - un fichier monte peut etre restreint (mode 0400) et Kubernetes le met a
    jour automatiquement en cas de rotation du Secret.

Si REQUIRE_SECRETS=1 (cas de la production), un secret absent fait echouer le
demarrage : on prefere un pod en CrashLoopBackOff, visible tout de suite, a une
application qui tourne avec une cle generee au hasard (sessions invalidees a
chaque redemarrage, valeur differente sur chaque replica).
"""

import os

DEFAULT_SECRETS_DIR = "/run/secrets/vulnbank"


class MissingSecretError(RuntimeError):
    pass


def read_secret(name, required=None):
    """Retourne (valeur, source) ou (None, None) si le secret est absent."""
    secrets_dir = os.environ.get("SECRETS_DIR", DEFAULT_SECRETS_DIR)
    path = os.path.join(secrets_dir, name)
    if os.path.isfile(path):
        with open(path) as handle:
            value = handle.read().strip()
        if value:
            return value, "file"

    value = os.environ.get(name.upper())
    if value:
        return value, "env"

    if required is None:
        required = os.environ.get("REQUIRE_SECRETS", "0") == "1"
    if required:
        # Le message ne contient que le NOM du secret, jamais une valeur.
        raise MissingSecretError(f"secret manquant : {name}")
    return None, None
