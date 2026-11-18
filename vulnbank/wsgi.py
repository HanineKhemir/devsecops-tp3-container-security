"""Point d'entree WSGI de production (TP3).

Le serveur de developpement Flask (app.run) n'est pas fait pour la production.
Gunicorn charge ce module une seule fois (option --preload) : la base est donc
initialisee une fois, avant le demarrage des workers.
"""

from vulnbank.app import app
from vulnbank.db import init_db

init_db()

__all__ = ["app"]
