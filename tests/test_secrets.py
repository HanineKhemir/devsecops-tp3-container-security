"""Tests TP3 : gestion des secrets (fichier monte > variable > echec)."""

import pytest

from vulnbank import secrets_loader
from vulnbank.secrets_loader import MissingSecretError, read_secret


def test_secret_lu_depuis_le_fichier_monte(tmp_path, monkeypatch):
    (tmp_path / "secret_key").write_text("valeur-fichier\n")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "valeur-env")
    assert read_secret("secret_key") == ("valeur-fichier", "file")


def test_repli_sur_la_variable_d_environnement(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "valeur-env")
    assert read_secret("secret_key") == ("valeur-env", "env")


def test_secret_obligatoire_absent_bloque_le_demarrage(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("REQUIRE_SECRETS", "1")
    with pytest.raises(MissingSecretError) as erreur:
        read_secret("admin_password")
    assert "admin_password" in str(erreur.value)


def test_admin_admin_ne_fonctionne_plus(tmp_path, monkeypatch):
    """Le compte admin/admin du TP2 n'existe plus : le mot de passe vient du secret."""
    from vulnbank import app as app_module
    from vulnbank import db as db_module

    (tmp_path / "admin_password").write_text("S3cret-De-Test")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "bank.db"))
    db_module.init_db()
    app_module.app.config.update(TESTING=True)
    client = app_module.app.test_client()
    assert client.post("/login", data={"username": "admin", "password": "admin"}).status_code == 401
    assert client.post("/login", data={"username": "admin", "password": "S3cret-De-Test"}).status_code == 302
    sante = client.get("/healthz").get_json()
    assert sante["secrets"]["admin_password"] == "file"
    assert "S3cret" not in str(sante)
