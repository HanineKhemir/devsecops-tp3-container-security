# syntax=docker/dockerfile:1
# =============================================================================
# TP3 - Dockerfile durci de VulnBank
# Ancienne version : before/Dockerfile (python:3.11-slim, root, serveur de dev)
# =============================================================================

# Image de base EPINGLEE PAR DIGEST : le build est reproductible et une image
# "python:3.13-alpine" modifiee en amont ne peut pas s'inviter dans la prod.
ARG PYTHON_IMAGE=python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e

# -----------------------------------------------------------------------------
# Etape 1 : "builder" - installe les dependances dans un environnement virtuel.
# Les outils d'installation (pip, setuptools, wheel, cache) restent ICI et ne
# sont jamais copies dans l'image finale.
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 # pip/setuptools/wheel ne servent qu'a installer : on les retire du venv.
 && /opt/venv/bin/pip uninstall -y pip setuptools wheel

# -----------------------------------------------------------------------------
# Etape 2 : image d'execution minimale
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="vulnbank" \
      org.opencontainers.image.description="VulnBank - image durcie (TP3 DevSecOps)"

# 1) Mises a jour de securite des paquets Alpine presents dans la base.
# 2) Suppression de pip de l'interpreteur systeme (inutile a l'execution,
#    et porteur de CVE) et de l'outil apk (plus aucun paquet installable
#    depuis le conteneur).
# 3) Utilisateur dedie SANS shell de connexion, UID/GID numeriques fixes
#    (10001) : Kubernetes peut verifier runAsNonRoot sans resoudre le nom.
RUN apk upgrade --no-cache \
 && python -m pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3.13/ensurepip /root/.cache \
 && addgroup -g 10001 -S app \
 && adduser -u 10001 -S -G app -H -h /nonexistent -s /sbin/nologin app \
 && mkdir -p /data \
 && chown 10001:10001 /data \
 && apk --purge del apk-tools

COPY --from=builder /opt/venv /opt/venv
# Le code appartient a root et est en lecture seule pour l'utilisateur app :
# un attaquant qui prend la main sur le processus ne peut pas le modifier.
COPY --chown=root:root --chmod=0755 vulnbank/ /app/vulnbank/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULNBANK_DB_PATH=/data/bank.db \
    SECRETS_DIR=/run/secrets/vulnbank

WORKDIR /app
USER 10001:10001

# Port non privilegie (> 1024) : aucune capacite NET_BIND_SERVICE necessaire.
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"

# Gunicorn (serveur WSGI de production) au lieu de app.run() ; forme "exec"
# (JSON) : gunicorn est le PID 1 et recoit directement SIGTERM.
# --no-control-socket : pas de socket d administration (surface reduite, et
# rien a ecrire hors de /tmp sur un systeme de fichiers en lecture seule).
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--preload", \
     "--worker-tmp-dir", "/tmp", "--no-control-socket", "--access-logfile", "-", "vulnbank.wsgi:app"]
