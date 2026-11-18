#!/usr/bin/env bash
# Cree (ou remplace) le Secret Kubernetes de VulnBank a partir de valeurs
# aleatoires. Les valeurs ne transitent ni par Git, ni par l'historique du
# shell, ni par la ligne de commande (visible dans `ps`) : elles sont ecrites
# dans un dossier temporaire en mode 0600, puis passees en --from-file.
# Usage : RATES_API_KEY=xxxx ./scripts/create-secret.sh   (cle API optionnelle)
set -euo pipefail
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
umask 077
openssl rand -hex 32                 > "$tmp/secret_key"
openssl rand -base64 18 | tr -d '\n' > "$tmp/admin_password"
printf '%s' "${RATES_API_KEY:-demo-$(openssl rand -hex 8)}" > "$tmp/rates_api_key"

kubectl -n vulnbank create secret generic vulnbank-secrets \
  --from-file=secret_key="$tmp/secret_key" \
  --from-file=admin_password="$tmp/admin_password" \
  --from-file=rates_api_key="$tmp/rates_api_key" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "Secret vulnbank/vulnbank-secrets cree (valeurs non affichees)."
