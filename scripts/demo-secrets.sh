#!/usr/bin/env bash
# Demonstration TP3 - partie 2 : gestion des secrets.
# Les valeurs des secrets ne sont JAMAIS affichees : on prouve leur usage par
# leur effet (connexion admin, session qui survit au redemarrage du pod).
set -uo pipefail
NS=vulnbank; PORT=18080; JAR="$(mktemp)"; trap 'rm -f "$JAR"; kill $PF 2>/dev/null' EXIT
title() { printf '\n=== %s\n' "$*"; }
pf() { kubectl -n $NS port-forward svc/vulnbank $PORT:80 >/dev/null 2>&1 & PF=$!; sleep 3; }

title "1. Le Secret existe : on voit les CLES et la taille, jamais les valeurs"
kubectl -n $NS describe secret vulnbank-secrets | sed -n '/^Data/,$p'

title "2. Dans etcd, le Secret est CHIFFRE (prefixe k8s:enc:aescbc), pas du simple base64"
ETCD=$(kubectl -n kube-system get pod -l component=etcd -o name | head -1)
RAW="$(mktemp)"
kubectl -n kube-system exec "$ETCD" -- etcdctl \
  --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key get /registry/secrets/vulnbank/vulnbank-secrets > "$RAW" \
  || { echo "ERREUR : lecture etcd impossible"; exit 1; }
echo "taille brute lue dans etcd : $(wc -c < "$RAW") octets"
head -c 110 "$RAW" | LC_ALL=C tr -c '[:print:]' '.'; echo
ADMIN_PW="$(kubectl -n $NS get secret vulnbank-secrets -o jsonpath='{.data.admin_password}' | base64 -d)"
ADMIN_B64="$(kubectl -n $NS get secret vulnbank-secrets -o jsonpath='{.data.admin_password}')"
printf 'mot de passe admin en clair dans etcd   : %s occurrence(s)\n' "$(LC_ALL=C grep -a -c -F -f <(printf '%s' "$ADMIN_PW") "$RAW")"
printf 'mot de passe admin en base64 dans etcd  : %s occurrence(s)\n' "$(LC_ALL=C grep -a -c -F -f <(printf '%s' "$ADMIN_B64") "$RAW")"
rm -f "$RAW"; unset ADMIN_B64

title "3. Aucun secret en variable d'environnement dans la spec du pod"
kubectl -n $NS get deploy vulnbank -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}'

title "4. Le compte de service du pod ne peut PAS lire les Secrets via l'API"
kubectl auth can-i get secrets -n $NS --as=system:serviceaccount:$NS:vulnbank

title "5. /healthz : l'application a charge ses secrets depuis le volume monte (source=file)"
pf; curl -s localhost:$PORT/healthz; echo

title "6. Connexion admin : l'ancien mot de passe 'admin' est refuse, celui du Secret est accepte"
printf 'admin/admin            -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -d username=admin -d password=admin localhost:$PORT/login)"
printf 'admin/<mot de passe du Secret> -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" --data-urlencode username=admin --data-urlencode "password=$ADMIN_PW" localhost:$PORT/login)"
unset ADMIN_PW

title "7. SECRET_KEY partagee : la session survit a la suppression du pod"
OLD=$(kubectl -n $NS get pod -l app=vulnbank -o name); echo "pod actuel : $OLD"
curl -s -b "$JAR" localhost:$PORT/ | grep -o 'Connecte en tant que <strong>[^<]*' | sed 's/<strong>//' || echo '(non connecte)'
kill $PF; kubectl -n $NS delete $OLD --wait=true >/dev/null
kubectl -n $NS rollout status deploy/vulnbank --timeout=120s >/dev/null
kubectl -n $NS wait --for=condition=Ready pod -l app=vulnbank --timeout=120s >/dev/null
echo "nouveau pod : $(kubectl -n $NS get pod -l app=vulnbank -o name)"
pf; echo "meme cookie, nouveau pod :"; curl -s -b "$JAR" localhost:$PORT/ | grep -o 'Connecte en tant que <strong>[^<]*' | sed 's/<strong>//' || echo '(non connecte)'
