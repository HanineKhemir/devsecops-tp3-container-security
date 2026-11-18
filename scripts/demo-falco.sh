#!/usr/bin/env bash
# Demonstration TP3 - partie 3 : detection d'intrusion au runtime avec Falco.
# Scenario : un attaquant (ou un operateur indelicat) ouvre un shell INTERACTIF
# dans le conteneur de production, puis tente de voler les secrets et de
# deposer une porte derobee.
set -uo pipefail
NS=vulnbank
POD=$(kubectl -n $NS get pod -l app=vulnbank -o jsonpath='{.items[0].metadata.name}')
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '=== Cible : pod %s (namespace %s)\n' "$POD" "$NS"

printf '\n=== 1. Attaque : kubectl exec -it ... -- sh  (TTY alloue)\n'
# `script` fournit un pseudo-terminal : c'est exactement ce que fait
# `kubectl exec -it` lance depuis un vrai terminal.
{ sleep 2
  echo 'id'
  echo 'ls -l /run/secrets/vulnbank/'
  echo 'wc -c /run/secrets/vulnbank/admin_password'
  echo 'touch /app/vulnbank/backdoor.py'
  echo 'apk add curl'
  sleep 2; echo 'exit'
} | script -q /dev/null kubectl -n $NS exec -it "$POD" -- sh 2>&1 | LC_ALL=C tr -d '\r' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g'

sleep 5
printf '\n=== 2. Alertes Falco pour ce pod (depuis %s)\n' "$START"
kubectl -n falco logs ds/falco -c falco --since-time="$START" | grep -F "$POD" \
  | sed -E 's/ aname\[[0-9]\]=<NA>//g'
