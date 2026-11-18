#!/usr/bin/env bash
# Capture les sorties REELLES des commandes du TP dans docs/screenshots/src/*.txt
# (rendues ensuite en images par scripts/render_terminals.py).
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=docs/screenshots/src; mkdir -p "$OUT"
run() { printf '$ %s\n' "$*"; eval "$@" 2>&1; echo; }

{ printf '$ trivy image --scanners vuln,secret vulnbank:1.0-before\n'
  grep -A2 '^vulnbank:1.0-before (debian' evidence/trivy-before.txt
  echo '[... 226 lignes de vulnerabilites Debian omises ...]'; echo
  sed -n '974,990p' evidence/trivy-before.txt
  echo '[...]'; echo
  run "trivy config --quiet before/Dockerfile | grep -E 'Tests:|Failures:|DS-0002'"
} > $OUT/01-trivy-before.txt

{ run "trivy image --quiet --scanners vuln,secret vulnbank:2.0-hardened | head -9"
  run "trivy image --quiet --format json vulnbank:2.0-hardened | jq '[.Results[].Vulnerabilities // [] | length] | add'"
  run "trivy config --quiet Dockerfile | head -7"
} > $OUT/02-trivy-after.txt

{ run "docker image ls vulnbank --format 'table {{.Repository}}:{{.Tag}}\t{{.Size}}'"
  run "docker run --rm vulnbank:1.0-before id"
  run "docker run --rm vulnbank:2.0-hardened id"
  run "docker run --rm vulnbank:2.0-hardened sh -c 'command -v pip apk || echo \"pip et apk : absents\"'"
  run "docker run --rm -e REQUIRE_SECRETS=1 --read-only --tmpfs /tmp --tmpfs /data:uid=10001 vulnbank:2.0-hardened | grep Error"
} > $OUT/03-docker-hardening.txt

{ run "kubectl get ns vulnbank --show-labels"
  run "kubectl -n vulnbank get deploy,pod,svc,secret,networkpolicy"
  run "kubectl -n falco get daemonset,pod"
} > $OUT/04-kubernetes.txt

{ printf '$ ./scripts/demo-secrets.sh\n'; grep -v '^$' evidence/demo-secrets.txt; } > $OUT/05-secrets-demo.txt

{ printf '$ kubectl -n vulnbank run oldimage --image=vulnbank:1.0-before --dry-run=server\n'
  cat evidence/psa-reject-root.txt; echo
  cat evidence/root-image-blocked.txt
} > $OUT/06-psa-blocked.txt

{ printf '$ kubectl -n vulnbank exec -it %s -- sh\n' "$(sed -n 's/.*pod \([^ ]*\) .*/\1/p' evidence/demo-falco.txt | head -1)"
  sed -n '/^=== 1/,/^=== 2/p' evidence/demo-falco.txt | sed '1d;$d' | grep -v '^$'
} > $OUT/07-falco-attack.txt

{ printf '$ kubectl -n falco logs ds/falco -c falco | grep vulnbank\n'
  sed -n '/^=== 2/,$p' evidence/demo-falco.txt | sed '1d' \
    | sed -E 's/ container_id=.*$//; s/ \| evt_type=execve user=<NA>/ |/; s/ user_loginuid=-1//; s/ exe_flags=[A-Z_|]+//'
} > $OUT/08-falco-alerts.txt

{ run ".venv/bin/pytest -q -p no:cacheprovider | tail -4"
  run ".venv/bin/bandit -q -r vulnbank && echo 'Bandit : aucun probleme'"
} > $OUT/09-tests.txt
echo "captures dans $OUT"; ls $OUT
