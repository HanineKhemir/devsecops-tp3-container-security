#!/usr/bin/env bash
# Genere la cle de chiffrement etcd (32 octets aleatoires) - JAMAIS commitee.
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)/k8s/cluster/encryption"
mkdir -p "$dir"
[ -f "$dir/encryption-config.yaml" ] && { echo "existe deja : $dir/encryption-config.yaml"; exit 0; }
umask 022  # lisible par kube-apiserver dans le noeud kind (le dossier reste hors Git)
cat > "$dir/encryption-config.yaml" <<YAML
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: $(head -c 32 /dev/urandom | base64)
      - identity: {}
YAML
echo "cle generee : $dir/encryption-config.yaml"
