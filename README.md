# TP3 DevSecOps : sécurité des conteneurs et monitoring au runtime

Application : **VulnBank** (Flask), reprise des TP1/TP2. Le compte rendu est dans [RAPPORT.md](RAPPORT.md) (PDF : `RAPPORT.pdf`).

| Dossier | Contenu |
|---|---|
| `before/Dockerfile` | image d'origine (TP2), scannée pour le « avant » |
| `Dockerfile`, `.dockerignore` | image durcie |
| `vulnbank/` | application ; `secrets_loader.py` = lecture des secrets |
| `k8s/` | manifestes Kubernetes, config kind (chiffrement etcd), valeurs Helm Falco + règles |
| `scripts/` | création du Secret, démos secrets et Falco, génération PDF |
| `evidence/` | sorties réelles (Trivy, démos) citées dans le rapport |

Commandes complètes : annexe du rapport. Tests : `pip install -r requirements.txt pytest && pytest`.
