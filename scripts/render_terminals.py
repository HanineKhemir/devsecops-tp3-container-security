#!/usr/bin/env python3
"""Rend les sorties de commandes capturees (docs/screenshots/src/*.txt) en
images PNG au style « fenetre de terminal » (Chrome headless + recadrage Pillow).

Le TEXTE n'est pas modifie : seule la mise en forme (couleurs) est ajoutee.
Usage : python scripts/render_terminals.py
"""

import html
import pathlib
import re
import subprocess
import tempfile

from PIL import Image, ImageChops

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs/screenshots/src"
DST = ROOT / "docs/screenshots"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

TITLES = {
    "01-trivy-before": "trivy — image d'origine vulnbank:1.0-before",
    "02-trivy-after": "trivy — image durcie vulnbank:2.0-hardened",
    "03-docker-hardening": "docker — avant / apres durcissement",
    "04-kubernetes": "kubectl — cluster kind-tp3",
    "05-secrets-demo": "demo-secrets.sh — gestion des secrets",
    "06-psa-blocked": "kubectl — Pod Security Admission",
    "07-falco-attack": "attaquant — shell interactif dans le pod de production",
    "08-falco-alerts": "falco — alertes en temps reel",
    "09-tests": "pytest + bandit",
}

RULES = [  # (regex, classe CSS) appliques ligne par ligne
    (r"^\$ .*", "cmd"),
    (r"^/app \$ .*", "cmd"),
    (r"^=== .*", "sec"),
    (r"^\[\.\.\..*\]$", "dim"),
]
WORDS = [
    (r"\bCRITICAL\b|\bCritical\b|Forbidden|forbidden|Read-only file system|not found|"
     r"Error:?|\bFailed\b|uid=0\(root\)|HTTP 401|HIGH: [1-9]\d*|\(HIGH\)|\bHIGH\b", "bad"),
    (r"\bWarning\b|\bMEDIUM\b|CreateContainerConfigError", "warn"),
    (r"\bNotice\b|k8s:enc:aescbc:v1:key1", "info"),
    (r"\b0 occurrence\(s\)|uid=10001\(app\)|HTTP 302|\bRunning\b|18 passed|aucun probleme|"
     r"absents|enforce=restricted|\"file\"|Connecte en tant que admin|\bno$", "good"),
]

CSS = """
body{margin:0;padding:28px;background:#fff;font-family:-apple-system,Helvetica,Arial,sans-serif}
.win{display:inline-block;max-width:__MAXW__px;border-radius:10px;overflow:hidden;
     box-shadow:0 8px 24px rgba(0,0,0,.28);background:#1e1f24}
.bar{background:#38393f;height:30px;display:flex;align-items:center;padding:0 12px;position:relative}
.dot{width:12px;height:12px;border-radius:50%;margin-right:8px}
.t{position:absolute;left:0;right:0;text-align:center;color:#c9c9cf;font-size:13px}
pre{margin:0;padding:14px 18px 16px;color:#dcdfe4;font:13px/1.45 Menlo,"SF Mono",monospace;
    white-space:pre-wrap;word-break:break-all}
.cmd{color:#7ee787;font-weight:bold}.sec{color:#79c0ff;font-weight:bold}.dim{color:#7d8590;font-style:italic}
.bad{color:#ff7b72;font-weight:bold}.warn{color:#e3b341}.info{color:#56d4dd}.good{color:#56d364;font-weight:bold}
"""


def colorize(line):
    for pattern, cls in RULES:
        if re.match(pattern, line):
            return f'<span class="{cls}">{html.escape(line)}</span>'
    out, pos = [], 0
    combined = "|".join(f"(?P<{c}{i}>{p})" for i, (p, c) in enumerate(WORDS))
    for m in re.finditer(combined, line):
        cls = re.sub(r"\d+$", "", m.lastgroup)
        out.append(html.escape(line[pos:m.start()]))
        out.append(f'<span class="{cls}">{html.escape(m.group())}</span>')
        pos = m.end()
    out.append(html.escape(line[pos:]))
    return "".join(out)


def render(txt):
    name = txt.stem
    lines = txt.read_text().rstrip("\n").split("\n")
    body = "\n".join(colorize(l) for l in lines)
    # Largeur adaptee a la plus longue ligne (max 170 colonnes, au-dela : retour a la ligne)
    cols = min(max(len(l) for l in lines), 170)
    win_w = int(cols * 7.83) + 40
    css = CSS.replace("__MAXW__", str(win_w))
    page = (f"<!doctype html><meta charset=utf-8><style>{css}</style><div class=win><div class=bar>"
            '<span class=dot style="background:#ff5f57"></span><span class=dot style="background:#febc2e">'
            '</span><span class=dot style="background:#28c840"></span>'
            f"<span class=t>{html.escape(TITLES.get(name, name))}</span></div><pre>{body}</pre></div>")
    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / "p.html"; src.write_text(page)
        shot = pathlib.Path(tmp) / "s.png"
        subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                        "--force-device-scale-factor=2", f"--window-size={win_w + 60},2400",
                        f"--screenshot={shot}", src.as_uri()],
                       check=True, capture_output=True)
        img = Image.open(shot).convert("RGB")
        bg = Image.new("RGB", img.size, (255, 255, 255))
        box = ImageChops.difference(img, bg).getbbox()
        m = 24
        img = img.crop((max(box[0]-m, 0), max(box[1]-m, 0),
                        min(box[2]+m, img.width), min(box[3]+m, img.height)))
        out = DST / f"{name}.png"; img.save(out, optimize=True)
        print(out.relative_to(ROOT), img.size)


if __name__ == "__main__":
    for txt in sorted(SRC.glob("*.txt")):
        render(txt)
