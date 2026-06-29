#!/usr/bin/env python3
"""Générateur de rapport de pentest avec CVSS + ATT&CK."""
import json, argparse
from datetime import datetime

T = """# Rapport de Test d'Intrusion
**Date :** {date} | **Risque :** {risk}

## Résumé
| Criticité | Nombre |
|---|---|
| Critique | {c} |
| Élevée | {h} |
| Modérée | {m} |
| Faible | {l} |

## Vulnérabilités
{findings}
## Recommandations
{recos}
"""

def gen(data, out):
    sev = {"CRITIQUE":0,"ELEVEE":0,"MODEREE":0,"FAIBLE":0}
    f = ""
    for i, v in enumerate(data["findings"], 1):
        sev[v["severity"]] += 1
        f += f"""
### VULN-{i:03d} — {v['title']}
- Criticité : {v['severity']} | CVSS : {v.get('cvss','N/A')}
- ATT&CK : {v.get('attack','N/A')}
- {v.get('desc','')}
- Remédiation : {v.get('fix','')}
"""
    risk = "CRITIQUE" if sev["CRITIQUE"]>0 else "ÉLEVÉ" if sev["ELEVEE"]>0 else "MODÉRÉ"
    with open(out,"w") as fh: fh.write(T.format(
        date=datetime.now().strftime("%Y-%m-%d"), risk=risk,
        c=sev["CRITIQUE"], h=sev["ELEVEE"], m=sev["MODEREE"], l=sev["FAIBLE"],
        findings=f,
        recos="\n".join(f"- {r}" for r in data.get("recos",[]))))
    print(f"Rapport généré : {out}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="rapport_final.md")
    a = p.parse_args()
    with open(a.input) as fh: gen(json.load(fh), a.output)
