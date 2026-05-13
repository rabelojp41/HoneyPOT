"""
report.py — gera um relatório de texto/markdown com IoCs e estatísticas.

Uso:
    python report.py                        # salva report.md no diretório atual
    python report.py --logs /path/logs --out report.md
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from parser import CowrieParser


def build_report(parser: CowrieParser) -> str:
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    iocs  = parser.iocs()
    conns = parser.connections
    cmds  = parser.top_commands(20)
    creds = parser.top_credentials(20)
    dls   = parser.downloads

    # Período dos dados
    period = "—"
    if not conns.empty and "timestamp" in conns.columns:
        t_min = conns["timestamp"].min().strftime("%Y-%m-%d %H:%M UTC")
        t_max = conns["timestamp"].max().strftime("%Y-%m-%d %H:%M UTC")
        period = f"{t_min} → {t_max}"

    lines = [
        "# Relatório de Análise — Cowrie Honeypot",
        "",
        f"> Gerado em: {now}",
        f"> Período dos dados: {period}",
        "",
        "---",
        "",
        "## Resumo Executivo",
        "",
        f"| Métrica | Valor |",
        f"|---|---|",
        f"| IPs únicos | {parser.unique_ips()} |",
        f"| Total de conexões | {len(conns)} |",
        f"| Logins falhos | {len(parser.logins_failed)} |",
        f"| Logins bem-sucedidos | {len(parser.logins_success)} |",
        f"| Comandos executados | {len(parser.commands)} |",
        f"| Downloads de malware | {len(dls)} |",
        "",
        "---",
        "",
        "## Top 20 IPs Atacantes (IoC)",
        "",
        "| # | IP | Conexões |",
        "|---|---|---|",
    ]

    top_ips = parser.top_ips(20)
    for i, (ip, count) in enumerate(top_ips.items(), 1):
        lines.append(f"| {i} | `{ip}` | {count} |")

    lines += [
        "",
        "---",
        "",
        "## Top 20 Credenciais Tentadas",
        "",
    ]

    if not creds.empty:
        has_user = "username" in creds.columns
        has_pass = "password" in creds.columns

        if has_user and has_pass:
            lines.append("| # | Usuário | Senha | Tentativas |")
            lines.append("|---|---|---|---|")
            for i, row in enumerate(creds.itertuples(), 1):
                lines.append(f"| {i} | `{row.username}` | `{row.password}` | {row.count} |")
        else:
            lines.append("| # | Credencial | Tentativas |")
            lines.append("|---|---|---|")
            for i, row in enumerate(creds.itertuples(), 1):
                val = row.username if has_user else row.password
                lines.append(f"| {i} | `{val}` | {row.count} |")

    lines += [
        "",
        "---",
        "",
        "## Top 20 Comandos Executados",
        "",
        "| # | Comando | Ocorrências |",
        "|---|---|---|",
    ]

    for i, (cmd, count) in enumerate(cmds.items(), 1):
        safe = str(cmd).replace("|", "\\|")
        lines.append(f"| {i} | `{safe}` | {count} |")

    # Downloads / malware
    lines += [
        "",
        "---",
        "",
        "## Malware / Downloads",
        "",
    ]

    if dls.empty:
        lines.append("_Nenhum download registrado._")
    else:
        if "url" in dls.columns:
            lines.append("### URLs")
            lines.append("")
            for url in dls["url"].dropna().unique():
                lines.append(f"- `{url}`")
            lines.append("")

        if "shasum" in dls.columns:
            lines.append("### Hashes SHA256")
            lines.append("")
            for h in dls["shasum"].dropna().unique():
                lines.append(f"- `{h}`")

    # IoCs em JSON bruto
    lines += [
        "",
        "---",
        "",
        "## IoCs (JSON)",
        "",
        "```json",
        json.dumps(iocs, indent=2, ensure_ascii=False),
        "```",
        "",
    ]

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Gera relatório markdown do honeypot")
    ap.add_argument("--logs", default="../logs", help="Diretório dos logs JSON")
    ap.add_argument("--out",  default="report.md", help="Arquivo de saída")
    args = ap.parse_args()

    print("Carregando logs...")
    p = CowrieParser(args.logs).load()
    print(p.summary())

    print("\nGerando relatório...")
    content = build_report(p)

    out = Path(args.out)
    out.write_text(content, encoding="utf-8")
    print(f"Relatório salvo em: {out.resolve()}")


if __name__ == "__main__":
    main()
