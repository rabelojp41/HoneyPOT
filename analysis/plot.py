"""
plot.py — gera todos os gráficos de análise do honeypot.

Estética: dark/cyberpunk com roxo e lilás.

Uso:
    python plot.py              # lê ../logs, salva PNGs em ./output/
    python plot.py --logs /caminho/logs --out ./plots
"""

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import pandas as pd

from parser import CowrieParser

# ──────────────────────────────────────────────────────────
# Paleta cyberpunk
# ──────────────────────────────────────────────────────────
BG       = "#0d0d1a"   # fundo principal
BG2      = "#12122a"   # fundo de painel
PURPLE   = "#9b59b6"   # destaque principal
LILAC    = "#c39bd3"   # destaque secundário
ACCENT   = "#7d3c98"   # barras escuras
TEXT     = "#e8d5f5"   # texto
GRID     = "#2a1a3a"   # linhas de grade
DANGER   = "#e74c3c"   # alerta (downloads)

PALETTE  = [PURPLE, LILAC, "#d2b4de", "#a569bd", ACCENT, "#6c3483",
            "#bb8fce", "#8e44ad", "#d7bde2", "#5b2c6f"]


def _apply_theme(fig: plt.Figure, ax: plt.Axes) -> None:
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG2)
    ax.tick_params(colors=TEXT, labelsize=9)
    ax.xaxis.label.set_color(TEXT)
    ax.yaxis.label.set_color(TEXT)
    ax.title.set_color(LILAC)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID)
    ax.grid(color=GRID, linestyle="--", linewidth=0.5, alpha=0.7)


def _save(fig: plt.Figure, path: Path, name: str) -> None:
    out = path / name
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"  → {out}")


# ──────────────────────────────────────────────────────────
# Gráficos
# ──────────────────────────────────────────────────────────

def plot_top_ips(parser: CowrieParser, out: Path) -> None:
    data = parser.top_ips(15)
    if data.empty:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(data.index[::-1], data.values[::-1], color=PURPLE, edgecolor=ACCENT)

    # Gradiente manual de cor
    for i, bar in enumerate(bars):
        bar.set_alpha(0.6 + 0.4 * (i / len(bars)))

    ax.set_xlabel("Número de conexões", color=TEXT)
    ax.set_title("Top 15 IPs Atacantes", fontsize=14, pad=12)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    _apply_theme(fig, ax)
    _save(fig, out, "top_ips.png")


def plot_attacks_timeline(parser: CowrieParser, out: Path) -> None:
    series = parser.attacks_over_time("1h")
    if series.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.fill_between(series.index, series.values, alpha=0.3, color=PURPLE)
    ax.plot(series.index, series.values, color=LILAC, linewidth=1.5)

    ax.set_xlabel("Tempo (UTC)", color=TEXT)
    ax.set_ylabel("Conexões / hora", color=TEXT)
    ax.set_title("Volume de Ataques ao Longo do Tempo", fontsize=14, pad=12)
    fig.autofmt_xdate()
    _apply_theme(fig, ax)
    _save(fig, out, "timeline.png")


def plot_top_credentials(parser: CowrieParser, out: Path) -> None:
    df = parser.top_credentials(15)
    if df.empty:
        return

    # Cria label "user:pass"
    has_user = "username" in df.columns
    has_pass = "password" in df.columns
    if has_user and has_pass:
        df["credential"] = df["username"].fillna("?") + " : " + df["password"].fillna("?")
    elif has_user:
        df["credential"] = df["username"].fillna("?")
    else:
        df["credential"] = df["password"].fillna("?")

    df = df.sort_values("count")

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(df["credential"], df["count"], color=LILAC, edgecolor=ACCENT, alpha=0.85)
    ax.set_xlabel("Tentativas", color=TEXT)
    ax.set_title("Top 15 Credenciais Tentadas", fontsize=14, pad=12)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    _apply_theme(fig, ax)
    _save(fig, out, "top_credentials.png")


def plot_top_commands(parser: CowrieParser, out: Path) -> None:
    data = parser.top_commands(15)
    if data.empty:
        return

    # Trunca comandos longos
    labels = [str(cmd)[:60] + ("…" if len(str(cmd)) > 60 else "") for cmd in data.index]
    df = pd.Series(data.values, index=labels).sort_values()

    fig, ax = plt.subplots(figsize=(11, 6))
    ax.barh(df.index, df.values, color=PALETTE[:len(df)], edgecolor=ACCENT, alpha=0.85)
    ax.set_xlabel("Ocorrências", color=TEXT)
    ax.set_title("Top 15 Comandos Executados pelos Atacantes", fontsize=14, pad=12)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    _apply_theme(fig, ax)
    _save(fig, out, "top_commands.png")


def plot_downloads(parser: CowrieParser, out: Path) -> None:
    df = parser.downloads
    if df.empty or "url" not in df.columns:
        print("  ℹ Nenhum download registrado.")
        return

    counts = df["url"].value_counts().head(10)

    fig, ax = plt.subplots(figsize=(11, 5))
    bars = ax.barh(counts.index[::-1], counts.values[::-1], color=DANGER, alpha=0.75, edgecolor="#922b21")
    ax.set_xlabel("Downloads", color=TEXT)
    ax.set_title("URLs de Malware Mais Baixadas", fontsize=14, pad=12)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    _apply_theme(fig, ax)
    _save(fig, out, "malware_downloads.png")


def plot_login_ratio(parser: CowrieParser, out: Path) -> None:
    n_fail = len(parser.logins_failed)
    n_ok   = len(parser.logins_success)
    if n_fail + n_ok == 0:
        return

    fig, ax = plt.subplots(figsize=(5, 5))
    wedges, texts, autotexts = ax.pie(
        [n_fail, n_ok],
        labels=["Falhos", "Sucesso"],
        autopct="%1.1f%%",
        colors=[PURPLE, LILAC],
        startangle=90,
        wedgeprops={"edgecolor": BG, "linewidth": 2},
    )
    for t in texts + autotexts:
        t.set_color(TEXT)
    ax.set_title("Tentativas de Login", fontsize=14, color=LILAC, pad=12)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    _save(fig, out, "login_ratio.png")


# ──────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Gera gráficos do honeypot Cowrie")
    ap.add_argument("--logs", default="../logs", help="Diretório dos logs JSON")
    ap.add_argument("--out",  default="./output", help="Diretório de saída dos gráficos")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Carregando logs...")
    parser = CowrieParser(args.logs).load()
    print(parser.summary())

    print("\nGerando gráficos...")
    plot_top_ips(parser, out_dir)
    plot_attacks_timeline(parser, out_dir)
    plot_top_credentials(parser, out_dir)
    plot_top_commands(parser, out_dir)
    plot_downloads(parser, out_dir)
    plot_login_ratio(parser, out_dir)

    print(f"\nProntos em: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
