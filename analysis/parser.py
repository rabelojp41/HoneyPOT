"""
parser.py — lê os logs JSON do Cowrie e retorna DataFrames prontos pra análise.

Uso:
    from parser import CowrieParser
    p = CowrieParser("../logs")
    p.load()
    print(p.summary())
"""

import json
import re
from pathlib import Path

import pandas as pd
from tqdm import tqdm


class CowrieParser:
    def __init__(self, logs_dir: str = "../logs"):
        self.logs_dir = Path(logs_dir)
        self._raw: list[dict] = []

    # ──────────────────────────────────────────
    # Carregamento
    # ──────────────────────────────────────────

    def load(self) -> "CowrieParser":
        """Lê todos os arquivos cowrie.json* do diretório de logs."""
        files = sorted(self.logs_dir.glob("cowrie.json*"))
        if not files:
            raise FileNotFoundError(f"Nenhum log encontrado em {self.logs_dir}")

        for path in tqdm(files, desc="Carregando logs"):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            self._raw.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        return self

    # ──────────────────────────────────────────
    # DataFrames por tipo de evento
    # ──────────────────────────────────────────

    def _df(self, *event_ids: str) -> pd.DataFrame:
        rows = [r for r in self._raw if r.get("eventid") in event_ids]
        if not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        return df

    @property
    def connections(self) -> pd.DataFrame:
        """Todas as conexões recebidas."""
        return self._df("cowrie.session.connect")

    @property
    def logins_failed(self) -> pd.DataFrame:
        return self._df("cowrie.login.failed")

    @property
    def logins_success(self) -> pd.DataFrame:
        return self._df("cowrie.login.success")

    @property
    def commands(self) -> pd.DataFrame:
        return self._df("cowrie.command.input")

    @property
    def downloads(self) -> pd.DataFrame:
        return self._df("cowrie.session.file_download")

    # ──────────────────────────────────────────
    # Agregações prontas
    # ──────────────────────────────────────────

    def top_ips(self, n: int = 20) -> pd.Series:
        df = self.connections
        if df.empty or "src_ip" not in df.columns:
            return pd.Series(dtype=int)
        return df["src_ip"].value_counts().head(n)

    def top_credentials(self, n: int = 20) -> pd.DataFrame:
        df = pd.concat([self.logins_failed, self.logins_success], ignore_index=True)
        if df.empty:
            return pd.DataFrame()
        cols = [c for c in ["username", "password"] if c in df.columns]
        return (
            df.groupby(cols)
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(n)
        )

    def top_commands(self, n: int = 20) -> pd.Series:
        df = self.commands
        if df.empty or "input" not in df.columns:
            return pd.Series(dtype=int)
        return df["input"].value_counts().head(n)

    def attacks_over_time(self, freq: str = "1h") -> pd.Series:
        """Número de conexões agrupadas por intervalo de tempo."""
        df = self.connections
        if df.empty or "timestamp" not in df.columns:
            return pd.Series(dtype=int)
        return df.set_index("timestamp").resample(freq).size()

    def unique_ips(self) -> int:
        df = self.connections
        if df.empty or "src_ip" not in df.columns:
            return 0
        return df["src_ip"].nunique()

    def iocs(self) -> dict:
        """Retorna um dicionário com os principais Indicadores de Comprometimento."""
        dl = self.downloads
        return {
            "ips": self.top_ips(50).index.tolist(),
            "malware_urls": dl["url"].dropna().unique().tolist() if not dl.empty and "url" in dl.columns else [],
            "malware_hashes": dl["shasum"].dropna().unique().tolist() if not dl.empty and "shasum" in dl.columns else [],
            "credentials": self.top_credentials(30).to_dict(orient="records"),
        }

    def summary(self) -> str:
        lines = [
            "═" * 50,
            "  COWRIE HONEYPOT — RESUMO",
            "═" * 50,
            f"  Total de eventos    : {len(self._raw)}",
            f"  IPs únicos          : {self.unique_ips()}",
            f"  Conexões            : {len(self.connections)}",
            f"  Logins falhos       : {len(self.logins_failed)}",
            f"  Logins bem-sucedidos: {len(self.logins_success)}",
            f"  Comandos executados : {len(self.commands)}",
            f"  Downloads (malware) : {len(self.downloads)}",
            "═" * 50,
        ]
        return "\n".join(lines)


if __name__ == "__main__":
    p = CowrieParser("../logs").load()
    print(p.summary())
