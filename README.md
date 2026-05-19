# 🍯 HoneyPOT

Stack de honeypots containerizada para captura e análise de ataques reais. Combina um **SSH honeypot (Cowrie)** e um **HTTP honeypot (WordPress falso)** com pipeline de análise em Python que gera IoCs, gráficos e relatórios em Markdown.

---

## 📐 Arquitetura

```
HoneyPOT/
├── infra/
│   ├── docker-compose.yml        # Orquestra Cowrie + HTTP honeypot
│   ├── setup.sh                  # Provisionamento do host (Ubuntu/Azure)
│   └── http-honeypot/
│       ├── Dockerfile
│       ├── app.py                # Flask — WordPress falso
│       └── templates/            # HTML das páginas isca
├── analysis/
│   ├── parser.py                 # Lê logs JSON → DataFrames pandas
│   ├── plot.py                   # Gera gráficos (estética cyberpunk)
│   ├── report.py                 # Gera relatório Markdown com IoCs
│   └── requirements.txt
└── logs/                         # Volume persistente dos logs (gitignored)
```

### Serviços

| Container | Porta host | Porta interna | Função |
|---|---|---|---|
| `cowrie` | `22` | `2222` | SSH/Telnet honeypot (Cowrie) |
| `wp-honeypot` | `80` | `5000` | HTTP honeypot — WordPress falso |

> O SSH **real** do host é movido para a porta `2222` pelo `setup.sh`, liberando a `22` para o Cowrie.

---

## ⚙️ Pré-requisitos

- Ubuntu Server 22.04+ (testado em Azure VM)
- Docker Engine + Docker Compose Plugin
- Python 3.10+ (apenas para rodar a análise localmente)
- Acesso root no host para execução do `setup.sh`

O `setup.sh` instala o Docker automaticamente se não estiver presente.

---

## 🚀 Deploy

### 1. Clonar o repositório

```bash
git clone https://github.com/rabelojp41/HoneyPOT.git
cd HoneyPOT
```

### 2. Provisionar o host

```bash
sudo bash infra/setup.sh
```

O script executa automaticamente:
- Instala Docker Engine via repositório oficial
- Move o SSH do host da porta `22` → `2222`
- Configura UFW (libera `22/tcp` para o honeypot e `2222/tcp` para gestão)
- Cria e permissiona o diretório `logs/`
- Sobe os containers via `docker compose up -d`

> ⚠️ **Após o setup, reconecte via `ssh user@host -p 2222`** — a porta 22 passa a ser do honeypot.

### 3. Variáveis de ambiente (opcional)

Crie um `.env` em `infra/` para sobrescrever o IP exibido nas iscas:

```bash
SERVER_IP=<IP_PUBLICO_DA_VM>
```

### 4. Verificar se está rodando

```bash
cd infra
docker compose ps
docker compose logs -f cowrie
```

---

## 📊 Análise dos Logs

Os logs ficam em `logs/` — o Cowrie grava em `cowrie.json*` e o HTTP honeypot em `http-honeypot.json`.

### Instalar dependências

```bash
cd analysis
pip install -r requirements.txt
```

### Resumo rápido no terminal

```bash
python parser.py
# Saída:
# ══════════════════════════════════════════
#   COWRIE HONEYPOT — RESUMO
# ══════════════════════════════════════════
#   Total de eventos    : 4821
#   IPs únicos          : 312
#   Conexões            : 1204
#   Logins falhos       : 987
#   Logins bem-sucedidos: 3
#   Comandos executados : 241
#   Downloads (malware) : 7
# ══════════════════════════════════════════
```

### Gerar gráficos

```bash
python plot.py --logs ../logs --out ./output
```

Gráficos gerados em `analysis/output/`:

| Arquivo | Conteúdo |
|---|---|
| `top_ips.png` | Top 15 IPs atacantes |
| `timeline.png` | Volume de ataques por hora |
| `top_credentials.png` | Top 15 pares user:pass tentados |
| `top_commands.png` | Top 15 comandos executados pelos atacantes |
| `malware_downloads.png` | URLs de malware mais baixadas |
| `login_ratio.png` | Proporção logins falhos vs. bem-sucedidos |

### Gerar relatório Markdown com IoCs

```bash
python report.py --logs ../logs --out report.md
```

O `report.md` inclui tabelas com top IPs, credenciais, comandos, hashes SHA256 de malware e um bloco JSON com todos os IoCs prontos para importar em um SIEM ou threat intel feed.

---

## 🔌 API do `CowrieParser`

```python
from parser import CowrieParser

p = CowrieParser("../logs").load()

p.connections        # DataFrame: todas as conexões
p.logins_failed      # DataFrame: tentativas falhas
p.logins_success     # DataFrame: logins bem-sucedidos
p.commands           # DataFrame: comandos executados
p.downloads          # DataFrame: arquivos baixados pelos atacantes

p.top_ips(20)            # Series: IPs mais frequentes
p.top_credentials(20)    # DataFrame: pares user:pass mais tentados
p.top_commands(20)       # Series: comandos mais executados
p.attacks_over_time("1h")# Series: volume de ataques por intervalo
p.iocs()                 # dict: IPs, URLs, hashes, credenciais
p.summary()              # str: resumo formatado
```

---

## 🌐 HTTP Honeypot — Rotas da Isca

O `wp-honeypot` simula um WordPress com credenciais expostas para atrair scanners e bots.

| Rota | Comportamento |
|---|---|
| `/` | Página inicial WordPress falsa |
| `/wp-login.php`, `/wp-admin` | Login falso — loga todas as tentativas de credencial |
| `/server-info.php`, `/phpinfo.php` | phpinfo() falso com credenciais isca expostas |
| `/phpmyadmin`, `/pma` | Redireciona para o login falso |
| Qualquer 404 | Registrado como `http.probe.404` — detecta scanners |

Login com `admin`/`admin` retorna um dashboard WordPress falso (para manter o atacante engajado).

Todos os eventos são gravados em `logs/http-honeypot.json` no mesmo formato de linha JSON do Cowrie.

---

## 🔒 Precisa subir para a internet pública?

**Sim — o objetivo do honeypot é exatamente ficar exposto.** Mas com os seguintes controles obrigatórios:

### ✅ O que já está implementado

- Containers rodam em **rede bridge isolada** (`honeypot-net`) sem acesso à rede interna do host
- Resource limits configurados no Compose (`0.5 CPU / 256MB` Cowrie, `0.25 CPU / 128MB` HTTP)
- `no-new-privileges:true` em ambos os containers
- HTTP honeypot roda como usuário não-root (`UID 1001`)
- Secrets, chaves e `.env` estão no `.gitignore`

### ⚠️ O que você deve fazer antes de expor

- **Nunca rode em uma máquina com dados reais** — use uma VM dedicada (ex: Azure B1s, ~$10/mês)
- Configure alertas de billing na cloud para evitar surpresas com flood de tráfego
- Habilite o Network Security Group (NSG) da Azure para bloquear saída de tráfego dos containers se necessário
- Monitore o consumo de disco — logs de honeypot crescem rápido em ambientes com alto volume de scans
- Não exponha a porta `2222` (SSH real) publicamente — restrinja por IP no NSG/UFW

### 🧩 MITRE ATT&CK — Técnicas capturadas

| Tática | Técnica |
|---|---|
| Initial Access | T1190 — Exploit Public-Facing Application |
| Credential Access | T1110.001 — Brute Force: Password Guessing |
| Execution | T1059 — Command and Scripting Interpreter |
| Command & Control | T1105 — Ingress Tool Transfer (downloads de malware) |

---

## 📦 Gerenciamento dos Containers

```bash
# Ver status
docker compose ps

# Logs em tempo real
docker compose logs -f

# Reiniciar apenas o Cowrie
docker compose restart cowrie

# Parar tudo
docker compose down

# Subir forçando rebuild do HTTP honeypot
docker compose up -d --build
```

---

## 📄 Licença

MIT — use à vontade para estudos, CTFs e pesquisa em threat intelligence.
