#!/usr/bin/env bash
# Honeypot setup script — Ubuntu Server (Azure VM)
# Run as root: sudo bash setup.sh

set -euo pipefail

HONEYPOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGS_DIR="${HONEYPOT_DIR}/logs"
NEW_SSH_PORT=2222

log()  { echo -e "\e[35m[honeypot]\e[0m $*"; }
ok()   { echo -e "\e[32m[  ok  ]\e[0m $*"; }
warn() { echo -e "\e[33m[ warn ]\e[0m $*"; }
die()  { echo -e "\e[31m[ fail ]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Execute como root: sudo bash setup.sh"

# ──────────────────────────────────────────────
# 1. Dependências do sistema
# ──────────────────────────────────────────────
log "Atualizando pacotes..."
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg lsb-release ufw

# ──────────────────────────────────────────────
# 2. Docker Engine
# ──────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Instalando Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    ok "Docker instalado: $(docker --version)"
else
    ok "Docker já instalado: $(docker --version)"
fi

# ──────────────────────────────────────────────
# 3. Mover SSH do host para a porta 2222
#    (libera a porta 22 para o honeypot)
# ──────────────────────────────────────────────
SSHD_CONFIG="/etc/ssh/sshd_config"

if grep -qE "^Port ${NEW_SSH_PORT}" "${SSHD_CONFIG}"; then
    ok "SSH do host já está na porta ${NEW_SSH_PORT}"
else
    log "Movendo SSH do host para porta ${NEW_SSH_PORT}..."

    # Garante que não existe linha 'Port' duplicada
    sed -i "s/^#\?Port [0-9]*/Port ${NEW_SSH_PORT}/" "${SSHD_CONFIG}"

    # Se ainda não existe a diretiva Port, adiciona
    grep -qE "^Port " "${SSHD_CONFIG}" \
        || echo "Port ${NEW_SSH_PORT}" >> "${SSHD_CONFIG}"

    # Reinicia SSHD — conexão atual NÃO é derrubada (já estabelecida)
    systemctl restart sshd
    ok "SSH do host movido para ${NEW_SSH_PORT}. Reconecte via: ssh user@host -p ${NEW_SSH_PORT}"
fi

# ──────────────────────────────────────────────
# 4. Firewall (UFW)
# ──────────────────────────────────────────────
log "Configurando UFW..."
ufw --force reset

# Porta de gerenciamento real (SSH do host)
ufw allow "${NEW_SSH_PORT}/tcp" comment "SSH management"

# Porta 22 — honeypot Cowrie (exposta ao mundo)
ufw allow 22/tcp comment "Cowrie honeypot SSH"

# Telnet honeypot (opcional, descomente se quiser)
# ufw allow 23/tcp comment "Cowrie honeypot Telnet"

ufw --force enable
ok "UFW ativo:"
ufw status numbered

# ──────────────────────────────────────────────
# 5. Diretório de logs persistentes
# ──────────────────────────────────────────────
log "Preparando diretório de logs: ${LOGS_DIR}"
mkdir -p "${LOGS_DIR}"
# Cowrie roda como UID 1000 dentro do container
chown -R 1000:1000 "${LOGS_DIR}"
chmod 750 "${LOGS_DIR}"
ok "Logs em: ${LOGS_DIR}"

# ──────────────────────────────────────────────
# 6. Subir o honeypot
# ──────────────────────────────────────────────
log "Iniciando Cowrie via Docker Compose..."
cd "${HONEYPOT_DIR}/infra"
docker compose up -d --pull always
ok "Honeypot ativo. Logs em tempo real:"
echo "  docker compose logs -f cowrie"
echo ""
echo "  Logs JSON: ${LOGS_DIR}/cowrie.json"
