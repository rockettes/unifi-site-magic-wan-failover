#!/usr/bin/env bash
# ucg-ssh.sh — roda um comando por SSH num gateway UniFi.
#
# 🔑 O SSH do UCG aceita SO SENHA: nao ha authorized_keys e o UniFi OS nao
#    oferece caminho suportado para adicionar uma. Por isso `expect`, e nao
#    chave — medido em 2026-08-29.
#
# ⚠️ A senha vem do .env (UCG_SSH_ROOT_PASS) e NUNCA aparece em argv: o expect
#    a le do ambiente. `ps` de outro usuario nao a enxerga.
#
# Uso:  ./scripts/ucg-ssh.sh 192.168.1.1 'ip -br a'
set -uo pipefail
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${1:?uso: ucg-ssh.sh <host> <comando>}"; shift
CMD="$*"
SENHA=$(grep -m1 '^UCG_SSH_ROOT_PASS=' "$RAIZ/.env" | cut -d= -f2- | sed 's/#.*//' | tr -d ' "'"'"'')
[ -z "$SENHA" ] && { echo "erro: UCG_SSH_ROOT_PASS ausente no .env" >&2; exit 1; }
export SENHA CMD HOST
expect -c '
  set timeout 90
  log_user 0
  spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR root@$env(HOST) $env(CMD)
  expect {
    "assword:" { send "$env(SENHA)\r" }
    timeout    { puts "TIMEOUT esperando senha"; exit 1 }
  }
  log_user 1
  expect eof
'
