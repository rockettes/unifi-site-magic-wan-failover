#!/usr/bin/env bash
# sonda-ssh.sh — UMA sessao multiplexada para a sonda, compartilhada por todo
#               script deste repo (e por mim, na mao).
#
# POR QUE ISTO EXISTE
#
# A sonda derruba o sshd com conexao em rajada (`MaxStartups`, regra 3 do
# CLAUDE.md). Mesmo sabendo disso, cada ferramenta daqui abria conexao propria:
# o `deploy.sh` dispara uma por arquivo (~15 seguidas) e derrubou a porta 22
# DUAS vezes em 2026-09-19; o `failover-prova-guiada.sh` abria mais tres. A
# regra existia, estava escrita, e mesmo assim era violada em toda execucao —
# porque dependia de quem chamava lembrar dela. Aqui ela passa a ser mecanismo:
# quem quiser falar com a sonda fala por este arquivo, e este arquivo mantem
# UMA sessao autenticada viva e serializa todo mundo nela.
#
# ⛔ `nc -z` NAO entra aqui. Medido 2026-08-23: falso negativo 6 de 6 contra o
#    sonda enquanto o `ssh` funcionava 6 de 6 no mesmo host e porta, e ainda por
#    cima foi ele que estourou o MaxStartups. Quem testa porta e o `/dev/tcp`
#    do bash — e mesmo ele so diz que ALGO escuta. Sinal de vida honesto e
#    comando executado (`vivo`).
#
# USO NA LINHA DE COMANDO
#   scripts/sonda-ssh.sh vivo                       # 0 se executa comando
#   scripts/sonda-ssh.sh exec '<comando cmd.exe>'
#   scripts/sonda-ssh.sh ps '<comando powershell>' # embrulha sozinho
#   scripts/sonda-ssh.sh copia LOCAL 'C:/destino'
#   scripts/sonda-ssh.sh destacar '<powershell>' NOME-DA-TAREFA
#   scripts/sonda-ssh.sh fechar
#
# USO COMO BIBLIOTECA
#   source "$(dirname "$0")/sonda-ssh.sh"   # nao executa nada
#   sonda_exec '...' ; sonda_copia a b ; sonda_ps '...'
set -uo pipefail

SONDA_HOST="${HOMELAB_SONDA:-win-siteb}"
SONDA_CTL="${TMPDIR:-/tmp}/cm-sonda-$(printf '%s' "$SONDA_HOST" | tr -c 'a-zA-Z0-9' '_').sock"
SONDA_TRAVA="${TMPDIR:-/tmp}/sonda-ssh.trava"
SONDA_PERSIST="${SONDA_PERSIST:-600}"
SONDA_TETO_PORTA="${SONDA_TETO_PORTA:-900}"   # teto da espera quando a porta cai (regra 16)
SONDA_ESPACO="${SONDA_ESPACO:-3}"             # segundos entre operacoes consecutivas

_sonda_msg() { printf '  [sonda] %s\n' "$*" >&2; }

# porta TCP sem mentir: /dev/tcp, com teto feito a mao porque o macOS nao tem
# `timeout`. Mesmo metodo do health-check.sh.
#
# ⚠️ O `bash -c` NAO e enfeite: `/dev/tcp` e recurso do **bash** e nao existe
#    no **zsh**, que e o shell padrao do Mac. Sourceado a partir do zsh, o
#    teste dava "porta fechada" contra QUALQUER alvo — inclusive um sonda que
#    respondia `ssh` no mesmo segundo. Esse erro ja custou um dia de medicao em
#    2026-09-01 e se repetiu em 2026-09-19. Assim o resultado nao depende mais
#    do shell de quem chamou.
_sonda_porta() {
  bash -c "exec 3<>/dev/tcp/${1}/22" 2>/dev/null &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 60 ]; do sleep 0.1; i=$((i+1)); done
  if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 1; fi
  wait "$pid" 2>/dev/null
}

# ── trava: duas ferramentas ao mesmo tempo viram rajada de novo ──────────────
# A trava guarda o PID do dono. Dono morto (script interrompido, Ctrl-C,
# processo derrubado) libera na hora em vez de prender todo mundo pelo teto —
# medido 2026-09-19: um kill no meio deixou a trava presa e a chamada seguinte
# ficou 2 min parada sem motivo.
_sonda_travar() {
  local t0 espera=0 dono
  t0=$(date +%s)
  until mkdir "$SONDA_TRAVA" 2>/dev/null; do
    dono="$(cat "$SONDA_TRAVA/pid" 2>/dev/null)"
    if [ -n "$dono" ] && ! kill -0 "$dono" 2>/dev/null; then
      _sonda_msg "trava de processo morto ($dono) — liberando"
      rm -rf "$SONDA_TRAVA"; continue
    fi
    espera=$(( $(date +%s) - t0 ))
    if [ "$espera" -ge 120 ]; then         # teto: trava viva nao pode prender para sempre
      _sonda_msg "trava presa ha ${espera}s — assumindo orfa e seguindo"
      rm -rf "$SONDA_TRAVA"; mkdir -p "$SONDA_TRAVA"; break
    fi
    sleep 1
  done
  echo $$ > "$SONDA_TRAVA/pid" 2>/dev/null || true
}
_sonda_destravar() { rm -rf "$SONDA_TRAVA" 2>/dev/null || true; }

# ── a sessao: abre uma vez, todo mundo reusa ────────────────────────────────
sonda_abrir() {
  [ -S "$SONDA_CTL" ] && ssh -S "$SONDA_CTL" -O check "$SONDA_HOST" >/dev/null 2>&1 && return 0
  rm -f "$SONDA_CTL" 2>/dev/null

  # alvo do teste de porta: o HostName real, nao o alias
  local alvo; alvo="$(ssh -G "$SONDA_HOST" 2>/dev/null | awk '/^hostname /{print $2; exit}')"
  [ -n "$alvo" ] || alvo="$SONDA_HOST"

  local t0; t0=$(date +%s)
  until _sonda_porta "$alvo"; do
    local espera=$(( $(date +%s) - t0 ))
    if [ "$espera" -ge "$SONDA_TETO_PORTA" ]; then
      _sonda_msg "teto de $((SONDA_TETO_PORTA/60)) min: porta 22 de $alvo nao abriu"
      return 1
    fi
    # 60 s entre tentativas: se o sshd ja esta sufocado, sondar rapido piora
    _sonda_msg "porta 22 fechada — esperando 60 s (${espera}s de ${SONDA_TETO_PORTA}s)"
    sleep 60
  done

  ssh -M -S "$SONDA_CTL" -o ControlPersist="$SONDA_PERSIST" -fN \
      -o BatchMode=yes -o ConnectTimeout=25 \
      -o ServerAliveInterval=15 -o ServerAliveCountMax=8 \
      "$SONDA_HOST" >/dev/null 2>&1
  [ -S "$SONDA_CTL" ]
}

sonda_fechar() {
  [ -S "$SONDA_CTL" ] && ssh -S "$SONDA_CTL" -O exit "$SONDA_HOST" >/dev/null 2>&1
  rm -f "$SONDA_CTL" 2>/dev/null; return 0
}

# comando cru (o shell de la e cmd.exe)
sonda_exec() {
  _sonda_travar
  if ! sonda_abrir; then _sonda_destravar; return 1; fi
  ssh -S "$SONDA_CTL" -o BatchMode=yes -o ConnectTimeout=25 "$SONDA_HOST" "$@" </dev/null
  local st=$?
  sleep "$SONDA_ESPACO"          # espacamento: a regra 3 virando mecanismo
  _sonda_destravar
  return $st
}

# powershell embrulhado — o erro de escapar a mao ja custou caro aqui
sonda_ps() {
  local cmd="$1"
  sonda_exec "powershell -NoProfile -ExecutionPolicy Bypass -Command \"${cmd//\"/\\\"}\""
}

# copia com plano B: se o `scp` recusar (2026-09-19: `Connection closed` no
# sonda enquanto o `ssh` ia bem, causa em aberto), manda o arquivo por STDIN em
# base64 pela MESMA sessao. Sem stdin gigante na linha de comando: o cmd.exe
# corta em ~32 KB.
sonda_copia() {
  local origem="$1" destino="$2"
  [ -f "$origem" ] || { _sonda_msg "sem origem: $origem"; return 1; }
  _sonda_travar
  if ! sonda_abrir; then _sonda_destravar; return 1; fi

  local st=0
  if scp -o ControlPath="$SONDA_CTL" -o BatchMode=yes -q "$origem" "$SONDA_HOST:$destino" 2>/dev/null; then
    st=0
  else
    _sonda_msg "scp recusou — indo por base64 na mesma sessao"
    local dest_win="${destino//\//\\}"
    base64 < "$origem" | tr -d '\n' | ssh -S "$SONDA_CTL" -o BatchMode=yes "$SONDA_HOST" \
      "powershell -NoProfile -Command \"\$b=[Console]::In.ReadToEnd(); [IO.File]::WriteAllBytes('$dest_win',[Convert]::FromBase64String(\$b))\"" >/dev/null 2>&1
    st=$?
  fi
  sleep "$SONDA_ESPACO"
  _sonda_destravar
  return $st
}

# trabalho que precisa SOBREVIVER ao fim da sessao SSH.
# ⛔ `Start-Process` NAO serve: medido 2026-09-19, o OpenSSH do Windows derruba
#    a arvore de processos quando a sessao fecha — e o `ssh` volta 0 do mesmo
#    jeito, virando falso positivo. Tarefa agendada roda pelo servico do
#    Windows e nao e filha do sshd.
sonda_destacar() {
  local cmd="$1" tarefa="${2:-homelab-destacado}"
  # 2>/dev/null: o schtasks avisa "a tarefa talvez nao seja executada porque
  # /ST e anterior a hora atual" — verdade e irrelevante, porque quem dispara
  # e o /run logo abaixo, nao o horario. O aviso so assusta quem opera.
  sonda_exec "schtasks /create /tn $tarefa /tr \"$cmd\" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f" >/dev/null 2>&1 || return 1
  sonda_exec "schtasks /run /tn $tarefa" >/dev/null 2>&1
}
sonda_destacar_limpar() { sonda_exec "schtasks /delete /tn ${1:-homelab-destacado} /f" >/dev/null 2>&1; }

# sinal de vida honesto: comando executado, nao porta aberta
sonda_vivo() { [ "$(sonda_exec 'echo ok' 2>/dev/null | tr -d '\r')" = "ok" ]; }

# ── se foi SOURCEADO, para por aqui ─────────────────────────────────────────
(return 0 2>/dev/null) && return 0

case "${1:-}" in
  vivo)       sonda_vivo && { echo "vivo"; exit 0; } || { echo "sem resposta"; exit 1; } ;;
  exec)      shift; sonda_exec "$@" ;;
  ps)        shift; sonda_ps "$1" ;;
  copia)     shift; sonda_copia "$1" "$2" ;;
  destacar)  shift; sonda_destacar "$1" "${2:-homelab-destacado}" ;;
  limpar)    shift; sonda_destacar_limpar "${1:-homelab-destacado}" ;;
  fechar)    sonda_fechar; echo "sessao fechada" ;;
  *) sed -n '2,32p' "$0"; exit 2 ;;
esac
