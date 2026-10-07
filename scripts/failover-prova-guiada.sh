#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# OS ENDERECOS NOS COMENTARIOS SAO MARCADORES, NAO ENDERECOS DE VERDADE.
# Este arquivo e a copia publica de um script que rodou numa rede real; os
# enderecos daquela rede foram substituidos. Onde se le:
#
#   <WAN1-A>   IP publico da WAN1 do site A — a que tem o cabo puxado
#   <WAN2-A>   IP publico da WAN2 do site A — a sobrevivente
#   <PUB-B>    IP publico TRADUZIDO do site B, o que o WireGuard aprende
#   <CGNAT-B>  IP interno do site B dentro do CGNAT da operadora dele
#              (RFC 6598, 100.64.0.0/10) — o endereco que a nuvem provisiona
#              e que nao existe na Internet. E a dobradica do defeito.
#
# Nada aqui depende desses valores: o script DESCOBRE os enderecos reais em
# tempo de execucao. Eles aparecem so para a explicacao fazer sentido.
# ─────────────────────────────────────────────────────────────────────────────
# failover-prova-guiada.sh — conduz o teste de failover do Site Magic do
# comeco ao fim: diz o que fazer, DETECTA sozinho que voce fez, coleta tudo,
# analisa, e deixa o pacote commitado e no remoto.
#
# ⚠️ `set -uo pipefail` SEM `-e`, de proposito: aqui alvo mudo e RESULTADO
#    ESPERADO, nao erro. Mesma excecao de teste-failover-wan.sh.
#
# ─────────────────────────────────────────────────────────────────────────────
# O QUE ELE PROVA, E POR QUE ASSIM
#
# Ticket #5927426. A Ubiquiti respondeu (17/09) que "o failover funciona desde
# que a WAN de backup tenha conectividade e IP publicamente alcancavel", e
# pediu capturas das duas WANs, support file e carimbo de tempo exato.
# Este script produz isso fechando CADA objecao antes que ela seja levantada:
#
#   objecao possivel                prova que este script produz
#   ─────────────────────────────   ──────────────────────────────────────────
#   "a outra WAN nao era publica"   sonda EXTERNA da Casa B (outra operadora,
#                                   fora do tunel — ver abaixo) batendo no IP
#                                   publico da WAN sobrevivente o tempo todo
#   "a outra WAN estava sem rede"   captura geral nessa WAN: milhares de
#                                   pacotes de OUTRO trafego durante a queda
#   "o gateway nao viu a WAN cair"  estado da interface lido no proprio
#                                   gateway, de 2 em 2 s, durante toda a janela
#   "voce nao esperou o bastante"   janela default de 900 s; o teste que eles
#                                   ja receberam tinha 727 s
#   "a captura nao mostra tentativa" tcpdump filtrado no ENDPOINT do peer, nas
#                                   duas WANs ao mesmo tempo: zero pacote na
#                                   sobrevivente enquanto ela carrega o resto
#   "carimbo ambiguo"               um relogio so — o do gateway — em todo
#                                   artefato, ISO-8601 com offset
#   "voce mexeu em outra coisa"     manifesto SHA-256 de cada arquivo + o
#                                   estado completo de rotas/regras antes,
#                                   durante e depois
#   (v2, 2026-09-23 — o que o Product Lead pediu depois de admitir o sintoma)
#   "e o lado B? ele tenta a WAN2?" endpoint que a nuvem provisiona em B para
#                                   A, lido antes e vigiado de 2 em 2 s; captura
#                                   na WAN da gw_b durante a queda: para
#                                   ONDE B inicia handshake (00c, 05, pvb-*)
#   "a operadora de B filtra 20000" sonda UDP de B para a WAN sobrevivente de
#                                   A na porta 20000, a cada 30 s, com a chegada
#                                   contada na captura de A (06 + pcap de A).
#                                   Ja no --ensaio: 3 de 3 chegaram em 23/09
#
# ─────────────────────────────────────────────────────────────────────────────
# O ARRANJO DE 2026-09-18, E POR QUE O SCRIPT DESCOBRE O ALVO EM VEZ DE FIXA-LO
#
# O tunel esta ASSIMETRICO:
#   A → B  sai por `ppp0` (WAN1 ISP-1, <WAN1-A>)
#   B → A  entra por `<WAN2-A>:20000` = WAN2 **ISP-2** da Casa A
# Puxar "o cabo da WAN1" as cegas pode testar NADA se, na hora, o tunel
# estiver saindo pela outra. Por isso o passo zero e descobrir a saida atual.
#
# O QUE DECIDE A SAIDA (lido inteiro, nao pela metade)
#
#   32766: from all lookup 201.ppp0        ← pega-tudo: tabela da WAN primaria
#
# E so isso. A saida e a ISP-1 porque a ISP-1 e a primaria.
#
# ⚠️ CORRECAO DE UMA LEITURA MINHA, para nao virar folclore no repo: existe
#    tambem a regra
#      32500: from all to <CGNAT-B> dport 20000 lookup 201.ppp0
#    e eu a li como "o binding de WAN que prende o tunel a ISP-1". NAO e.
#    Ela e escrita pelo `ubios-udapi-server` a partir do
#    `/run/wireguard_wgsts1000.*.config`, onde o Endpoint provisionado e
#    `<CGNAT-B>:20000` — o endereco INTERNO de CGNAT da Casa B. Mas o
#    peer vivo e `<PUB-B>:65500`, o endereco TRADUZIDO que o WireGuard
#    aprendeu pelo handshake de entrada. Os dois nao batem: a 32500 nao casa
#    com o trafego real e esta inerte. A mesma regra existe espelhada na
#    Casa B, apontando para o IP da ISP-1 enquanto o tunel de la fala com o da
#    ISP-2 — mesmo descasamento, dos dois lados.
#
# 📌 A UNICA regra que mandaria o tunel para a tabela da ISP-2 e
#      32507: from <WAN2-A> lookup 202.eth3
#    que casa por ENDERECO DE ORIGEM. Ou seja, para usar a ISP-2 o daemon
#    teria de religar o socket na origem da ISP-2. A pergunta do teste fica
#    precisa: o Site Magic refaz esse bind quando a WAN primaria morre?
#
# ⚠️ Isso e MECANISMO OBSERVADO, nao conclusao — e o veredito do script sai
#    dos CONTADORES, nao desta leitura. Regra 17 do CLAUDE.md vale nos dois
#    sentidos: nem a resposta do fabricante nem a minha leitura do `ip rule`
#    viram fato sem o teste.
#
# ─────────────────────────────────────────────────────────────────────────────
# DISCIPLINA
#   - todo laco de espera tem TETO (regra 16); estourou, aborta limpo e ainda
#     assim coleta o que ja existe;
#   - a sonda leva UMA conexao por vez, espacada (regra 3): a sonda e publicada
#     e disparada DESTACADA, porque a conexao SSH morre junto com o tunel —
#     e o tunel cair e justamente o evento medido;
#   - ⚠️ DESTACADA DE VERDADE = TAREFA AGENDADA, nao `Start-Process`. Medido
#     2026-09-19: o OpenSSH do Windows derruba a arvore de processos quando a
#     sessao fecha, e o `ssh` volta 0 do mesmo jeito. Resultado do mecanismo
#     antigo: a sonda morria antes de escrever o cabecalho, ZERO log, e este
#     script anunciava "sonda disparada DESTACADA" — falso positivo no pivo do
#     dossie. A tarefa agendada roda pelo servico do Windows, nao e filha do
#     sshd, e sobrevive;
#   - nada e escrito direto no Windows (regra 14): a sonda vem do repo;
#   - o script nunca deixa processo rodando no gateway: `trap` mata tcpdump em
#     qualquer saida, inclusive Ctrl-C.
#
# USO
#   ./scripts/failover-prova-guiada.sh --ensaio      # valida tudo, nao toca em nada
#   ./scripts/failover-prova-guiada.sh               # teste completo (900 s)
#   ./scripts/failover-prova-guiada.sh --janela 1800 # janela maior
#   ./scripts/failover-prova-guiada.sh --porta 4     # corta a ISP-2 (eth3) em vez da WAN de saida
#   ./scripts/failover-prova-guiada.sh --sem-painel  # v3: NAO pede support files nem capturas pelo painel
#   ./scripts/failover-prova-guiada.sh --sem-push    # commita mas nao empurra
#
# v3 (2026-09-24) — o que a Ubiquiti pediu depois de admitir o mecanismo:
#   support file dos DOIS consoles gerados DURANTE a falha, e capturas de WAN
#   SIMULTANEAS pela ferramenta do proprio painel (Devices > UCG > Overview >
#   Packet Captures), WAN2 de A e WAN de B. O script agora conduz o operador
#   por essas 4 tarefas no navegador enquanto o cabo esta fora, detecta os
#   arquivos em ~/Downloads e so pede o cabo de volta depois de te-los.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACAO — tudo que depende do SEU ambiente vem daqui, nada e fixo no
# codigo. Copie `.env.example` para `.env` e preencha, ou exporte no shell.
#
#   GW_A        gateway do site A, o que tem DUAS WANs e onde o cabo e puxado
#   GW_B        gateway do site B, atras de CGNAT
#   SONDA_USER  usuario da maquina-sonda do site B
#   SONDA_HOST  endereco da maquina-sonda, ALCANCADA PELO TUNEL DO SITE MAGIC
#
# ⚠️ A sonda tem de ser alcancada pelo caminho do Site Magic, NAO por uma VPN
#    de usuario: essa VPN cai junto com o tunel, e a sessao morreria no meio
#    do teste — que e exatamente o evento medido.
# O .env e lido ANTES das checagens, e nunca entra no git.
if [ -f "$RAIZ/.env" ]; then
  set -a; . "$RAIZ/.env"; set +a
fi
: "${GW_A:?defina GW_A, ex.: GW_A=192.168.1.1}"
: "${GW_B:?defina GW_B, ex.: GW_B=192.168.2.1}"
: "${SONDA_USER:?defina SONDA_USER, o usuario da maquina-sonda do site B}"
: "${SONDA_HOST:?defina SONDA_HOST, o IP da maquina-sonda pelo tunel}"

# Todo acesso a sonda passa por aqui: uma sessao, serializada e espacada.
export HOMELAB_SONDA="${HOMELAB_SONDA:-${SONDA_USER}@${SONDA_HOST}}"
source "$(dirname "${BASH_SOURCE[0]}")/sonda-ssh.sh"
GATEWAY_A="$GW_A"
# 🔑 LADO B (v2, 2026-09-23). A Ubiquiti (Product Lead de SD-WAN)
#    admitiu o sintoma e pediu o que faltava: o endpoint que a nuvem provisiona
#    em B para A, e captura na WAN de B durante a falha — "B tenta a WAN2 de
#    A?". A gw_b so e alcancavel pelo proprio Site Magic: ela SOME quando o
#    tunel cai. Logo tudo do lado B e armado ANTES do corte, destacado e com
#    teto (`timeout`), e colhido quando o tunel volta. Nada e tocado em B
#    durante a janela.
GATEWAY_B="$GW_B"
TAREFA_SONDA=homelab-sonda-failover
TUNEL=wgsts1000
# ⛔ FILTRAR PELA PORTA, NAO SO PELO PEER. Auditoria de 2026-09-19: o filtro
#    `host $EP_IP and udp` capturava TAMBEM a VPN de usuario (51820) que o
#    sonda da Casa B mantem contra a mesma WAN — mesmo IP publico, porque o
#    sonda sai pelo CGNAT do gw_b. O RESUMO dizia "1393 pacotes do tunel na
#    sobrevivente" e eram TODOS da sonda; do Site Magic (UDP 20000) havia ZERO.
#    Numero certo com etiqueta errada e o que a defesa mais gosta de achar.
PORTA_SM=20000
JANELA=900          # 15 min. Era 1800; 15 basta e permite repetir a serie
ENSAIO=0
PUSH=1
# PAINEL=1 (v3): pede ao operador, durante a queda, os support files dos DOIS
# consoles e as capturas pelo painel dos dois gateways — o pedido do o Product Lead de SD-WAN
# em 24/09. Ate a v2 o support file era opcional (--com-support), porque a
# config de A nao mudava entre corridas; agora o que interessa e o PAR gerado
# no mesmo instante de falha. --sem-painel desliga (corrida so de medicao).
PAINEL=1
ALVO_FLAG=""
# ⚠️ `-P` RESOLVE SYMLINK, e isso nao e detalhe: neste Mac o ~/Downloads e um
#    link para /Volumes/S1T/Downloads, e o `find` do BSD NAO atravessa symlink
#    sem `-L`. Resultado medido em 2026-09-19, com o teste rodando e o cabo ja
#    fora: a deteccao do support file nao achava NADA, e nunca acharia.
#    Mesma familia do `timeout` que nao existe no macOS e do `/dev/tcp` que nao
#    existe no zsh — comando que funciona no Linux e mente aqui.
DOWNLOADS="$(cd -P "$HOME/Downloads" 2>/dev/null && pwd)"
[ -n "$DOWNLOADS" ] || DOWNLOADS="$HOME/Downloads"
TMPD="${TMPDIR:-/tmp}/failover-prova-$$"
ASKPASS="$TMPD/askpass.sh"
CTL="$TMPD/ctl"
CTL_B="$TMPD/ctl-b"
# Sonda UDP de B para a WAN sobrevivente de A, na porta do Site Magic: um
# datagrama com este prefixo a cada 30 s. Chegando UM na captura de A, "a
# operadora de B filtra UDP/20000 para a WAN2 de A" morre como hipotese. O
# WireGuard descarta em silencio o que nao e protocolo dele — inofensivo.
# Em BPF: os 4 primeiros bytes do payload UDP = "PROV".
SONDA_PREFIXO="PROVA-5927426-B"
SONDA_BPF="udp[8:4]=0x50524f56"
SONDA_UDP_PASSO=30
TETO_CABO=900          # ate 15 min esperando voce puxar/religar o cabo
TETO_PAINEL=600        # depois da janela: ate 10 min para o operador parar as capturas e baixar tudo
LIMITE_COMMIT_MB=25    # acima disso o binario fica fora do commit

# ── rastreabilidade: cada pacote diz QUAL script o produziu ──────────────────
# "Mesmo script" = mesma SECAO DE MEDICAO (das pre-condicoes ate "parando
# capturas e coletando"). O pos-processamento pode ser corrigido sem invalidar
# a serie; a medicao, nao. O hash ignora comentarios, linhas em branco e as
# proprias linhas de rastreabilidade — assim so codigo que MEDE conta.
#   ./scripts/failover-prova-guiada.sh --hash-medicao <commit|tag|arquivo>
hash_medicao() {   # $1 = texto do script
  printf '%s\n' "$1" | sed -n '/^# ═* PRE-CONDICOES ═/,/^passo "parando capturas e coletando"/p' \
    | grep -v -E '^\s*#|^\s*$|marcar "SCRIPT|SCRIPT_SHA=|SCRIPT_GIT=|MEDICAO_SHA=' \
    | shasum -a 256 | cut -c1-16
}
SCRIPT_SHA="$(shasum -a 256 "${BASH_SOURCE[0]}" | cut -c1-16)"
MEDICAO_SHA="$(hash_medicao "$(cat "${BASH_SOURCE[0]}")")"
SCRIPT_GIT="$(cd "$RAIZ" && git log -1 --format=%h -- scripts/failover-prova-guiada.sh 2>/dev/null)$(cd "$RAIZ" && git diff --quiet -- scripts/failover-prova-guiada.sh 2>/dev/null || echo '+alterado-nao-commitado')"

while [ $# -gt 0 ]; do
  case "$1" in
    --ensaio)    ENSAIO=1 ;;
    --janela)    JANELA="${2:?--janela precisa de segundos}"; shift ;;
    --sem-push)  PUSH=0 ;;
    # Escolher a WAN a cortar. Sem isto o alvo e a WAN por onde o tunel SAI.
    # Com --porta 4 corta-se a ISP-2 mesmo que o tunel saia pela ISP-1: o que se
    # testa ai e a WAN por onde a Casa B CHEGA (tunel assimetrico, 2026-09-18).
    --porta)     case "${2:?--porta precisa do numero (4 ou 5)}" in
                   4) ALVO_FLAG=eth3 ;; 5) ALVO_FLAG=ppp0 ;;
                   *) echo "--porta aceita 4 (ISP-2/eth3) ou 5 (ISP-1/ppp0)"; exit 2 ;;
                 esac; shift ;;
    --sem-painel|--sem-support) PAINEL=0 ;;  # corrida so de medicao, sem tarefas no navegador
    --com-support) PAINEL=1 ;;               # mantido por compatibilidade: ja e o padrao
    --hash-medicao)
      ref="${2:?--hash-medicao precisa de um commit/tag ou caminho}"; shift
      if [ -f "$ref" ]; then src="$(cat "$ref")"; else src="$(git -C "$RAIZ" show "$ref:scripts/failover-prova-guiada.sh" 2>/dev/null)"; fi
      [ -n "$src" ] || { echo "nao achei o script em '$ref'"; exit 2; }
      hash_medicao "$src"; exit 0 ;;
    -h|--help)   sed -n '2,/^set -uo pipefail/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "opcao desconhecida: $1"; exit 2 ;;
  esac
  shift
done

# ───────────────────────────────────────────────────────────── aparencia ────
if [ -t 1 ]; then
  N=$'\033[0m'; B=$'\033[1m'; VERM=$'\033[31m'; VERD=$'\033[32m'
  AMAR=$'\033[33m'; AZUL=$'\033[36m'
else
  N=; B=; VERM=; VERD=; AMAR=; AZUL=
fi
titulo() { printf '\n%s%s%s\n' "$B$AZUL" "$*" "$N"; }
passo()  { printf '\n%s▸ %s%s\n' "$B" "$*" "$N"; }
ok()     { printf '  %s✅ %s%s\n' "$VERD" "$*" "$N"; }
aviso()  { printf '  %s⚠️  %s%s\n' "$AMAR" "$*" "$N"; }
erro()   { printf '  %s⛔ %s%s\n' "$VERM" "$*" "$N"; }
acao()   { printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$B$AMAR" "$N"
           printf '%s║  AGORA VOCE: %-48s║%s\n' "$B$AMAR" "$1" "$N"
           printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$B$AMAR" "$N"; }

# ────────────────────────────────────────────────────── ssh do gateway ─────
# ControlMaster: UMA autenticacao, muitas consultas. Sem isso o script abriria
# centenas de conexoes durante a janela.
senha_gw() { grep -m1 '^UCG_SSH_ROOT_PASS=' "$RAIZ/.env" | cut -d= -f2- | sed 's/#.*//' | tr -d ' "'"'"'\r'; }

abrir_mestre() {
  mkdir -p "$TMPD"; chmod 700 "$TMPD"
  printf '#!/bin/sh\nprintf "%%s\\n" "$UCG_PASS"\n' > "$ASKPASS"; chmod 700 "$ASKPASS"
  UCG_PASS="$(senha_gw)" SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  ssh -M -S "$CTL" -o ControlPersist=7200 -fN \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
      -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=8 \
      root@"$GATEWAY_A" </dev/null 2>/dev/null
}
gw()  { ssh -S "$CTL" -o ConnectTimeout=20 root@"$GATEWAY_A" "$@" </dev/null 2>/dev/null; }
gwr() { ssh -S "$CTL" -o ConnectTimeout=20 root@"$GATEWAY_A" "$@" </dev/null 2>&1; }
# A mesma coisa para a gw_b (mesma senha de root nas duas casas — medido
# 2026-09-18). O mestre morre junto com o tunel; `b_de_volta` o reabre.
abrir_mestre_b() {
  UCG_PASS="$(senha_gw)" SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  ssh -M -S "$CTL_B" -o ControlPersist=7200 -fN \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
      -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
      root@"$GATEWAY_B" </dev/null 2>/dev/null
}
gwb()    { ssh -S "$CTL_B" -o ConnectTimeout=20 root@"$GATEWAY_B" "$@" </dev/null 2>/dev/null; }
b_vivo() { [ -S "$CTL_B" ] && [ "$(gwb 'echo vivo' | tr -d '\r')" = "vivo" ]; }
# ⛔ O mestre morre com o tunel e deixa o SOCKET orfao; `ssh -M` com o arquivo
#    existente nao reabre ("ControlSocket already exists") e a coleta do lado B
#    desistiu depois de 5 min na corrida 2026-09-23 19:12 — com os dados
#    intactos no /tmp da gw_b. Socket morto se apaga antes de reabrir.
b_de_volta() { ssh -S "$CTL_B" -O check root@"$GATEWAY_B" >/dev/null 2>&1 || { rm -f "$CTL_B"; abrir_mestre_b; }; b_vivo; }
scp_b() { UCG_PASS="$(senha_gw)" SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
          scp -q -o ControlPath="$CTL_B" root@"$GATEWAY_B":"$1" "$2" 2>/dev/null; }

# ───────────────────────────────────────────────────────────── limpeza ─────
DIR=""
# ⛔ A LIMPEZA SO PODE AGIR NO QUE ESTA EXECUCAO LIGOU.
#    Medido 2026-09-19, e caro: o `trap limpar` rodava em QUALQUER saida,
#    inclusive a do `--ensaio`, e dava `pkill` em tcpdump e amostrador NO
#    GATEWAY. Um ensaio meu, rodado durante um teste real em andamento, matou
#    as capturas daquele teste — a corrida seguiu 25 min gravando nada e so
#    descobrimos no fim. `ARMADO` so vira 1 depois que ESTA execucao sobe as
#    capturas; antes disso a limpeza nao encosta no gateway.
ARMADO=0
ARMADO_B=0
limpar_b() {
  # So o que ESTA execucao ligou em B. Se o tunel estiver caido, B esta fora
  # de alcance — e tudo la tem `timeout`: morre sozinho, sem deixar rastro
  # rodando numa casa sem socorro fisico.
  # ⛔ `pkill -f` so com o NOME EXATO do script: um padrao curto como '[p]vb-'
  #    casa com qualquer `/tmp/pvb-*` na mesma linha de comando e mata o shell
  #    remoto (medido 2026-09-23).
  if [ "$ARMADO_B" = "1" ] && b_vivo; then
    gwb "pkill -x tcpdump >/dev/null 2>&1; pkill -f '[p]vb-amostra.sh' >/dev/null 2>&1; pkill -f '[p]vb-sonda-udp.sh' >/dev/null 2>&1" || true
  fi
  [ -S "$CTL_B" ] && ssh -S "$CTL_B" -O exit root@"$GATEWAY_B" >/dev/null 2>&1
  return 0
}
limpar() {
  local st=$?
  printf '\n'
  if [ "$ARMADO" = "0" ]; then
    # Nada foi ligado por esta execucao. Nao matar processo alheio, e nao
    # deixar diretorio de provas vazio para tras (o o autor chamou de sujeira,
    # com razao: pasta com 3 arquivos parece medicao e nao e).
    [ -n "$DIR" ] && [ ! -f "$DIR/eventos.log" ] && rm -rf "$DIR"
    [ -n "$DIR" ] && [ -f "$DIR/eventos.log" ] && ! grep -q "CABO PUXADO" "$DIR/eventos.log" 2>/dev/null && {
      rm -rf "$DIR"; aviso "nada foi medido (cabo nunca saiu) — diretorio de provas descartado"
    }
    limpar_b
    [ -S "$CTL" ] && ssh -S "$CTL" -O exit root@"$GATEWAY_A" >/dev/null 2>&1
    rm -rf "$TMPD"
    return 0
  fi
  limpar_b
  if [ -S "$CTL" ]; then
    # ⛔ `pkill -f 'tcpdump -i'` NAO: o padrao casa com a linha de comando do
    #    PROPRIO shell remoto (ela contem esse texto) e o mata antes de matar o
    #    tcpdump. Medido 2026-09-19. `-x` casa pelo NOME do executavel.
    #    E o `pkill -f amostra-gw` era o erro inverso: nunca casou com nada, o
    #    amostrador seguia rodando depois do aborto. Agora ele tem arquivo com
    #    nome proprio, e o colchete impede o auto-casamento.
    gw "pkill -x tcpdump >/dev/null 2>&1; pkill -f '[p]v-amostra.sh' >/dev/null 2>&1" || true
    ssh -S "$CTL" -O exit root@"$GATEWAY_A" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMPD"
  # Mesmo com as capturas ligadas: se o cabo nunca saiu, nao houve medicao.
  # Diretorio com linha de base e mais nada vira sujeira que parece prova.
  if [ -n "$DIR" ] && [ -f "$DIR/eventos.log" ] && ! grep -q "CABO PUXADO" "$DIR/eventos.log" 2>/dev/null; then
    rm -rf "$DIR"
    # Sem medicao, os arquivos no gateway tambem sao sujeira — e pior: a
    # proxima corrida herdaria pcap velho com cara de novo.
    gw "rm -f /tmp/pv-*" >/dev/null 2>&1
    [ "$ARMADO_B" = "1" ] && b_de_volta && gwb "rm -f /tmp/pvb-*" >/dev/null 2>&1
    aviso "nada foi medido (cabo nunca saiu) — provas e arquivos do gateway descartados"
    DIR=""
  fi
  [ "$st" -ne 0 ] && [ -n "$DIR" ] && aviso "saida com codigo $st — o que ja foi coletado esta em $DIR"
  return 0
}

# ⛔ TRAP DE INT/TERM TEM DE SAIR. Medido 2026-09-19, com o teste rodando e o
#    cabo ja fora: `trap limpar EXIT INT TERM`, com `limpar` terminando em
#    `return 0`, ENGOLIA o Ctrl-C — o bash rodava a limpeza e VOLTAVA para o
#    laco de espera. Ou seja: o operador nao conseguia abortar, e cada Ctrl-C
#    matava os tcpdump enquanto o script seguia esperando, achando que ainda
#    estava medindo. Um `exit` explicito resolve; sem ele, trap de sinal so
#    "passa por" a funcao.
# ⛔ ABORTAR NAO PODE DEPENDER DA REDE. Medido 2026-09-19: o trap disparava,
#    chamava a limpeza, e a limpeza ficava PENDURADA num `ssh` para o gateway —
#    resultado indistinguivel de "o Ctrl-C nao funciona", com os tcpdump vivos
#    do outro lado. Agora a limpeza roda com TETO e o aborto acontece de
#    qualquer jeito; um segundo Ctrl-C mata na hora, sem esperar nada.
LIMPO=0
abortar() {
  trap - INT TERM            # o proximo sinal e fatal, sem passar por aqui
  printf '\n'
  erro "abortado pelo operador — limpando (Ctrl-C de novo aborta a limpeza)"
  [ -n "${TAREFA_SONDA:-}" ] && [ "${SONDA_OK:-0}" = "1" ] && {
    aviso "parando a sonda na sonda (ela se restaura sozinha)"
    ( sonda_exec "schtasks /end /tn $TAREFA_SONDA" >/dev/null 2>&1
      sonda_destacar_limpar "$TAREFA_SONDA" ) &
  }
  ( limpar ) &
  local pl=$! i=0
  while kill -0 "$pl" 2>/dev/null && [ "$i" -lt 25 ]; do sleep 1; i=$((i+1)); done
  if kill -0 "$pl" 2>/dev/null; then
    kill -9 "$pl" 2>/dev/null
    aviso "a limpeza passou de 25 s e foi cortada — conferir o gateway com:"
    aviso "  ./scripts/ucg-ssh.sh $GATEWAY_A 'pgrep -c tcpdump'"
  fi
  LIMPO=1
  exit 130
}
limpar_saida() { [ "$LIMPO" = "1" ] && return 0; limpar; }
trap limpar_saida EXIT
trap abortar INT TERM

# ─────────────────────────────────────────── espera com teto, na tela ──────
# $1 teto(s)  $2 rotulo  $3.. comando que devolve 0 quando a condicao bateu
esperar_ate() {
  local teto="$1" rotulo="$2"; shift 2
  local t0 agora resto
  t0=$(date +%s)
  while :; do
    if "$@"; then printf '\r%-72s\r' ''; return 0; fi
    agora=$(date +%s); resto=$(( teto - (agora - t0) ))
    if [ "$resto" -le 0 ]; then printf '\r%-72s\r' ''; return 1; fi
    printf '\r  %s⏳ %s… (teto em %02d:%02d)%s' "$AMAR" "$rotulo" $((resto/60)) $((resto%60)) "$N"
    sleep 2
  done
}


# ────────────────────────────────────────── leituras do gateway ────────────
relogio_gw()   { gw 'date -Is' | tr -d '\r'; }
estado_fis()   { gw "cat /sys/class/net/$1/operstate 2>/dev/null" | tr -d '\r'; }
# 🔑 sem a mascara: este valor vai como alvo de ping para a sonda da sonda, e
#    "<WAN2-A>/24" nao e endereco que o Test-Connection aceite.
ip_de()        { gw "ip -4 -br a show $1 2>/dev/null | awk '{print \$3}'" | tr -d '\r' | cut -d/ -f1; }
peer_endpoint(){ gw "wg show $TUNEL endpoints 2>/dev/null | awk '{print \$2}'" | tr -d '\r'; }
handshake_ep() { gw "wg show $TUNEL latest-handshakes 2>/dev/null | awk '{print \$2}'" | tr -d '\r'; }
tunel_rxtx()   { gw "cat /sys/class/net/$TUNEL/statistics/rx_bytes /sys/class/net/$TUNEL/statistics/tx_bytes 2>/dev/null" | tr -d '\r' | paste -sd, -; }
saida_do_tunel(){ gw "ip route get ${1%%:*} 2>/dev/null | head -1 | sed -n 's/.*dev \([a-z0-9]*\).*/\1/p'" | tr -d '\r'; }

# eth fisico por tras de cada WAN — ppp0 roda SOBRE um ethernet, e quando o
# cabo sai e o ethernet que cai; o ppp0 apenas desaparece depois.
fisico_de() {
  case "$1" in
    ppp0) gw "awk 'NR>1{print \$3; exit}' /proc/net/pppoe 2>/dev/null" | tr -d '\r' ;;
    *)    echo "$1" ;;
  esac
}
porta_de() {   # ethX -> numero da porta impresso na caixa
  gw "cat /sys/class/net/$1/ifindex >/dev/null 2>&1" || { echo "?"; return; }
  case "$1" in eth0) echo 1;; eth1) echo 2;; eth2) echo 3;; eth3) echo 4;; eth4) echo 5;; *) echo "?";; esac
}

# ─────────────────────────────── o roteiro do navegador (v3) ───────────────
# Impresso no ensaio (para o operador achar os menus com o tunel de pe) e de
# novo logo depois do corte. Caminhos de menu como o o Product Lead de SD-WAN os descreveu em
# 24/09; se o painel estiver diferente, o operador adapta — o que importa e a
# interface certa, o filtro e o momento.
roteiro_painel() {
  printf '\n%s  ANTES DE PUXAR O CABO: 4 abas abertas, ja nas telas certas:%s\n' "$B" "$N"
  printf '    A1  https://%s   → UniFi Devices → gateway A → Overview → Packet Captures\n' "$GATEWAY_A"
  printf '    B1  https://unifi.ui.com → console da Casa B → UniFi Devices → gw_b → Overview → Packet Captures\n'
  printf '    A2  https://%s   → Settings → Support   (Download Support File)\n' "$GATEWAY_A"
  printf '    B2  https://unifi.ui.com → console da Casa B → Settings → Support\n'
  printf '\n%s  COM O CABO FORA — 4 tarefas, no 1o minuto, nesta ordem:%s\n\n' "$B" "$N"
  printf '  %s1) aba A1: Iniciar captura%s   interface %sWAN2 / ISP-2 (porta %s, %s)%s, duracao %s300 s%s (o maximo do painel; nao ha filtro)\n' "$B" "$N" "$B" "$PORTA_OUTRA" "$IF_OUTRA" "$N" "$B" "$N"
  printf '  %s2) aba B1: Iniciar captura%s   interface %sWAN (ISP do site B / PPPoE)%s, 300 s\n' "$B" "$N" "$B" "$N"
  printf '  %s3) aba A2: Download Support File%s   (comeca a gerar; ~6 min ate o arquivo cair)\n' "$B" "$N"
  printf '  %s4) aba B2: Download Support File%s   (AO MESMO TEMPO; a Casa B continua na nuvem)\n\n' "$B" "$N"
  printf '  %sQuando as capturas terminarem (5 min):%s baixe as duas. Se quiser uma segunda rodada,\n' "$B" "$N"
  printf '  inicie de novo nas abas A1/B1 por volta do minuto 8 e baixe ao terminar. Eu aceito\n'
  printf '  quantas houver; o minimo e uma por gateway.\n'
  printf '  %sTempo:%s gerar + baixar um support file leva ~6 min (medido). Dois em serie nao cabem\n' "$B" "$N"
  printf '  com folga nos %d min de janela; em PARALELO, iniciados no 1o minuto, terminam por volta\n' $((JANELA/60))
  printf '  do minuto 7 — com o cabo fora, como o o Product Lead de SD-WAN pediu ("before restoring WAN1").\n'
  printf '  %sSem filtro:%s a captura do painel leva 5 min do trafego da casa na WAN (destinos, DNS;\n' "$B" "$N"
  printf '  conteudo quase todo cifrado). Antes de anexar eu listo o que ha dentro e o o autor decide.\n'
  printf '  Tudo cai em ~/Downloads; eu detecto e REGISTRO no eventos.log a chegada de cada arquivo,\n'
  printf '  com o relogio do gateway — e o que prova que nasceram com a WAN1 fora.\n'
}
# Registra no eventos.log, UMA vez, cada arquivo novo do painel que aparece em
# Downloads (nome, tamanho, mtime do arquivo). Chamado a cada volta do laco.
PAINEL_VISTOS=""
registrar_novos_painel() {
  local f b
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    b="$(basename "$f")"
    case " $PAINEL_VISTOS " in *" $b "*) continue ;; esac
    PAINEL_VISTOS="$PAINEL_VISTOS $b"
    marcar "painel: chegou em Downloads $b ($(( $(stat -f %z "$f")/1024 )) KB, mtime $(date -r "$(stat -f %m "$f")" +%H:%M:%S)) — cabo ainda fora"
  done <<< "$(find -L "$DOWNLOADS" -maxdepth 1 -type f -newer "$MARCO_ARQ" \( \( -name 'support-*.tgz' -size +50k \) -o -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) 2>/dev/null)"
}
# quantos arquivos novos ha em Downloads desde a queda: "tgz=N(ids) pcap=M"
arquivos_painel() {
  local tgz pcap ids
  tgz="$(find -L "$DOWNLOADS" -maxdepth 1 -type f -newer "$MARCO_ARQ" -name 'support-*.tgz' -size +50k 2>/dev/null)"
  pcap="$(find -L "$DOWNLOADS" -maxdepth 1 -type f -newer "$MARCO_ARQ" \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) 2>/dev/null)"
  ids="$(printf '%s\n' "$tgz" | sed -n 's/.*support-\([A-Za-z0-9]*\)-.*/\1/p' | sort -u | tr '\n' ',' | sed 's/,$//')"
  N_TGZ=$(printf '%s\n' "$tgz" | grep -c .); N_TGZ_IDS=$(printf '%s' "$ids" | tr ',' '\n' | grep -c .)
  N_PCAP=$(printf '%s\n' "$pcap" | grep -c .)
  printf 'tgz=%s(%s) pcap=%s' "$N_TGZ" "${ids:-—}" "$N_PCAP"
}
painel_completo() { arquivos_painel >/dev/null; [ "${N_TGZ_IDS:-0}" -ge 2 ] && [ "${N_PCAP:-0}" -ge 2 ]; }

# ═══════════════════════════════════════════════════════ PRE-CONDICOES ═════
titulo "FAILOVER DO SITE MAGIC — teste guiado · ticket #5927426"

passo "pre-condicoes (nada comeca antes de tudo isto passar)"

for b in jq tcpdump git ssh scp; do
  command -v "$b" >/dev/null || { erro "falta '$b' no Mac"; exit 1; }
done
ok "ferramentas locais"

[ -f "$RAIZ/.env" ] || { erro ".env ausente"; exit 1; }
[ -n "$(senha_gw)" ] || { erro "UCG_SSH_ROOT_PASS vazia no .env"; exit 1; }

nc -z -G 5 "$GATEWAY_A" 22 >/dev/null 2>&1 || {
  erro "porta 22 do gw_a fechada — Console > Advanced > Device SSH"; exit 1; }
abrir_mestre
[ -S "$CTL" ] || { erro "SSH do gw_a nao autenticou (senha do .env desatualizada?)"; exit 1; }
[ "$(gw 'echo vivo')" = "vivo" ] || { erro "SSH do gw_a nao executa comando"; exit 1; }
ok "gw_a: uma sessao autenticada, multiplexada"

abrir_mestre_b
b_vivo || { erro "SSH da gw_b ($GATEWAY_B) nao respondeu — desde a v2 o lado B e parte do teste (pedido da Ubiquiti, 23/09)"; exit 1; }
ok "gw_b: uma sessao autenticada, multiplexada — pelo Site Magic (some na queda, volta com o tunel)"
for b in tcpdump timeout bash stat; do
  gwb "command -v $b >/dev/null" || { erro "falta '$b' na gw_b"; exit 1; }
done

RELOGIO="$(relogio_gw)"
ok "relogio do gateway (fonte unica de tempo): $RELOGIO"
# Os artefatos de B levam o relogio de B. O desvio entre os dois fica gravado
# para que ninguem precise supor que estao sincronizados.
DESVIO_AB=$(( $(gw 'date +%s' | tr -d '\r') - $(gwb 'date +%s' | tr -d '\r') ))
[ "${DESVIO_AB#-}" -le 2 ] && ok "relogio da gw_b: desvio de ${DESVIO_AB}s em relacao a gw_a" \
  || aviso "relogio da gw_b desviado ${DESVIO_AB}s da gw_a — os carimbos do lado B levam esse desvio"

EP="$(peer_endpoint)"
[ -n "$EP" ] || { erro "tunel $TUNEL sem endpoint — Site Magic esta de pe?"; exit 1; }
EP_IP="${EP%%:*}"
HS="$(handshake_ep)"
AGORA_EPOCH="$(gw 'date +%s' | tr -d '\r')"
IDADE_HS=$(( AGORA_EPOCH - ${HS:-0} ))
[ "${HS:-0}" -gt 0 ] && [ "$IDADE_HS" -lt 300 ] \
  && ok "tunel vivo (handshake ha ${IDADE_HS}s, peer $EP)" \
  || { erro "tunel sem handshake recente (${IDADE_HS}s) — nao da para testar queda de um tunel que ja esta caido"; exit 1; }

# ── o passo zero: POR ONDE O TUNEL SAI AGORA ────────────────────────────────
IF_SAIDA="$(saida_do_tunel "$EP_IP")"
[ -n "$IF_SAIDA" ] || { erro "nao consegui descobrir a interface de saida do tunel"; exit 1; }

# 🔑 POR ONDE A CASA B CHEGA — medido, nao assumido. O tunel e assimetrico
#    (A->B pela ISP-1, B->A pela ISP-2 em 2026-09-18) e isso pode mudar. Uma
#    captura curta em cada WAN, filtrada na ORIGEM do peer, diz qual delas
#    recebe os pacotes da Casa B agora. E o dado que decide o que --porta 4
#    esta testando.
# Filtrado na PORTA do Site Magic: a VPN de usuario da sonda (51820) chega pelo
# mesmo IP e pela ISP-2, e sem o filtro a resposta era "ambas" — errada.
# ⛔ Contar LINHAS do tcpdump nao e contar pacotes: em 2026-09-21 uma linha
#    espuria virou "Casa B chega por ambas" enquanto a captura da corrida
#    inteira tinha ZERO pacotes 20000 na eth3. Agora so conta linha que e
#    pacote (`> <ip>.20000: UDP`), e as linhas cruas ficam guardadas: numero
#    sem a evidencia ao lado nao entra em pacote de prova.
CHEGA_RAW="$(gw "for i in ppp0 eth3; do echo \"--- \$i ---\"; timeout 8 tcpdump -i \$i -c 8 -nn 'src host $EP_IP and udp port $PORTA_SM' 2>/dev/null; done")"
CHEGA_PPP0="$(printf '%s\n' "$CHEGA_RAW" | awk '/^--- ppp0/{f=1;next} /^--- eth3/{f=0} f && /\.'"$PORTA_SM"': UDP/' | wc -l | tr -d ' ')"
CHEGA_ETH3="$(printf '%s\n' "$CHEGA_RAW" | awk '/^--- eth3/{f=1;next} f && /\.'"$PORTA_SM"': UDP/' | wc -l | tr -d ' ')"
if [ "${CHEGA_ETH3:-0}" -gt 0 ] && [ "${CHEGA_PPP0:-0}" -eq 0 ]; then IF_CHEGADA=eth3
elif [ "${CHEGA_PPP0:-0}" -gt 0 ] && [ "${CHEGA_ETH3:-0}" -eq 0 ]; then IF_CHEGADA=ppp0
elif [ "${CHEGA_PPP0:-0}" -gt 0 ] && [ "${CHEGA_ETH3:-0}" -gt 0 ]; then IF_CHEGADA="ambas"
else IF_CHEGADA="nenhuma (sem pacote do peer em 6 s)"; fi

# O alvo do corte: a WAN de saida, salvo --porta.
IF_TUNEL="${ALVO_FLAG:-$IF_SAIDA}"
FIS_TUNEL="$(fisico_de "$IF_TUNEL")"
PORTA_TUNEL="$(porta_de "$FIS_TUNEL")"

# a outra WAN: a que sobrevive, e onde a prova acontece
IF_OUTRA=""; for c in ppp0 eth3; do [ "$c" != "$IF_TUNEL" ] && IF_OUTRA="$c"; done
FIS_OUTRA="$(fisico_de "$IF_OUTRA")"
PORTA_OUTRA="$(porta_de "$FIS_OUTRA")"
IP_TUNEL_WAN="$(ip_de "$IF_TUNEL")"; IP_OUTRA_WAN="$(ip_de "$IF_OUTRA")"

printf '\n  %s%-22s %-10s %-10s %-18s%s\n' "$B" "papel" "logica" "fisica" "ip publico" "$N"
printf '  %-22s %-10s %-10s %-18s\n' "ALVO DO CORTE"      "$IF_TUNEL" "$FIS_TUNEL (p$PORTA_TUNEL)" "${IP_TUNEL_WAN:-—}"
printf '  %-22s %-10s %-10s %-18s\n' "sobrevivente"       "$IF_OUTRA" "$FIS_OUTRA (p$PORTA_OUTRA)" "${IP_OUTRA_WAN:-—}"
printf '  %-22s %-10s\n' "tunel SAI por"    "$IF_SAIDA"
printf '  %-22s %-10s   (medido agora: ppp0=%s eth3=%s pacotes do peer)\n' "Casa B CHEGA por" "$IF_CHEGADA" "${CHEGA_PPP0:-0}" "${CHEGA_ETH3:-0}"
if [ "$IF_TUNEL" = "$IF_SAIDA" ]; then
  ok "o corte e na WAN de SAIDA do tunel: testa se a Casa A muda a saida"
else
  aviso "o corte NAO e na WAN de saida ($IF_SAIDA): testa se o tunel sobrevive perdendo a WAN de CHEGADA ($IF_CHEGADA)"
  aviso "a Casa B esta em CGNAT e e quem inicia — se ela perder o endereco por onde alcanca a Casa A, nao ha como descobrir o outro sozinha"
fi

# 🔑 O QUE B SABE DE A — o dado que a Ubiquiti pediu em 23/09. A nuvem
#    provisiona em B UM endpoint para A; se for o IP da WAN que vai cair, B nao
#    tem como tentar a sobrevivente, e "filtro da operadora de B" nem se poe.
EP_B_PROV="$(gwb "grep -h '^Endpoint' /run/wireguard_$TUNEL.*.config 2>/dev/null | head -1 | awk '{print \$3}'" | tr -d '\r')"
EP_B_APR="$(gwb "wg show $TUNEL endpoints 2>/dev/null | awk '{print \$2}'" | tr -d '\r')"
IF_WAN_B="$(gwb "ip route get $IP_OUTRA_WAN 2>/dev/null | head -1 | sed -n 's/.*dev \([a-z0-9]*\).*/\1/p'" | tr -d '\r')"
IP_WAN_B="$(gwb "ip -4 -br a show $IF_WAN_B 2>/dev/null | awk '{print \$3}'" | tr -d '\r' | cut -d/ -f1)"
[ -n "$IF_WAN_B" ] && [ -n "$IP_WAN_B" ] || { erro "nao consegui descobrir a WAN da gw_b (rota ate $IP_OUTRA_WAN)"; exit 1; }
case "${EP_B_PROV%%:*}" in
  "$IP_TUNEL_WAN") ROTULO_B="a WAN ALVO ($IF_TUNEL) — justamente a que vai cair" ;;
  "$IP_OUTRA_WAN") ROTULO_B="a WAN SOBREVIVENTE ($IF_OUTRA)" ;;
  *)               ROTULO_B="NENHUMA das WANs atuais de A (provisionamento defasado?)" ;;
esac
printf '  %-22s %-22s <- provisionado pela nuvem em B: %s\n' "Casa B conhece A por" "${EP_B_PROV:-?}" "$ROTULO_B"
printf '  %-22s %-22s    (B sai por %s = %s, CGNAT)\n' "B fala com A por" "${EP_B_APR:-?}" "$IF_WAN_B" "$IP_WAN_B"

[ -n "$IP_OUTRA_WAN" ] || { erro "a WAN sobrevivente esta sem IP — a precondicao da Ubiquiti nao esta satisfeita, o teste nao valeria"; exit 1; }
case "$IP_OUTRA_WAN" in
  10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*)
     aviso "IP da WAN sobrevivente ($IP_OUTRA_WAN) e PRIVADO/CGNAT — a Ubiquiti vai dizer que nao e publicamente alcancavel, e dessa vez com razao" ;;
  *) ok "WAN sobrevivente com IP publico ($IP_OUTRA_WAN) — precondicao deles satisfeita" ;;
esac

ESPACO="$(gw "df -k /tmp | awk 'NR==2{print \$4}'" | tr -d '\r')"
[ "${ESPACO:-0}" -gt 204800 ] && ok "espaco em /tmp do gateway: $((ESPACO/1024)) MB" \
  || { erro "menos de 200 MB em /tmp do gateway"; exit 1; }

if [ -n "$(cd "$RAIZ" && git status --porcelain)" ]; then
  aviso "o repo tem alteracoes nao commitadas — o commit final vai levar SO o diretorio de provas"
else
  ok "repo limpo"
fi

if [ "$ENSAIO" = "1" ]; then
  # O ensaio exercita o mecanismo do lado B de ponta a ponta, em 20 s, sem
  # cabo: arma (tcpdump + amostrador + 3 sondas UDP), colhe, apaga. E a captura
  # em A diz se as sondas CHEGARAM na WAN sobrevivente — a resposta a "a
  # operadora de B filtra UDP/20000" sai daqui, antes de qualquer corte.
  # ⛔ Sem `pkill` em A: um ensaio ja matou as capturas de um teste real
  #    (2026-09-19). Arquivos com nome proprio e `timeout` curto.
  passo "ensaio do lado B: arma 12 s, colhe, e confere se a sonda UDP de B chega na WAN sobrevivente de A"
  # ⛔ Matar por PIDFILE, nunca por `pkill -f <nome-do-arquivo>`: o padrao casa
  #    com o `rm -f /tmp/<nome>` da MESMA linha de comando remota e mata o shell
  #    antes de ler o pcap — "zero sondas chegaram" falso. Medido 2026-09-23,
  #    duas vezes na mesma hora.
  gw "nohup timeout 30 tcpdump -i $IF_OUTRA -s 128 -w /tmp/pv-ensaio-sondas-b.pcap 'udp port $PORTA_SM and $SONDA_BPF' >/dev/null 2>&1 &
      echo \$! > /tmp/pv-ensaio.pid; sleep 1; echo ok" >/dev/null
  gwb "rm -f /tmp/pvb-ensaio-*
       nohup timeout 20 tcpdump -i $IF_WAN_B -s 128 -w /tmp/pvb-ensaio-wan.pcap 'udp port $PORTA_SM' >/dev/null 2>&1 &
       ( for n in 1 2 3; do m=\"$SONDA_PREFIXO-ensaio-\$(date +%s)-\$n\"
           bash -c \"exec 3<>/dev/udp/$IP_OUTRA_WAN/$PORTA_SM; printf %s '\$m' >&3; exec 3>&-\" 2>/dev/null && r=enviada || r=FALHOU
           printf '%s %s %s -> $IP_OUTRA_WAN:$PORTA_SM\n' \"\$(date -Is)\" \"\$r\" \"\$m\"; sleep 2; done ) > /tmp/pvb-ensaio-sonda.log 2>&1 &
       sleep 12; pkill -x tcpdump; sleep 1
       echo \"pcap=\$(tcpdump -n -r /tmp/pvb-ensaio-wan.pcap 2>/dev/null | wc -l | tr -d ' ') sondas=\$(grep -c enviada /tmp/pvb-ensaio-sonda.log)\"
       rm -f /tmp/pvb-ensaio-*" > "$TMPD/ensaio-b" 2>&1
  ENS_B="$(tr -d '\r' < "$TMPD/ensaio-b" | tail -1)"
  sleep 3
  ENS_A="$(gw "kill \$(cat /tmp/pv-ensaio.pid 2>/dev/null) >/dev/null 2>&1; sleep 1; tcpdump -n -r /tmp/pv-ensaio-sondas-b.pcap 2>/dev/null | grep -c 'UDP'; rm -f /tmp/pv-ensaio-sondas-b.pcap /tmp/pv-ensaio.pid" | tr -d '\r' | tail -1)"
  ENS_PCAP="${ENS_B#pcap=}"; ENS_PCAP="${ENS_PCAP%% *}"; ENS_SONDAS="${ENS_B##*sondas=}"
  [ "${ENS_PCAP:-0}" -gt 0 ] && ok "gw_b: tcpdump destacado gravou ${ENS_PCAP} pacotes UDP $PORTA_SM em 12 s" \
    || { erro "gw_b: o tcpdump destacado NAO gravou nada em 12 s — nao rode o teste real ate isto passar"; exit 1; }
  [ "${ENS_SONDAS:-0}" -eq 3 ] && ok "gw_b: 3 sondas UDP enviadas para $IP_OUTRA_WAN:$PORTA_SM" \
    || { erro "gw_b: sondas UDP nao sairam (${ENS_SONDAS:-0} de 3)"; exit 1; }
  if [ "${ENS_A:-0}" -gt 0 ]; then
    ok "gw_a: ${ENS_A} sonda(s) de B CHEGARAM na $IF_OUTRA ($IP_OUTRA_WAN:$PORTA_SM) — a operadora de B NAO filtra UDP/$PORTA_SM ate aqui"
  else
    erro "gw_a: NENHUMA sonda de B chegou na $IF_OUTRA — ou a operadora de B filtra, ou a captura em A falhou. Investigar antes do teste real."
    exit 1
  fi
  [ -d "$DOWNLOADS" ] && [ -w "$DOWNLOADS" ] && ok "Downloads: $DOWNLOADS (e onde o painel vai deixar os arquivos)" \
    || { erro "Downloads inacessivel: $DOWNLOADS"; exit 1; }
  if [ "$PAINEL" = "1" ]; then
    passo "roteiro do navegador que o teste real vai pedir com o cabo fora — ache os menus AGORA, com o tunel de pe"
    roteiro_painel
  fi
  titulo "ENSAIO — nada foi tocado"
  printf '  O teste real mandaria puxar o cabo da %sPORTA %s (%s)%s.\n' "$B" "$PORTA_TUNEL" "$IF_TUNEL" "$N"
  printf '  Tunel sai por %s; Casa B chega por %s.\n' "$IF_SAIDA" "$IF_CHEGADA"
  printf '  A prova seria feita na porta %s (%s, %s).\n' "$PORTA_OUTRA" "$IF_OUTRA" "$IP_OUTRA_WAN"
  printf '  B conhece A por %s (%s).\n' "${EP_B_PROV:-?}" "$ROTULO_B"
  printf '  Janela: %s s. Rode sem --ensaio quando estiver na frente do rack.\n' "$JANELA"
  exit 0
fi

# ═══════════════════════════════════════════════════ PREPARO DA COLETA ═════
# O pacote de provas mora em teste_ubiquiti/: e o que vai para o ticket, e o
# o autor quer isso como arquivo no repo, nunca em /tmp (2026-09-19).
DIR="$RAIZ/teste_ubiquiti/failover-prova-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIR"
EVENTOS="$DIR/eventos.log"
marcar() { printf '%s  %s\n' "$(relogio_gw)" "$*" >> "$EVENTOS"; }

passo "linha de base (o estado completo, antes de qualquer corte)"
gw "echo '=== relogio ==='; date -Is
    echo; echo '=== WANs ==='; ip -br a show $IF_TUNEL; ip -br a show $IF_OUTRA
    echo; echo '=== tunel ==='; ip -br a show $TUNEL; wg show $TUNEL
    echo; echo '=== endpoint PROVISIONADO pelo daemon (vs. o aprendido acima) ==='; grep -h -E '^# peer|^Endpoint|Keepalive|ForcedHandshake' /run/wireguard_$TUNEL.*.config 2>/dev/null
    echo; echo '=== regras de politica (onde o tunel esta preso) ==='; ip rule show
    echo; echo '=== rota efetiva ate o peer ==='; ip route get $EP_IP
    echo; echo '=== tabelas de WAN ==='; ip route show table all 2>/dev/null | grep -E '201\.|202\.' | head -40" \
  > "$DIR/00-linha-de-base.txt" 2>&1
ok "linha de base ($(wc -l < "$DIR/00-linha-de-base.txt") linhas)"
{ echo "# por qual WAN o peer $EP_IP chega (UDP $PORTA_SM), 8 s por interface, antes do corte"
  echo "# relogio: $(relogio_gw)"; printf '%s\n' "$CHEGA_RAW"; } > "$DIR/00b-chegada-do-peer.txt"
ok "chegada do peer gravada (ppp0=$CHEGA_PPP0 eth3=$CHEGA_ETH3 pacotes) — linhas cruas em 00b"
gwb "echo '=== relogio (gw_b) ==='; date -Is; hostname
     echo; echo '=== WAN de B ==='; ip -br a show $IF_WAN_B
     echo; echo '=== tunel ==='; ip -br a show $TUNEL; wg show $TUNEL
     echo; echo '=== endpoint PROVISIONADO pela nuvem em B, para A (vs. o aprendido acima) ==='; stat -c '%y  %n' /run/wireguard_$TUNEL.*.config; grep -h -E '^# peer|^Endpoint|Keepalive|ForcedHandshake' /run/wireguard_$TUNEL.*.config 2>/dev/null
     echo; echo '=== regras de politica ==='; ip rule show
     echo; echo '=== rota de B ate cada WAN de A ==='; echo \"# WAN alvo $IP_TUNEL_WAN:\"; ip route get $IP_TUNEL_WAN; echo \"# WAN sobrevivente $IP_OUTRA_WAN:\"; ip route get $IP_OUTRA_WAN" \
  > "$DIR/00c-linha-de-base-casa-b.txt" 2>&1
ok "linha de base da Casa B ($(wc -l < "$DIR/00c-linha-de-base-casa-b.txt") linhas)"
marcar "SCRIPT sha256=$SCRIPT_SHA medicao=$MEDICAO_SHA git=$SCRIPT_GIT"
marcar "INICIO — alvo $IF_TUNEL ($FIS_TUNEL, porta $PORTA_TUNEL); tunel sai por $IF_SAIDA; Casa B chega por $IF_CHEGADA; peer $EP"
marcar "LADO B — provisionado em B para A: ${EP_B_PROV:-?} ($ROTULO_B); B sai por $IF_WAN_B=$IP_WAN_B; desvio de relogio A-B=${DESVIO_AB}s"

# 🔑 Qual tunel de usuario da sonda aponta para a WAN que vai SOBREVIVER.
#
# ⛔ NAO ESCOLHER PELO NOME. Ate 2026-09-19 este bloco assumia a convencao
#    "vpn->casa-a (ISP-1), vpn2->site-a-2 (ISP-2)" — e na maquina os dois
#    perfis estao CRUZADOS: `casa-a` aponta para `vpn2` e `site-a-2` para
#    `vpn`. Escolhendo pelo nome, a sonda subia justamente o tunel da WAN que
#    o teste derruba: ela cairia junto com o alvo e entregaria a Ubiquiti, de
#    bandeja, o argumento "sua WAN de backup nao estava alcancavel".
#    Medido: `ep=<WAN1-A>:51820` (ISP-1) num teste que pedia a ISP-2.
#
# ✅ Agora decide o ENDPOINT lido do proprio arquivo de configuracao, resolvido
#    e comparado com o IP da WAN sobrevivente. Funciona com os nomes como
#    estao, e continua funcionando se alguem arrumar os nomes depois.
TUNEL_SONDA=""; TUNEL_PADRAO=""
if sonda_abrir; then
  CONFS="$(sonda_ps "Get-ChildItem C:\homelab\*.conf | ForEach-Object { \$n=\$_.BaseName; (Select-String -Path \$_.FullName -Pattern '^\s*Endpoint' | ForEach-Object { \$n + '=' + (\$_.Line -split '=',2)[1].Trim() }) }" 2>/dev/null | tr -d '\r')"
  while IFS='=' read -r nome ep; do
    [ -n "$nome" ] && [ -n "$ep" ] || continue
    ip_ep="$(dig +short "${ep%%:*}" | tail -1)"
    [ -n "$ip_ep" ] || continue
    if [ "$ip_ep" = "$IP_OUTRA_WAN" ]; then TUNEL_SONDA="$nome"
    elif [ "$ip_ep" = "$IP_TUNEL_WAN" ]; then TUNEL_PADRAO="$nome"; fi
  done <<< "$CONFS"
fi
# ⚠️ `$TUNEL_PADRAO` e so o rotulo do OUTRO tunel (o da WAN que vai cair).
#    NAO e "o que sera restaurado": quem restaura e a sonda, e ela grava por
#    OBSERVACAO qual servico estava de pe no inicio. Os dois podem divergir —
#    quando a WAN sobrevivente ja e a padrao, a sonda sobe o que ja estava
#    ativo e o `$TUNEL_PADRAO` aponta para um servico parado. Imprimir isto
#    como "vai restaurar" foi texto errado meu, visto na tela em 2026-09-19.
if [ -z "$TUNEL_PADRAO" ]; then
  TUNEL_PADRAO="$(sonda_ps "(Get-Service 'WireGuardTunnel\$*' | Where-Object Status -eq 'Running' | Select-Object -First 1).Name -replace 'WireGuardTunnel\\\$',''" 2>/dev/null | tr -d '\r ')"
fi
RODANDO_AGORA="$(sonda_ps "(Get-Service 'WireGuardTunnel\$*' | Where-Object Status -eq 'Running' | Select-Object -First 1).Name -replace 'WireGuardTunnel\\\$',''" 2>/dev/null | tr -d '\r ')"
if [ -n "$TUNEL_SONDA" ]; then
  ok "tunel da sonda escolhido por endpoint: $TUNEL_SONDA -> $IP_OUTRA_WAN (sobrevivente)"
  ok "de pe na sonda agora: ${RODANDO_AGORA:-nenhum} — e este que a sonda devolve no fim"
else
  aviso "nenhum tunel da sonda aponta para a WAN sobrevivente ($IP_OUTRA_WAN) — sem testemunha externa"
  aviso "conferir os Endpoint em C:\\homelab\\*.conf; sondar a WAN errada e pior que nao sondar"
fi

passo "sonda externa na Casa B (a testemunha independente)"
printf '  Metodo: subir o tunel %s (aponta para a WAN sobrevivente) e medir\n' "${TUNEL_SONDA:-?}"
printf '  handshake + resposta TCP atraves dele durante a queda.\n'
printf '  %sNAO e ICMP%s: medido em 2026-09-18, ICMP da Casa B nao passa para\n' "$B" "$N"
printf '  nenhuma das duas WANs — daria "inalcancavel" nas duas e nao provaria nada.\n\n'
printf '  %sIsto MEXE na sonda%s: para o %s, sobe o %s e desabilita o watchdog,\n' "$B$AMAR" "$N" "$TUNEL_PADRAO" "$TUNEL_SONDA"
printf '  restaurando tudo no fim (inclusive se for morta no meio).\n'
printf '  Enter para seguir, Ctrl-C para abortar, ou "n" + Enter para rodar SEM a sonda: '
read -r RESP
if [ "$RESP" = "n" ] || [ "$RESP" = "N" ]; then TUNEL_SONDA=""; aviso "seguindo sem a testemunha externa"; fi
SONDA_OK=0
# ⛔ NADA de `nc -z` e nada de conexao propria: tudo pelo sonda-ssh.sh, que
#    mantem UMA sessao e serializa. Rajada aqui ja derrubou a porta 22.
if [ -n "$TUNEL_SONDA" ] && sonda_abrir; then
  # ⛔ A sonda restaura o watchdog ao estado em que o ENCONTROU. Encontrado
  #    Disabled (2026-09-19 17:03, causa nao identificada), ela o devolve
  #    Disabled — e a Casa B fica sem failover de tunel sem ninguem saber.
  #    Garantir Ready antes, e conferir de novo depois da coleta.
  WD_ANTES="$(sonda_ps '(Get-ScheduledTask homelab-wg-failover -EA SilentlyContinue).State' 2>/dev/null | tr -d '\r ')"
  if [ "$WD_ANTES" = "Disabled" ]; then
    sonda_ps 'Enable-ScheduledTask homelab-wg-failover | Out-Null' >/dev/null 2>&1
    aviso "watchdog da sonda estava DISABLED antes do teste — reabilitado (causa nao identificada; ver backlog)"
    marcar "watchdog da sonda encontrado Disabled e reabilitado antes da sonda"
  else
    ok "watchdog da sonda: ${WD_ANTES:-?}"
  fi
  if sonda_copia "$RAIZ/scripts/casab/sonda-failover-casab.ps1" \
                "C:/homelab/sonda-failover-casab.ps1"; then
    # A tarefa roda como SYSTEM: a sonda mexe em servico e em tarefa agendada,
    # o que exige elevacao. Nome proprio, /f para nao herdar sobra de execucao
    # anterior, e apagada na coleta.
    sonda_destacar \
      "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\homelab\\sonda-failover-casab.ps1 -Tunel $TUNEL_SONDA -TunelPadrao $TUNEL_PADRAO -Segundos $((JANELA+180))" \
      "$TAREFA_SONDA" && SONDA_OK=1
  fi
fi

# 🔑 `ssh` voltar 0 NAO prova que a sonda esta viva (foi assim que o mecanismo
#    antigo enganou). Confirmacao e o log existir e crescer na sonda.
if [ "$SONDA_OK" = "1" ]; then
  sleep 20
  LINHAS_SONDA="$(sonda_ps '(Get-Content C:\homelab\sonda-failover.log -EA SilentlyContinue | Measure-Object -Line).Lines' 2>/dev/null | tr -d '\r ')"
  if [ "${LINHAS_SONDA:-0}" -lt 9 ]; then
    SONDA_OK=0
    aviso "a sonda foi disparada mas NAO esta escrevendo (log com ${LINHAS_SONDA:-0} linhas) — seguindo sem ela"
    marcar "sonda externa disparada porem MUDA (log com ${LINHAS_SONDA:-0} linhas)"
  else
    ok "sonda CONFIRMADA viva na sonda (log com $LINHAS_SONDA linhas)"
  fi
fi
if [ "$SONDA_OK" = "1" ]; then
  ok "sonda disparada DESTACADA na sonda (sobrevive a queda do tunel)"
  marcar "sonda externa iniciada na Casa B"
else
  aviso "sonda inacessivel ou sshd recusando — segue SEM a testemunha externa"
  aviso "a prova fica mais fraca: a Ubiquiti pode alegar que a WAN sobrevivente nao era alcancavel de fora"
  marcar "sonda externa NAO iniciada (sonda fora)"
fi

passo "capturas nas duas WANs"
# ⛔ A captura geral NAO tem `-c`. Com `-c 5000` ela parava aos ~40 s — ANTES
#    do corte — e o RESUMO afirmava "N pacotes na sobrevivente no mesmo
#    periodo" com pacotes de antes da queda. Agora e limitada por TEMPO (o
#    timeout) e por snaplen curto; 15 min de cabecalhos cabem folgado.
#    (Este comentario fica FORA da string do gw: crase e parentese dentro de
#    aspas duplas quebram o bash — aconteceu em 2026-09-19.)
gw "pkill -x tcpdump >/dev/null 2>&1
    nohup timeout $((JANELA+1200)) tcpdump -i $IF_TUNEL  -s 128 -w /tmp/pv-alvo-tunel.pcap  'host $EP_IP and udp port $PORTA_SM' >/dev/null 2>&1 &
    nohup timeout $((JANELA+1200)) tcpdump -i $IF_OUTRA  -s 128 -w /tmp/pv-outra-tunel.pcap 'host $EP_IP and udp port $PORTA_SM' >/dev/null 2>&1 &
    nohup timeout $((JANELA+1200)) tcpdump -i $IF_OUTRA  -s 64 -w /tmp/pv-outra-geral.pcap 'not (host $EP_IP and udp)' >/dev/null 2>&1 &
    nohup timeout $((JANELA+1200)) tcpdump -i $FIS_TUNEL -s 128 -w /tmp/pv-alvo-fisico.pcap >/dev/null 2>&1 &
    sleep 3; pgrep -c tcpdump"  > "$TMPD/tcpd" 2>&1
N_TCPD="$(tr -d '\r' < "$TMPD/tcpd" | tail -1)"
# 🔑 CONFIRMAR, NAO SUPOR. Ate 2026-09-19 esta linha so imprimia o numero — e
#    quando ele era ZERO (pkill matando o proprio shell) o teste seguia alegre
#    ate o fim, entregando um pacote de provas SEM AS CAPTURAS, que sao o corpo
#    da prova. Agora: sem captura gravando, nao ha teste.
ARQ_PCAP="$(gw "ls /tmp/pv-*.pcap 2>/dev/null | wc -l" | tr -d '\r ')"
if [ "${N_TCPD:-0}" -lt 3 ] || [ "${ARQ_PCAP:-0}" -lt 3 ]; then
  erro "capturas NAO subiram (processos=${N_TCPD:-0}, arquivos=${ARQ_PCAP:-0}) — sem elas o teste nao prova nada"
  erro "abortando antes de te fazer puxar cabo a toa"
  marcar "ABORTADO — tcpdump nao subiu no gateway"
  exit 1
fi
ARMADO=1   # a partir daqui a limpeza pode agir: os processos sao desta execucao
ok "tcpdump ativo ($N_TCPD processos, $ARQ_PCAP arquivos abertos)"
ok "  alvo  : $IF_TUNEL  filtrado no peer $EP_IP"
ok "  outra : $IF_OUTRA  filtrado no peer + captura geral (prova de que estava viva)"

passo "amostrador no gateway (2 em 2 s, relogio dele)"
gw "cat > /tmp/pv-amostra.sh <<'FIMAMOSTRA'
for i in \$(seq 1 $(( (JANELA+1200)/2 ))); do
      printf \"%s alvo=%s/%s outra=%s/%s tunel=%s rx=%s tx=%s hs=%s rota=%s\n\" \
        \"\$(date -Is)\" \
        \"\$(cat /sys/class/net/$FIS_TUNEL/operstate 2>/dev/null)\" \
        \"\$(ip -4 -br a show $IF_TUNEL 2>/dev/null | awk \"{print \\\$3}\")\" \
        \"\$(cat /sys/class/net/$FIS_OUTRA/operstate 2>/dev/null)\" \
        \"\$(ip -4 -br a show $IF_OUTRA 2>/dev/null | awk \"{print \\\$3}\")\" \
        \"\$(cat /sys/class/net/$TUNEL/operstate 2>/dev/null)\" \
        \"\$(cat /sys/class/net/$TUNEL/statistics/rx_bytes 2>/dev/null)\" \
        \"\$(cat /sys/class/net/$TUNEL/statistics/tx_bytes 2>/dev/null)\" \
        \"\$(wg show $TUNEL latest-handshakes 2>/dev/null | awk \"{print \\\$2}\")\" \
        \"\$(ip route get $EP_IP 2>/dev/null | head -1 | sed -n \"s/.*dev \\([a-z0-9]*\\).*/\\1/p\")\"
      sleep 2; done
FIMAMOSTRA
    nohup sh /tmp/pv-amostra.sh > /tmp/pv-amostra.log 2>&1 & echo ok" >/dev/null
ok "amostrador rodando"

passo "lado B: captura na WAN da gw_b + amostrador + sonda UDP (destacados, com teto — B some na queda)"
# Tres processos em B, todos com `timeout`, porque depois do corte ninguem
# alcanca B para mata-los. O que cada um prova:
#   pvb-wan.pcap        tudo que B troca com QUALQUER endereco de A e todo UDP
#                       20000: iniciacoes de handshake B->WAN1 (morta) e
#                       B->WAN2 contam-se dai;
#   pvb-amostra.log     de 2 em 2 s: mtime e Endpoint da config provisionada
#                       (a nuvem reprovisiona B com a WAN2 durante a queda?),
#                       endpoint aprendido, handshake, rotas ate as WANs de A;
#   pvb-sonda-udp.log   a sonda UDP para a WAN2 de A a cada 30 s (chegada
#                       conta-se na captura de A).
gwb "pkill -x tcpdump >/dev/null 2>&1; rm -f /tmp/pvb-*
     nohup timeout $((JANELA+1200)) tcpdump -i $IF_WAN_B -s 128 -w /tmp/pvb-wan.pcap 'udp port $PORTA_SM or host $IP_OUTRA_WAN or host $IP_TUNEL_WAN' >/dev/null 2>&1 &
     cat > /tmp/pvb-amostra.sh <<'FIMB'
for i in \$(seq 1 $(( (JANELA+1200)/2 ))); do
  printf \"%s wan=%s/%s cfg_mtime=%s prov=%s apr=%s hs=%s rx=%s tx=%s rota_alvo=%s rota_sobrev=%s\n\" \
    \"\$(date -Is)\" \
    \"\$(cat /sys/class/net/$IF_WAN_B/operstate 2>/dev/null)\" \
    \"\$(ip -4 -br a show $IF_WAN_B 2>/dev/null | awk \"{print \\\$3}\")\" \
    \"\$(stat -c %Y /run/wireguard_$TUNEL.*.config 2>/dev/null | head -1)\" \
    \"\$(grep -h '^Endpoint' /run/wireguard_$TUNEL.*.config 2>/dev/null | head -1 | awk \"{print \\\$3}\")\" \
    \"\$(wg show $TUNEL endpoints 2>/dev/null | awk \"{print \\\$2}\")\" \
    \"\$(wg show $TUNEL latest-handshakes 2>/dev/null | awk \"{print \\\$2}\")\" \
    \"\$(cat /sys/class/net/$TUNEL/statistics/rx_bytes 2>/dev/null)\" \
    \"\$(cat /sys/class/net/$TUNEL/statistics/tx_bytes 2>/dev/null)\" \
    \"\$(ip route get $IP_TUNEL_WAN 2>/dev/null | head -1 | sed -n \"s/.*dev \\([a-z0-9]*\\).*/\\1/p\")\" \
    \"\$(ip route get $IP_OUTRA_WAN 2>/dev/null | head -1 | sed -n \"s/.*dev \\([a-z0-9]*\\).*/\\1/p\")\"
  sleep 2; done
FIMB
     cat > /tmp/pvb-sonda-udp.sh <<'FIMS'
n=0
while [ \$n -lt $(( (JANELA+1200)/SONDA_UDP_PASSO )) ]; do
  n=\$((n+1)); m=\"$SONDA_PREFIXO-\$(date +%s)-\$n\"
  bash -c \"exec 3<>/dev/udp/$IP_OUTRA_WAN/$PORTA_SM; printf %s '\$m' >&3; exec 3>&-\" 2>/dev/null && r=enviada || r=FALHOU
  printf '%s %s %s -> $IP_OUTRA_WAN:$PORTA_SM\n' \"\$(date -Is)\" \"\$r\" \"\$m\"
  sleep $SONDA_UDP_PASSO
done
echo \"# fim=\$(date -Is)\"
FIMS
     nohup sh /tmp/pvb-amostra.sh > /tmp/pvb-amostra.log 2>&1 &
     nohup sh /tmp/pvb-sonda-udp.sh > /tmp/pvb-sonda-udp.log 2>&1 &
     sleep 4; echo \"tcpd=\$(pgrep -c tcpdump) arq=\$(ls /tmp/pvb-wan.pcap /tmp/pvb-amostra.log /tmp/pvb-sonda-udp.log 2>/dev/null | wc -l | tr -d ' ') linhas=\$(wc -l < /tmp/pvb-amostra.log) sondas=\$(grep -c enviada /tmp/pvb-sonda-udp.log)\"" \
  > "$TMPD/armado-b" 2>&1
ARM_B="$(tr -d '\r' < "$TMPD/armado-b" | tail -1)"
B_TCPD="$(printf '%s' "$ARM_B" | sed -n 's/.*tcpd=\([0-9]*\).*/\1/p')"; B_ARQ="$(printf '%s' "$ARM_B" | sed -n 's/.*arq=\([0-9]*\).*/\1/p')"
B_LIN="$(printf '%s' "$ARM_B" | sed -n 's/.*linhas=\([0-9]*\).*/\1/p')"; B_SND="$(printf '%s' "$ARM_B" | sed -n 's/.*sondas=\([0-9]*\).*/\1/p')"
# Mesma regra do lado A: sem confirmar que esta gravando, nao ha teste.
if [ "${B_TCPD:-0}" -lt 1 ] || [ "${B_ARQ:-0}" -lt 3 ] || [ "${B_LIN:-0}" -lt 1 ] || [ "${B_SND:-0}" -lt 1 ]; then
  erro "lado B NAO armou (tcpdump=${B_TCPD:-0} arquivos=${B_ARQ:-0} amostras=${B_LIN:-0} sondas=${B_SND:-0}) — abortando antes do cabo"
  marcar "ABORTADO — lado B nao armou: $ARM_B"
  exit 1
fi
ARMADO_B=1
ok "gw_b: tcpdump ($B_TCPD) na $IF_WAN_B, amostrador ($B_LIN linhas) e sonda UDP ($B_SND enviada) — tudo com teto de $((JANELA+1200))s"
marcar "lado B armado: captura na $IF_WAN_B, amostrador 2 s, sonda UDP a cada ${SONDA_UDP_PASSO}s para $IP_OUTRA_WAN:$PORTA_SM"

# ═════════════════════════════════════════════════════ PASSO 1 · CABO ══════
acao "PUXE O CABO DA PORTA $PORTA_TUNEL  ($IF_TUNEL)"
printf '  E a WAN por onde o tunel esta saindo AGORA (conferido nesta execucao).\n'
printf '  A outra ponta (porta %s, %s) fica de pe: e nela que a prova acontece.\n' "$PORTA_OUTRA" "$IP_OUTRA_WAN"

caiu() { [ "$(estado_fis "$FIS_TUNEL")" = "down" ]; }
if ! esperar_ate "$TETO_CABO" "esperando o cabo sair da porta $PORTA_TUNEL" caiu; then
  erro "teto de $((TETO_CABO/60)) min sem o cabo sair. Abortando limpo."
  marcar "ABORTADO — cabo nao foi puxado dentro do teto"
  exit 1
fi
T_QUEDA="$(relogio_gw)"; T_QUEDA_EPOCH="$(gw 'date +%s' | tr -d '\r')"
# O HANDSHAKE DE ANTES DA QUEDA. Tudo depende dele: so conta como tunel
# restabelecido um handshake com carimbo MAIOR que este.
HS_ANTES="$(handshake_ep)"; HS_ANTES="${HS_ANTES:-0}"
ok "CABO FORA detectado — $T_QUEDA"
marcar "CABO PUXADO da porta $PORTA_TUNEL ($FIS_TUNEL operstate=down)"
gw "echo '=== no instante da queda ==='; date -Is; ip rule show; echo; ip route get $EP_IP 2>&1; echo; ip -br a" \
  > "$DIR/01-instante-da-queda.txt" 2>&1
ok "estado de rotas/regras no instante da queda gravado"

# 🔑 QUANDO O SUPPORT FILE E PEDIDO
#    Nao no fim da janela (o operador ficava 15-30 min parado e perdeu a janela
#    de download duas vezes em 2026-09-19), e nem imediatamente na queda — o
#    arquivo seria gerado ANTES do momento interessante. O gatilho e por
#    EVENTO, decidido dentro do laco de observacao:
#      - assim que MIGRAR (o arquivo passa a conter a migracao), ou
#      - aos 180 s sem migrar (a ausencia de migracao ja e o fato a documentar).
#    O relogio de deteccao (MARCO) e o da QUEDA, nao o do pedido: assim um
#    download adiantado tambem conta.
MARCO=$T_QUEDA_EPOCH
# ⛔ NAO USAR `find -newermt "@$MARCO"`. O find do macOS (BSD) NAO aceita
#    `@epoch` — responde "Can't parse date/time" — e o `2>/dev/null` do script
#    engolia o erro, virando "nenhum arquivo" para sempre. Descoberto em
#    2026-09-19 depois de UM DIA de deteccao falhando: todo teste "manual" meu
#    tinha passado porque o shell da ferramenta de edicao embrulha `find` num
#    binario compativel com GNU. Validar comando de script no shell errado e o
#    mesmo erro do `/dev/tcp` no zsh. Arquivo-marcador com `-newer` funciona
#    nos dois finds.
MARCO_ARQ="$TMPD/marco-queda"
touch -t "$(date -r "$MARCO" +%Y%m%d%H%M.%S 2>/dev/null || date -d "@$MARCO" +%Y%m%d%H%M.%S)" "$MARCO_ARQ"
N_TGZ=0; N_TGZ_IDS=0; N_PCAP=0

# O ROTEIRO SAI AGORA, no comeco, e o operador trabalha enquanto a janela
# corre. Historico: pedir no FIM da janela perdeu o download duas vezes em
# 2026-09-19; decisao do o autor: no comeco. Na v3 sao 4 tarefas (capturas pelo
# painel nos dois gateways + support file dos dois consoles), e a coleta so
# libera o cabo depois de ve-las em Downloads.
if [ "$PAINEL" = "1" ]; then
  acao "NO NAVEGADOR: 2 CAPTURAS + 2 SUPPORT FILES (o cabo acabou de sair)"
  roteiro_painel
  marcar "roteiro do painel entregue ao operador (2 capturas udp/$PORTA_SM + 2 support files, com o cabo fora)"
fi

# ══════════════════════════════════════════ PASSO 2 · JANELA DE OBSERVACAO ═
passo "janela de observacao: $((JANELA/60)) min"
printf '  %sA pergunta: o tunel migra para a porta %s sozinho?%s\n\n' "$B" "$PORTA_OUTRA" "$N"
FIM=$(( $(date +%s) + JANELA ))
MIGROU=0; ROTA_MIGRADA=""
T_ROTA=""      # segundos ate a ROTA sair pela outra WAN
T_TUNEL=""     # segundos ate o PRIMEIRO handshake posterior a queda
HS_CONTA=0     # handshakes novos durante a queda - prova que sustentou
HS_ULTIMO=0
ULTIMA_ROTA=""; TROCAS=0; ITER=0
while [ "$(date +%s)" -lt "$FIM" ]; do
  RESTO=$(( FIM - $(date +%s) ))
  ROTA_AGORA="$(saida_do_tunel "$EP_IP")"
  HS_AGORA="$(handshake_ep)"; EP_AGORA="$(gw "date +%s" | tr -d '\r')"
  IDADE=$(( EP_AGORA - ${HS_AGORA:-0} ))
  # ROTA MIGRAR NAO E TUNEL MIGRAR. Ate 2026-09-19 este bloco declarava
  # "MIGROU" quando a rota mudava E o handshake tinha menos de 180 s - e um
  # handshake de ANTES da queda satisfaz isso por ate 3 minutos. Medido na
  # corrida das 11:18: rotulo "MIGROU aos 31s" com o ultimo handshake datando
  # de antes do cabo sair, ou seja, rota na WAN nova e tunel MORTO. Rotulo
  # mentiroso em dossie e pior que rotulo ausente.
  #
  # Agora sao DOIS fatos, medidos e relatados separadamente:
  #   T_ROTA  - quando `ip route get` passou a sair pela outra WAN
  #   T_TUNEL - quando houve o PRIMEIRO handshake com carimbo POSTERIOR a
  #             queda, unica prova de que o tunel voltou a falar
  #
  # A janela segue ate o fim mesmo depois de restabelecer: interessa a CURVA
  # (quando voltou, se FICOU, se reverteu), nao o primeiro evento.
  HS_NOVO=0
  [ -n "$HS_AGORA" ] && [ "${HS_AGORA:-0}" -gt "${HS_ANTES:-0}" ] && HS_NOVO=1

  if [ -z "$T_ROTA" ] && [ -n "$ROTA_AGORA" ] && [ "$ROTA_AGORA" != "$IF_TUNEL" ]; then
    T_ROTA=$(( EP_AGORA - T_QUEDA_EPOCH ))
    printf '\r%-78s\r' ''
    ok "ROTA migrou aos ${T_ROTA}s - saida passou a ser $ROTA_AGORA"
    [ -z "$T_TUNEL" ] && aviso "isto ainda NAO e o tunel: falta handshake com carimbo posterior a queda"
    marcar "ROTA migrou para $ROTA_AGORA apos ${T_ROTA}s (sem handshake novo ainda)"
    ROTA_MIGRADA="$ROTA_AGORA"
  fi

  if [ "$HS_NOVO" = "1" ]; then
    [ "${HS_AGORA:-0}" != "${HS_ULTIMO:-0}" ] && HS_CONTA=$((HS_CONTA+1))
    HS_ULTIMO="$HS_AGORA"
    if [ -z "$T_TUNEL" ]; then
      T_TUNEL=$(( EP_AGORA - T_QUEDA_EPOCH ))
      printf '\r%-78s\r' ''
      ok "TUNEL RESTABELECIDO aos ${T_TUNEL}s - handshake novo por ${ROTA_AGORA:-?}"
      marcar "TUNEL restabelecido apos ${T_TUNEL}s, saindo por ${ROTA_AGORA:-?} (handshake posterior a queda)"
      MIGROU=1
    fi
  fi

  # Reversao so existe DEPOIS de a rota ter migrado. Sem esta guarda, quando o
  # handshake volta ANTES de a rota trocar (medido na corrida 09:32: tunel aos
  # 28 s, rota aos 36 s) o ramo abaixo disparava com a rota ainda na WAN alvo
  # e carimbava um "REVERTEU" falso. Pego pelo harness do laco, 2026-09-19.
  if [ "$MIGROU" = "1" ] && [ -n "$T_ROTA" ] && [ -n "$ROTA_AGORA" ] && [ "$ROTA_AGORA" = "$IF_TUNEL" ]; then
    printf '\r%-78s\r' ''
    aviso "VOLTOU para $IF_TUNEL aos $(( EP_AGORA - T_QUEDA_EPOCH ))s"
    marcar "REVERTEU para $IF_TUNEL apos $(( EP_AGORA - T_QUEDA_EPOCH ))s"
    MIGROU=2
  fi
  if [ -n "$ROTA_AGORA" ] && [ -n "$ULTIMA_ROTA" ] && [ "$ROTA_AGORA" != "$ULTIMA_ROTA" ]; then
    TROCAS=$((TROCAS+1))
    marcar "troca de rota #$TROCAS: $ULTIMA_ROTA -> $ROTA_AGORA aos $(( EP_AGORA - T_QUEDA_EPOCH ))s"
  fi
  [ -n "$ROTA_AGORA" ] && ULTIMA_ROTA="$ROTA_AGORA"
  # deteccao oportunista, sem travar o laco: uma olhada a cada ~30 s
  # SEM SONDAGEM DE SUPPORT FILE AQUI, DE PROPOSITO. Duas versoes tentaram
  # detectar durante a janela e as duas falharam em producao: a primeira com
  # gate de relogio (`epoch % 30 < 5`) que, com volta de laco de ~6 s, tem
  # fase em que nunca dispara; a segunda continuou sem achar arquivo que o
  # `find` da linha de comando encontrava. Sondagem dentro do laco so
  # atrapalha a medicao. O arquivo e recolhido UMA vez, ao coletar - varredura
  # deterministica, sem laco e sem fase.
  [ "$PAINEL" = "1" ] && registrar_novos_painel
  printf '\r  %s⏱ %02d:%02d restantes (cabo fora ha %02d:%02d) │ rota=%s │ hs novo: %s │ tunel: %s │ downloads: %s%s' \
    "$AZUL" $((RESTO/60)) $((RESTO%60)) $(( (EP_AGORA - T_QUEDA_EPOCH)/60 )) $(( (EP_AGORA - T_QUEDA_EPOCH)%60 )) "${ROTA_AGORA:-—}" \
    "$([ "$HS_NOVO" = "1" ] && echo "SIM (${HS_CONTA})" || echo NAO)" \
    "$([ -n "$T_TUNEL" ] && echo "de pe desde ${T_TUNEL}s" || echo "CAIDO desde a queda")" \
    "$([ "$PAINEL" = "1" ] && arquivos_painel || echo "—")" "$N"
  sleep 5
done
printf '\r%-78s\r' ''
if [ "$MIGROU" = "0" ]; then
  if [ -n "$T_ROTA" ]; then
    aviso "a ROTA migrou aos ${T_ROTA}s, mas o TUNEL nao voltou em $((JANELA))s"
    aviso "rota na WAN sobrevivente com tunel morto — e este o resultado que o ticket afirma"
  else
    aviso "nem a rota nem o tunel migraram em $((JANELA))s"
  fi
  marcar "SEM MIGRACAO ate o fim da janela de ${JANELA}s"
fi

# ═══════════════════════════ PASSO 3 · SUPPORT FILES E CAPTURAS DO PAINEL ═══
# O cabo continua FORA aqui, de proposito: o o Product Lead de SD-WAN pediu tudo "before
# restoring WAN1". O operador para as capturas e baixa os arquivos; o script
# espera ve-los em Downloads (2 support-*.tgz de consoles DIFERENTES + 2
# capturas), com teto, e Enter segue com o que houver.
PAINEL_ARQS=""
if [ "$PAINEL" = "0" ]; then
  aviso "corrida sem painel (--sem-painel): sem support files nem capturas do painel"
  marcar "painel nao solicitado nesta corrida"
else
  acao "PARE AS 2 CAPTURAS NO PAINEL E BAIXE OS ARQUIVOS — cabo ainda FORA"
  printf '  gw_a e gw_b: Packet Captures → Parar → Baixar. Se ainda falta support file,\n'
  printf '  baixe agora. Espero ate %d min; %sEnter%s segue com o que ja houver.\n' $((TETO_PAINEL/60)) "$B" "$N"
  marcar "fim da janela: operador instruido a parar as capturas do painel e baixar (cabo ainda fora); ate aqui: $(arquivos_painel)"
  T0P=$(date +%s)
  while :; do
    registrar_novos_painel
    if painel_completo; then printf '\r%-78s\r' ''; ok "painel completo: $(arquivos_painel)"; break; fi
    RESTOP=$(( TETO_PAINEL - ( $(date +%s) - T0P ) ))
    if [ "$RESTOP" -le 0 ]; then printf '\r%-78s\r' ''; aviso "teto de $((TETO_PAINEL/60)) min — seguindo com o que ha: $(arquivos_painel)"; break; fi
    printf '\r  %s⏳ esperando os arquivos do painel: %s (teto em %02d:%02d, Enter segue)%s' "$AMAR" "$(arquivos_painel)" $((RESTOP/60)) $((RESTOP%60)) "$N"
    if read -r -t 2 _; then printf '\r%-78s\r' ''; aviso "seguindo por ordem do operador com: $(arquivos_painel)"; break; fi
  done
  # Copia TUDO que e novo e relevante — nao so o mais novo. Support files ficam
  # no pacote (gitignored: podem conter segredo) com hash no manifesto; as
  # capturas do painel ganham o prefixo painel- para nao se confundirem com as
  # do tcpdump.
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    cp "$f" "$DIR/" && PAINEL_ARQS="$PAINEL_ARQS $(basename "$f")" \
      && ok "support file: $(basename "$f") ($(( $(stat -f %z "$f")/1024/1024 )) MB)"
  done <<< "$(find -L "$DOWNLOADS" -maxdepth 1 -type f -newer "$MARCO_ARQ" -name 'support-*.tgz' -size +50k 2>/dev/null)"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    cp "$f" "$DIR/painel-$(basename "$f")" && PAINEL_ARQS="$PAINEL_ARQS painel-$(basename "$f")" \
      && ok "captura do painel: painel-$(basename "$f") ($(( $(stat -f %z "$f")/1024 )) KB)"
  done <<< "$(find -L "$DOWNLOADS" -maxdepth 1 -type f -newer "$MARCO_ARQ" \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) 2>/dev/null)"
  if [ -n "$PAINEL_ARQS" ]; then
    marcar "painel coletado com o cabo fora:$PAINEL_ARQS"
  else
    aviso "nenhum arquivo do painel em $DOWNLOADS desde a queda — o pacote segue sem eles"
    marcar "painel NAO coletado (nenhum arquivo novo em Downloads)"
  fi
  [ "${N_TGZ_IDS:-0}" -lt 2 ] && aviso "support files de $N_TGZ_IDS console(s) — o o Product Lead de SD-WAN pediu os DOIS no mesmo instante de falha"
  [ "${N_PCAP:-0}" -lt 2 ] && aviso "capturas do painel: $N_PCAP — o pedido era uma por gateway"
fi

# ═══════════════════════════════════════════ PASSO 4 · RECONECTAR ══════════
acao "RECONECTE O CABO NA PORTA $PORTA_TUNEL"
voltou() { [ "$(estado_fis "$FIS_TUNEL")" = "up" ] && [ -n "$(ip_de "$IF_TUNEL")" ]; }
if esperar_ate "$TETO_CABO" "esperando o cabo voltar" voltou; then
  T_VOLTA_EPOCH="$(gw 'date +%s' | tr -d '\r')"
  ok "CABO DE VOLTA — $(relogio_gw) ($(( T_VOLTA_EPOCH - T_QUEDA_EPOCH ))s fora)"
  marcar "CABO RECONECTADO apos $(( T_VOLTA_EPOCH - T_QUEDA_EPOCH ))s de queda"
  tunel_voltou() {
    local h a; h="$(handshake_ep)"; a="$(gw 'date +%s' | tr -d '\r')"
    [ -n "$h" ] && [ "$h" -gt 0 ] && [ $(( a - h )) -lt 90 ]
  }
  if esperar_ate 300 "esperando o tunel refazer o handshake" tunel_voltou; then
    # ⛔ NAO reusar T_TUNEL aqui. Ate 2026-09-19 esta variavel era a mesma da
    #    janela de observacao ("segundos ate o primeiro handshake novo durante
    #    a queda"); este passo a sobrescrevia com um EPOCH depois do cabo
    #    voltar, e o RESUMO da corrida 17:02 saiu com "tunel voltou: SIM, aos
    #    1789849293s" numa corrida em que o tunel NAO voltou. Pego lendo o
    #    RESUMO gerado — o harness do laco nao cobre este passo.
    T_TUNEL_VOLTA="$(gw 'date +%s' | tr -d '\r')"
    ok "TUNEL DE VOLTA — $(( T_TUNEL_VOLTA - T_VOLTA_EPOCH ))s depois do cabo"
    marcar "TUNEL RESTABELECIDO $(( T_TUNEL_VOLTA - T_VOLTA_EPOCH ))s apos o cabo voltar, saindo por $(saida_do_tunel "$EP_IP")"
  else
    aviso "tunel nao refez handshake em 5 min apos o cabo voltar"
    marcar "tunel NAO restabelecido em 300s apos o cabo voltar"
  fi
else
  aviso "cabo nao voltou dentro do teto — coletando assim mesmo"
  marcar "cabo NAO reconectado dentro do teto"
fi

# ══════════════════════════════════════════════════════ COLETA E ANALISE ═══
passo "parando capturas e coletando"
gw "pkill -x tcpdump; pkill -f '[p]v-amostra.sh'; sleep 2; ls -l /tmp/pv-*.pcap" > "$DIR/pcaps-no-gateway.txt" 2>&1
gw "cat /tmp/pv-amostra.log" > "$DIR/02-amostra-gateway.log" 2>/dev/null
ok "amostrador: $(wc -l < "$DIR/02-amostra-gateway.log") linhas"

for f in pv-alvo-tunel pv-outra-tunel pv-outra-geral pv-alvo-fisico; do
  UCG_PASS="$(senha_gw)" SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  scp -q -o ControlPath="$CTL" root@"$GATEWAY_A":/tmp/"$f".pcap "$DIR/" 2>/dev/null \
    && ok "$f.pcap ($(du -h "$DIR/$f.pcap" 2>/dev/null | cut -f1))"
done
gw "rm -f /tmp/pv-*.pcap /tmp/pv-amostra.log /tmp/pv-amostra.sh" >/dev/null 2>&1

gw "echo '=== estado final ==='; date -Is; ip -br a; echo; wg show $TUNEL
    echo; ip rule show; echo; ip route get $EP_IP" > "$DIR/03-estado-final.txt" 2>&1

passo "lado B: colhendo (so com o tunel de pe)"
LADO_B=0
# ⛔ SEM RAJADA NA PORTA 22 DA GATEWAY_B. Na corrida 2026-09-23 19:12 o laco
#    tentou reabrir a cada 2 s por 5 min (socket orfao, ver b_de_volta) e a
#    gw_b passou a DESCARTAR SSH vindo do Mac — ping e as outras portas da
#    Casa B seguiam abrindo; so a 22 dela deu timeout. O bloqueio durou uns
#    15 min, e durante a penalidade passava ~1 conexao nova por minuto (medido
#    20:00-20:08: a tentativa isolada entrava, a seguinte em <60 s dava
#    timeout). E a regra 3 do CLAUDE.md, que era "da sonda", valendo para o
#    UCG. Aqui: uma tentativa a cada 60 s, no maximo 6.
b_de_volta_compassado() {
  local i
  for i in 1 2 3 4 5 6; do
    b_de_volta && return 0
    printf '\r  %s⏳ gw_b ainda nao responde pelo tunel (tentativa %s de 6, proxima em 60 s)%s' "$AMAR" "$i" "$N"
    sleep 60
  done
  printf '\r%-78s\r' ''; return 1
}
if b_de_volta_compassado; then
  gwb "pkill -x tcpdump; pkill -f '[p]vb-amostra.sh'; pkill -f '[p]vb-sonda-udp.sh'; sleep 2; ls -l /tmp/pvb-*" > "$DIR/pcaps-na-ultra-b.txt" 2>&1
  gwb "cat /tmp/pvb-amostra.log"   > "$DIR/05-amostra-casa-b.log"   2>/dev/null
  gwb "cat /tmp/pvb-sonda-udp.log" > "$DIR/06-sonda-udp-casa-b.log" 2>/dev/null
  ok "amostrador de B: $(wc -l < "$DIR/05-amostra-casa-b.log") linhas · sonda UDP: $(grep -c enviada "$DIR/06-sonda-udp-casa-b.log") enviadas"
  scp_b /tmp/pvb-wan.pcap "$DIR/pvb-wan-casa-b.pcap" && ok "pvb-wan-casa-b.pcap ($(du -h "$DIR/pvb-wan-casa-b.pcap" | cut -f1))" \
    || aviso "nao consegui trazer o pcap da gw_b"
  gwb "echo '=== estado final (gw_b) ==='; date -Is; ip -br a show $IF_WAN_B; echo; wg show $TUNEL
       echo; stat -c '%y  %n' /run/wireguard_$TUNEL.*.config; grep -h '^Endpoint' /run/wireguard_$TUNEL.*.config
       echo; ip rule show" > "$DIR/03b-estado-final-casa-b.txt" 2>&1
  gwb "rm -f /tmp/pvb-*" >/dev/null 2>&1
  [ -s "$DIR/pvb-wan-casa-b.pcap" ] && [ -s "$DIR/05-amostra-casa-b.log" ] && LADO_B=1
  marcar "lado B coletado (amostras=$(wc -l < "$DIR/05-amostra-casa-b.log"), sondas=$(grep -c enviada "$DIR/06-sonda-udp-casa-b.log"))"
else
  aviso "gw_b nao voltou em 5 min — os arquivos ficam em /tmp da gw_b (tmpfs, ate o reboot): pvb-wan.pcap, pvb-amostra.log, pvb-sonda-udp.log"
  aviso "colher a mao: ./scripts/ucg-ssh.sh $GATEWAY_B 'cat /tmp/pvb-amostra.log' etc. — e apagar depois"
  marcar "lado B NAO coletado (gw_b inalcancavel apos a janela); arquivos ficam em /tmp dela"
fi

if [ "$SONDA_OK" = "1" ]; then
  # ⛔ NAO ler nem apagar a sonda enquanto ela roda. Em 2026-09-21 a coleta
  #    leu o log com a sonda viva (13 amostras a menos, sem "# fim="), apagou
  #    a tarefa e conferiu o watchdog no meio da restauracao dela — uma
  #    corrida entre dois processos, com o watchdog como vitima. A sonda dura
  #    JANELA+180 s desde o disparo; aqui se espera o "# fim=" com teto.
  sonda_acabou() { sonda_ps '(Select-String -Path C:\homelab\sonda-failover.log -Pattern "^# fim=" -Quiet)' 2>/dev/null | tr -d '\r ' | grep -qi true; }
  if esperar_ate 420 "esperando a sonda da sonda terminar e restaurar" sonda_acabou; then
    ok "sonda terminou e restaurou sozinha"
  else
    aviso "sonda nao registrou fim em 7 min — lendo o que ha (log parcial)"
    marcar "sonda sem '# fim=' na coleta (log parcial)"
  fi
  sonda_exec "type C:\\homelab\\sonda-failover.log" > "$DIR/04-sonda-externa-casab.log" 2>/dev/null \
    && ok "sonda externa: $(grep -c '^20' "$DIR/04-sonda-externa-casab.log") amostras" \
    || aviso "nao consegui trazer o log da sonda (sonda pode ter sido desligado)"
  # hostname e conta de servico do PC da Casa B nao sao relevantes para o ticket
  sed -i '' 's/^# host=.*usuario=.*$/# host=<pc-casa-b> usuario=<conta-de-servico>  (redigido)/' "$DIR/04-sonda-externa-casab.log" 2>/dev/null
  # A sonda se restaura sozinha no `finally`; aqui so tiramos a tarefa, para
  # nao deixar agendamento orfao numa casa sem socorro fisico.
  sonda_destacar_limpar "$TAREFA_SONDA" \
    && ok "tarefa $TAREFA_SONDA removida da sonda" \
    || aviso "nao consegui remover a tarefa $TAREFA_SONDA — conferir a mao"
  # Casa B nao pode sair do teste sem o watchdog: conferir, e consertar se preciso.
  WD_DEPOIS="$(sonda_ps '(Get-ScheduledTask homelab-wg-failover -EA SilentlyContinue).State' 2>/dev/null | tr -d '\r ')"
  if [ "$WD_DEPOIS" = "Ready" ] || [ "$WD_DEPOIS" = "Running" ]; then
    ok "watchdog da sonda apos o teste: $WD_DEPOIS"
  else
    sonda_ps 'Enable-ScheduledTask homelab-wg-failover | Out-Null' >/dev/null 2>&1
    aviso "watchdog da sonda estava '${WD_DEPOIS:-?}' apos o teste — reabilitado"
    marcar "watchdog da sonda encontrado '${WD_DEPOIS:-?}' apos a coleta e reabilitado"
  fi
fi

# ⛔ A CAPTURA GERAL NAO E DISTRIBUIDA. Ela carrega TODO o trafego da casa na
#    WAN sobrevivente (DNS, destinos, IPv6) — metadado de uso da familia. O
#    que ela prova (WAN viva) cabe num resumo de contagens; e o que ela revelou
#    em 2026-09-21 (o gateway mandando Site Magic para o endpoint PROVISIONADO
#    em 100.64/10 pela WAN sobrevivente) e extraido num pcap so com UDP 20000.
# ⛔ Ordem importa, e custou a corrida 2 (2026-09-21 20:11): P_GERAL_QUEDA era
#    usado aqui e definido so na analise, 20 linhas abaixo — sob `set -u` o
#    bash morre ("unbound variable") e o pacote fica sem RESUMO, sem manifesto
#    e com o pcap bruto dentro. E a analise lia o pcap DEPOIS de movido.
#    Agora: contar primeiro, resumir depois, mover por ultimo.
P_GERAL=$([ -f "$DIR/pv-outra-geral.pcap" ] && tcpdump -n -r "$DIR/pv-outra-geral.pcap" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
P_GERAL_QUEDA=$([ -f "$DIR/pv-outra-geral.pcap" ] && tcpdump -n -tttt -r "$DIR/pv-outra-geral.pcap" 2>/dev/null | awk -v q="${T_QUEDA#*T}" '{ if (substr($2,1,8) >= substr(q,1,8)) n++ } END { print n+0 }' || echo 0)
P_SM_FORA=0; SM_FORA_DST=""
if [ -f "$DIR/pv-outra-geral.pcap" ]; then
  Q="${T_QUEDA#*T}"; Q="${Q:0:8}"
  # As sondas UDP de B (payload "PROV…") nao sao Site Magic: ficam FORA do pcap
  # "fora do peer" e vao para um pcap proprio. Elas podem cair aqui (se o CGNAT
  # de B lhes deu outro IP publico) ou em pv-outra-tunel (se vieram do IP do
  # peer aprendido) — as duas fontes sao somadas na analise.
  tcpdump -n -r "$DIR/pv-outra-geral.pcap" -w "$DIR/pv-outra-sitemagic-fora-do-peer.pcap" "udp port $PORTA_SM and not $SONDA_BPF" 2>/dev/null
  tcpdump -n -r "$DIR/pv-outra-geral.pcap" -w "$TMPD/sondas-geral.pcap" "udp port $PORTA_SM and $SONDA_BPF" 2>/dev/null
  P_SM_FORA=$(tcpdump -n -r "$DIR/pv-outra-sitemagic-fora-do-peer.pcap" 2>/dev/null | wc -l | tr -d ' ')
  SM_FORA_DST="$(tcpdump -n -r "$DIR/pv-outra-sitemagic-fora-do-peer.pcap" 2>/dev/null | awk '{print $3, "->", $5}' | sed 's/:$//' | sort | uniq -c | sort -rn | head -3 | sed 's/^ *//' | tr '\n' ';')"
  { echo "# pv-outra-geral.pcap — RESUMO da captura geral na WAN sobrevivente ($IF_OUTRA)"
    echo "# O pcap bruto contem todo o trafego da casa e NAO e distribuido; fica em teste_ubiquiti/.bruto/."
    echo "# corte=$Q  (relogio do gateway, UTC-03:00)"; echo
    echo "total de pacotes: $(tcpdump -n -r "$DIR/pv-outra-geral.pcap" 2>/dev/null | wc -l | tr -d ' ')"
    echo "pacotes DEPOIS do corte: $P_GERAL_QUEDA"; echo
    echo "pacotes por minuto:"; tcpdump -n -tttt -r "$DIR/pv-outra-geral.pcap" 2>/dev/null | cut -c12-16 | sort | uniq -c | awk '{printf "  %s  %6d\n", $2, $1}'
    echo; echo "UDP $PORTA_SM (Site Magic) nesta WAN que NAO envolve o peer aprendido $EP_IP, por origem -> destino:"
    tcpdump -n -r "$DIR/pv-outra-sitemagic-fora-do-peer.pcap" 2>/dev/null | awk '{print $3, "->", $5}' | sed 's/:$//' | sort | uniq -c | sort -rn
  } > "$DIR/pv-outra-geral.RESUMO.txt"
  mkdir -p "$RAIZ/teste_ubiquiti/.bruto"
  mv "$DIR/pv-outra-geral.pcap" "$RAIZ/teste_ubiquiti/.bruto/$(basename "$DIR").pv-outra-geral.pcap"
  ok "captura geral: resumo gerado; bruto movido para teste_ubiquiti/.bruto/ (fora do git)"
  [ "${P_SM_FORA:-0}" -gt 0 ] && ok "Site Magic na sobrevivente FORA do peer: $P_SM_FORA pacotes — $SM_FORA_DST"
fi

passo "analise — os numeros que sustentam o veredito"
# `-n`: sem DNS reverso (levava minutos). E as capturas do tunel sao lidas com
# o mesmo filtro de porta com que foram gravadas — cinto e suspensorio.
conta()    { [ -f "$1" ] && tcpdump -n -r "$1" 2>/dev/null | wc -l | tr -d ' ' || echo 0; }
conta_sm() { [ -f "$1" ] && tcpdump -n -r "$1" "udp port $PORTA_SM" 2>/dev/null | wc -l | tr -d ' ' || echo 0; }
# ⛔ CONTAR SO DENTRO DA QUEDA. Na corrida 2 (2026-09-21 20:11) o tunel voltou
#    pela WAN sobrevivente 1 s depois de o cabo religar, e a captura dela
#    tinha 273 pacotes com o peer — todos DEPOIS do corte acabar. Contados sem
#    janela, o resumo diria que o Site Magic usou a WAN2 durante a falha. Os
#    limites vem do eventos.log (CABO PUXADO / CABO RECONECTADO), para nao
#    tocar na secao de medicao.
Q_INI="$(grep -m1 'CABO PUXADO' "$EVENTOS" | cut -c12-19)"
Q_FIM="$(grep -m1 'CABO RECONECTADO' "$EVENTOS" | cut -c12-19)"; [ -n "$Q_FIM" ] || Q_FIM="23:59:59"
# `$2` opcional: filtro BPF extra. As sondas UDP de B ("PROV…") NAO contam
# como Site Magic — sao contadas a parte, e e a chegada delas que decide.
conta_janela() { [ -f "$1" ] && tcpdump -n -tttt -r "$1" "${2:-udp port $PORTA_SM}" 2>/dev/null | awk -v a="$Q_INI" -v b="$Q_FIM" '{t=substr($2,1,8); if (t>=a && t<=b) n++} END{print n+0}' || echo 0; }
conta_sm_queda() { conta_janela "$1" "udp port $PORTA_SM and not $SONDA_BPF"; }
P_ALVO=$(conta_sm_queda "$DIR/pv-alvo-tunel.pcap")
P_OUTRA=$(conta_sm_queda "$DIR/pv-outra-tunel.pcap")
P_OUTRA_TOTAL=$([ -f "$DIR/pv-outra-tunel.pcap" ] && tcpdump -n -r "$DIR/pv-outra-tunel.pcap" "udp port $PORTA_SM and not $SONDA_BPF" 2>/dev/null | wc -l | tr -d ' ' || echo 0)   # inclui o que veio DEPOIS do cabo voltar

# ── sondas UDP de B que CHEGARAM na WAN sobrevivente de A, durante a queda ──
P_SONDA_A_Q=$(( $(conta_janela "$DIR/pv-outra-tunel.pcap" "$SONDA_BPF") + $(conta_janela "$TMPD/sondas-geral.pcap" "$SONDA_BPF") ))
conta_bpf() { [ -f "$1" ] && tcpdump -n -r "$1" "$2" 2>/dev/null | wc -l | tr -d ' ' || echo 0; }
P_SONDA_A_TOT=$(( $(conta_bpf "$DIR/pv-outra-tunel.pcap" "$SONDA_BPF") + $(conta_bpf "$TMPD/sondas-geral.pcap" "$SONDA_BPF") ))
[ -f "$TMPD/sondas-geral.pcap" ] && [ "$(tcpdump -n -r "$TMPD/sondas-geral.pcap" 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && cp "$TMPD/sondas-geral.pcap" "$DIR/pv-outra-sondas-udp-da-casa-b.pcap"
SONDA_B_ENV_Q=$([ -f "$DIR/06-sonda-udp-casa-b.log" ] && awk -F'T' -v a="$Q_INI" -v b="$Q_FIM" '/ enviada /{t=substr($2,1,8); if (t>=a && t<=b) n++} END{print n+0}' "$DIR/06-sonda-udp-casa-b.log" || echo 0)
SONDA_B_ENV_TOT=$([ -f "$DIR/06-sonda-udp-casa-b.log" ] && grep -c ' enviada ' "$DIR/06-sonda-udp-casa-b.log" || echo 0)

# ── o lado B, na captura da propria gw_b (relogio de B) ───────────────────
# Iniciacao de handshake WireGuard = primeiro byte do payload 0x01 e tres
# zeros: `udp[8:4]=0x01000000`. Conta-se para ONDE B iniciou durante a queda.
WG_INIT="udp[8:4]=0x01000000"
PB_INIT_ALVO=$(conta_janela "$DIR/pvb-wan-casa-b.pcap" "dst host $IP_TUNEL_WAN and udp dst port $PORTA_SM and $WG_INIT")
PB_INIT_SOBREV=$(conta_janela "$DIR/pvb-wan-casa-b.pcap" "dst host $IP_OUTRA_WAN and udp dst port $PORTA_SM and $WG_INIT")
PB_PARA_SOBREV=$(conta_janela "$DIR/pvb-wan-casa-b.pcap" "dst host $IP_OUTRA_WAN and udp dst port $PORTA_SM and not $SONDA_BPF")
PB_DE_SOBREV=$(conta_janela "$DIR/pvb-wan-casa-b.pcap" "src host $IP_OUTRA_WAN and udp port $PORTA_SM")
PB_DE_ALVO=$(conta_janela "$DIR/pvb-wan-casa-b.pcap" "src host $IP_TUNEL_WAN and udp port $PORTA_SM")
# Destinos de Site Magic que B tentou ALEM das duas WANs de A, so DURANTE a
# queda e so o que SAIU de B (src = a WAN de B): revela um terceiro endereco
# provisionado, se houver. Sem o `src host`, entrava o que CHEGA em B.
PB_OUTROS_DST="$([ -f "$DIR/pvb-wan-casa-b.pcap" ] && tcpdump -n -tttt -r "$DIR/pvb-wan-casa-b.pcap" "src host $IP_WAN_B and udp dst port $PORTA_SM and not dst host $IP_TUNEL_WAN and not dst host $IP_OUTRA_WAN and not $SONDA_BPF" 2>/dev/null | awk -v a="$Q_INI" -v b="$Q_FIM" '{t=substr($2,1,8); if (t>=a && t<=b) print $6}' | sed 's/:$//' | sort | uniq -c | sort -rn | head -3 | sed 's/^ *//' | tr '\n' ';')"
# A config provisionada em B mudou durante a queda? (mtime e valor, do amostrador de B)
B_PROV_SERIE="$([ -f "$DIR/05-amostra-casa-b.log" ] && awk -F'T' -v a="$Q_INI" -v b="$Q_FIM" '{t=substr($2,1,8); if (t>=a && t<=b) print}' "$DIR/05-amostra-casa-b.log" | sed -n 's/^\([^ ]*\) .*cfg_mtime=\([^ ]*\) prov=\([^ ]*\) apr=\([^ ]*\).*/\2 \3 \4 \1/p' | awk '!v[$1" "$2" "$3]++ {print $4"  mtime="$1"  provisionado="$2"  aprendido="$3}' | tr '\n' ';')"
B_PROV_MUDOU=$(printf '%s' "$B_PROV_SERIE" | tr ';' '\n' | grep -c 'mtime=' )
# E DEPOIS da queda: a primeira vez, em todo o log de B, em que o provisionado
# deixou de ser o valor inicial — diz se a nuvem reprovisiona B e com que WAN
# (medido 23/09: 44 s depois de o cabo voltar, com o IP NOVO da WAN1; nunca
# com a WAN2 durante os 900 s).
B_PROV_INICIAL="$([ -f "$DIR/05-amostra-casa-b.log" ] && sed -n 's/.* prov=\([^ ]*\) .*/\1/p' "$DIR/05-amostra-casa-b.log" | head -1)"
B_PROV_DEPOIS="$([ -f "$DIR/05-amostra-casa-b.log" ] && [ -n "$B_PROV_INICIAL" ] && awk -v p="prov=$B_PROV_INICIAL" 'index($0, p)==0 && / prov=/ {print; exit}' "$DIR/05-amostra-casa-b.log" | sed -n 's/^\([^ ]*\) .*prov=\([^ ]*\) .*/\1 \2/p')"
if [ -n "$B_PROV_DEPOIS" ]; then
  B_REPROV_T="${B_PROV_DEPOIS%% *}"; B_REPROV_EP="${B_PROV_DEPOIS#* }"
  case "${B_REPROV_EP%%:*}" in
    "$IP_OUTRA_WAN") B_REPROV_ROT="a WAN SOBREVIVENTE de A" ;;
    *) B_REPROV_ROT="$( [ "$(grep -c "${B_REPROV_EP%%:*}" "$DIR/03-estado-final.txt" 2>/dev/null)" -gt 0 ] && echo "a WAN ALVO de A, com o IP NOVO que ela recebeu ao voltar" || echo "um endereco que nao e nenhuma das WANs de A gravadas")" ;;
  esac
  B_REPROV_TXT="SIM — em $B_REPROV_T, para \`$B_REPROV_EP\` ($B_REPROV_ROT)$([ -n "${Q_FIM:-}" ] && [ "$Q_FIM" != "23:59:59" ] && [ "${B_REPROV_T#*T}" \> "$Q_FIM" ] && echo "; isto e DEPOIS de o cabo voltar ($Q_FIM)")"
else
  B_REPROV_TXT="NAO em todo o log de B ($(wc -l < "$DIR/05-amostra-casa-b.log" 2>/dev/null || echo 0) amostras)"
fi
[ "$LADO_B" = "1" ] && {
  printf '  lado B: iniciacoes B->WAN alvo (%s, morta) %s · B->WAN sobrevivente (%s) %s · vindo da sobrevivente %s\n' "$IP_TUNEL_WAN" "$PB_INIT_ALVO" "$IP_OUTRA_WAN" "$PB_INIT_SOBREV" "$PB_DE_SOBREV"
  printf '  sondas UDP/%s de B para a sobrevivente: enviadas %s, CHEGARAM em A %s  %s\n' "$PORTA_SM" "$SONDA_B_ENV_Q" "$P_SONDA_A_Q" \
    "$([ "${P_SONDA_A_Q:-0}" -gt 0 ] && printf '%s← a operadora de B NAO filtra%s' "$B$VERD" "$N")"
  printf '  config provisionada em B durante a queda: %s estado(s) distinto(s) — %s\n' "$B_PROV_MUDOU" "$B_PROV_SERIE"
}
# P_GERAL e P_GERAL_QUEDA ja foram contados acima, antes de o bruto ser movido.
printf '  Site Magic (UDP %s) na WAN alvo (%s)        : %s\n' "$PORTA_SM" "$IF_TUNEL" "$P_ALVO"
printf '  Site Magic (UDP %s) na WAN sobrevivente (%s): %s DURANTE a queda (%s no total, o resto e apos o cabo voltar)  %s\n' "$PORTA_SM" "$IF_OUTRA" "$P_OUTRA" "$P_OUTRA_TOTAL" \
  "$([ "$P_OUTRA" -eq 0 ] && printf '%s← ZERO: nunca falou com o peer aprendido por ela%s' "$B$VERM" "$N")"
printf '  outro trafego na sobrevivente DURANTE a queda   : %s  %s\n' "$P_GERAL_QUEDA" \
  "$([ "$P_GERAL_QUEDA" -gt 0 ] && printf '%s← ela estava viva%s' "$VERD" "$N")"

if [ -f "$DIR/04-sonda-externa-casab.log" ]; then
  SONDA_OUTRA_OK=$(grep -c 'tcp=True' "$DIR/04-sonda-externa-casab.log" 2>/dev/null || echo 0)
  SONDA_TOT=$(grep -c 'tcp=' "$DIR/04-sonda-externa-casab.log" 2>/dev/null || echo 0)
  SONDA_QUEDA_OK=$(awk -F'T' -v a="$Q_INI" -v b="$Q_FIM" '/tcp=True/{t=substr($2,1,8); if (t>=a && t<=b) n++} END{print n+0}' "$DIR/04-sonda-externa-casab.log")
  SONDA_QUEDA_TOT=$(awk -F'T' -v a="$Q_INI" -v b="$Q_FIM" '/tcp=/{t=substr($2,1,8); if (t>=a && t<=b) n++} END{print n+0}' "$DIR/04-sonda-externa-casab.log")
  SONDA_COMPLETA=$(grep -q '^# fim=' "$DIR/04-sonda-externa-casab.log" && echo sim || echo NAO)
  printf '  sonda da Casa B: %s de %s amostras OK DURANTE a queda; log completo: %s\n' "$SONDA_QUEDA_OK" "$SONDA_QUEDA_TOT" "$SONDA_COMPLETA"
  printf '  entrada pela sobrevivente, de outra operadora: %s de %s amostras  %s\n' \
    "$SONDA_OUTRA_OK" "$SONDA_TOT" \
    "$([ "${SONDA_OUTRA_OK:-0}" -gt 0 ] && printf '%s← ela ACEITAVA entrada publica%s' "$B$VERD" "$N")"
fi

# ─────────────────────────────────────────────────── manifesto e resumo ────
# ⚠️ O manifesto NAO pode listar a si mesmo: `shasum *` incluia o proprio
#    manifesto.sha256 enquanto o escrevia, e `shasum -c` respondia FAILED em
#    todo pacote — na frente de quem for conferir. Pego na auditoria de
#    2026-09-19.
( cd "$DIR" && ls | grep -v '^manifesto.sha256$' | xargs shasum -a 256 > manifesto.sha256 2>/dev/null )
ok "manifesto SHA-256 de $(wc -l < "$DIR/manifesto.sha256") arquivos"

cat > "$DIR/RESUMO.md" <<RESUMO
# Failover do Site Magic — evidencia · ticket #5927426

Gerado por \`scripts/failover-prova-guiada.sh\`.
**Todo carimbo vem de um relogio so: o do gateway \`gw_a\`**, ISO-8601 com
offset (America/Sao_Paulo, UTC-03:00).
Script: sha256 \`$SCRIPT_SHA\` · **secao de medicao \`$MEDICAO_SHA\`** · git \`$SCRIPT_GIT\` (ver \`eventos.log\`).

## Arranjo no momento do teste

| papel | interface | fisica | IP publico |
|---|---|---|---|
| WAN cortada (alvo) | \`$IF_TUNEL\` | \`$FIS_TUNEL\`, porta $PORTA_TUNEL | $IP_TUNEL_WAN |
| WAN sobrevivente | \`$IF_OUTRA\` | \`$FIS_OUTRA\`, porta $PORTA_OUTRA | $IP_OUTRA_WAN |
| WAN por onde o tunel SAIA (A->B) | \`$IF_SAIDA\` | | |
| WAN por onde a Casa B CHEGAVA (B->A), medido antes do corte | \`$IF_CHEGADA\` | | ppp0=${CHEGA_PPP0:-0} eth3=${CHEGA_ETH3:-0} pacotes do peer em 6 s |

$([ "$IF_TUNEL" != "$IF_SAIDA" ] && printf '%s' '> **Este corte e na WAN de CHEGADA, nao na de saida.** A Casa B esta em CGNAT
> e e sempre quem inicia; ao perder a WAN por onde alcancava a Casa A, ela
> precisa descobrir o outro endereco publico sozinha. Rota migrar na Casa A
> nao e esperado nem necessario aqui — o que se mede e se o TUNEL volta.')

Peer do tunel: \`$EP\` · interface \`$TUNEL\`.
Metodo do corte: **cabo puxado fisicamente** — um \`down\` administrativo pode
nao exercitar o mesmo caminho de codigo que a queda de link.

## Resultado

**Duas perguntas diferentes, e o teste responde as duas separadamente.** A
rota do gateway pode migrar para a WAN sobrevivente sem que o tunel volte a
falar: e preciso um handshake com carimbo POSTERIOR a queda para afirmar que o
tunel foi restabelecido. Um handshake anterior sobrevive ate 3 minutos e ja
produziu rotulo falso neste repo (2026-09-19, corrida das 11:18).

| pergunta | resposta |
|---|---|
| a WAN sobrevivente aceitava entrada da internet, de outra operadora (sonda na Casa B)? | **$([ -f "$DIR/04-sonda-externa-casab.log" ] && { [ "${SONDA_QUEDA_TOT:-0}" -gt 0 ] && echo "${SONDA_QUEDA_OK} de ${SONDA_QUEDA_TOT} amostras durante a queda" || echo "SEM DADO na janela"; } || echo "sem sonda")$([ "${SONDA_COMPLETA:-NAO}" = "NAO" ] && [ -f "$DIR/04-sonda-externa-casab.log" ] && echo " — ⚠️ log INCOMPLETO (sonda interrompida)")** |
| a ROTA passou a sair pela WAN sobrevivente? | **$([ -n "$T_ROTA" ] && echo "SIM, aos ${T_ROTA}s" || echo NAO)** |
| o TUNEL voltou a fechar handshake (carimbo posterior a queda)? | **$([ -n "$T_TUNEL" ] && echo "SIM, aos ${T_TUNEL}s" || echo "NAO, em ${JANELA}s")** |
| quantos handshakes novos durante a queda | **${HS_CONTA:-0}** |
| sustentou ate o fim da janela | **$([ "$MIGROU" = "1" ] && echo SIM || { [ "$MIGROU" = "2" ] && echo "NAO - reverteu" || echo "nao se aplica"; })** |
| trocas de rota observadas | **${TROCAS:-0}** |

$([ -n "$T_ROTA" ] && [ -z "$T_TUNEL" ] && printf '%s' '> **Leitura:** a rota migrou e o tunel NAO voltou. Nao e "a WAN de backup
> estava indisponivel" - ela estava roteando. O tunel e que nao refez
> handshake por ela dentro da janela medida.')
- pacotes do **Site Magic (UDP $PORTA_SM)** entre este gateway e o peer aprendido na WAN sobrevivente, **durante a queda** (${Q_INI}–$Q_FIM): **$P_OUTRA** (no total da captura: $P_OUTRA_TOTAL — a diferenca e depois de o cabo voltar)
- pacotes de **outro trafego** na WAN sobrevivente **durante a queda**: **$P_GERAL_QUEDA** (captura geral, de $P_GERAL no total)

$([ "$P_OUTRA" -eq 0 ] && [ "$P_GERAL_QUEDA" -gt 0 ] && cat <<'INTERP'
O par acima e o nucleo da prova: **zero** pacote do Site Magic entre este
gateway e o peer aprendido cruzou a WAN sobrevivente, enquanto ela
demonstravelmente carregava outro trafego. Nao e "a WAN de backup estava
sem conectividade": ela estava passando pacote.
INTERP
)
$([ "${P_SM_FORA:-0}" -gt 0 ] && cat <<FORA

**E o gateway TENTOU pela WAN sobrevivente — para o endereco errado.** A captura
geral tem **${P_SM_FORA} pacotes UDP ${PORTA_SM}** nela que nao envolvem o peer
aprendido: \`${SM_FORA_DST}\`. Comparar com o \`Endpoint\` provisionado em
\`/run/wireguard_${TUNEL}.*.config\` (gravado em \`00\`/\`03\`): se o destino e
um endereco 100.64/10 (RFC 6598), o gateway voltou ao endpoint provisionado —
o endereco INTERNO de CGNAT do peer, irroteavel na internet — e abandonou o
endpoint publico que tinha aprendido pelo handshake. Pacotes em
\`pv-outra-sitemagic-fora-do-peer.pcap\`.
FORA
)

## Lado B — a \`gw_b\`, medida de dentro (v2, pedido da Ubiquiti em 23/09)

Carimbos desta secao vem do relogio da \`gw_b\` (desvio medido em relacao a
\`gw_a\`: ${DESVIO_AB}s, em \`eventos.log\`). Arquivos: \`00c\`, \`03b\`, \`05\`, \`06\`,
\`pvb-wan-casa-b.pcap\`. O pcap de B guarda TODO o trafego com os enderecos das
duas WANs de A, em qualquer porta — por isso nele tambem aparece a VPN de
usuario do PC da Casa B (UDP 51820, a sonda externa), que sai pela mesma WAN.
As contagens abaixo sao so UDP ${PORTA_SM} (Site Magic), e as sondas (\`PROV…\`)
sao contadas a parte.

| pergunta | resposta |
|---|---|
| que endereco de A a nuvem provisiona em B (\`00c\`) | **${EP_B_PROV:-?}** — $ROTULO_B |
| a config provisionada em B foi reescrita durante a queda (\`05\`) | **$([ "$LADO_B" = "1" ] && { [ "${B_PROV_MUDOU:-0}" -gt 1 ] && echo "SIM: ${B_PROV_SERIE}" || echo "NAO: ${B_PROV_SERIE}"; } || echo "sem dado (lado B nao coletado)")** |
| a nuvem reprovisionou B em algum momento do log (\`05\`, ate o fim da coleta) | **$([ "$LADO_B" = "1" ] && echo "$B_REPROV_TXT" || echo "sem dado")** |
| iniciacoes de handshake de B para a WAN ALVO de A (${IP_TUNEL_WAN}, morta), durante a queda | **$([ "$LADO_B" = "1" ] && echo "$PB_INIT_ALVO" || echo "—")** |
| iniciacoes de handshake de B para a WAN SOBREVIVENTE de A (${IP_OUTRA_WAN}), durante a queda | **$([ "$LADO_B" = "1" ] && echo "$PB_INIT_SOBREV" || echo "—")** (qualquer Site Magic B->sobrevivente: $([ "$LADO_B" = "1" ] && echo "$PB_PARA_SOBREV" || echo "—")) |
| Site Magic que CHEGOU em B vindo da WAN sobrevivente de A | **$([ "$LADO_B" = "1" ] && echo "$PB_DE_SOBREV" || echo "—")** |
| Site Magic de B para OUTROS destinos, durante a queda | $([ "$LADO_B" = "1" ] && echo "${PB_OUTROS_DST:-nenhum}" || echo "—") |
| sondas UDP/${PORTA_SM} de B para ${IP_OUTRA_WAN}: enviadas (\`06\`) → chegaram na captura de A | **$SONDA_B_ENV_Q → $P_SONDA_A_Q** durante a queda ($SONDA_B_ENV_TOT → $P_SONDA_A_TOT no total — os totais diferem porque a captura de A para na coleta e a sonda de B corre ate o proprio teto) |

$([ "$LADO_B" = "1" ] && [ "${P_SONDA_A_Q:-0}" -gt 0 ] && [ "${PB_INIT_SOBREV:-0}" -eq 0 ] && cat <<LADOB
> **Leitura:** datagramas UDP de B para a WAN sobrevivente de A, na porta do
> Site Magic, **chegaram** durante a queda — a operadora de B nao filtra esse
> caminho. E B **nao iniciou nenhum handshake** para essa WAN: iniciou
> ${PB_INIT_ALVO} vez(es) para a WAN morta, o unico endereco de A que a nuvem
> lhe provisionou. Nao ha bloqueio a investigar: ha um endereco que B nunca
> recebeu.
LADOB
)

## Coletado pelo painel da UniFi, com a WAN1 ainda fora (pedido de 2026-09-24)

$(if [ -n "${PAINEL_ARQS:-}" ]; then
    printf '%s\n' 'Support files dos dois consoles e capturas de WAN feitas pela ferramenta do proprio painel (Devices > UCG > Overview > Packet Captures), todos gerados/baixados ANTES de o cabo voltar. Os support files nao vao no repositorio (podem conter segredo); o SHA-256 de cada um esta no manifesto.'
    printf '\n| arquivo | tamanho | sha256 |\n|---|---|---|\n'
    for f in $PAINEL_ARQS; do printf '| `%s` | %s | `%s` |\n' "$f" "$(du -h "$DIR/$f" | cut -f1)" "$(shasum -a 256 "$DIR/$f" | cut -c1-16)…"; done
    printf '\nCapturas do painel: 300 s cada (o maximo da ferramenta) e SEM filtro (a ferramenta nao permite) — contem o trafego da WAN no periodo; revisadas antes de anexar. Os arquivos painel-* nao vao no repositorio.\n'
  else
    printf '%s\n' "Nenhum arquivo do painel nesta corrida$([ "$PAINEL" = "0" ] && echo ' (--sem-painel)')."
  fi)

## O que este teste NAO afirma

- nao diz o que acontece depois de ${JANELA}s: a janela terminou e a medicao
  para ai;
- nao afirma causa. O \`ip rule\` gravado em \`00\`, \`01\` e \`03\` mostra se a
  regra que prende a saida do tunel a uma tabela de WAN foi reescrita quando a
  interface caiu — o dado esta ali para quem analisar, sem conclusao embutida.

## Arquivos

\`\`\`
$(cd "$DIR" && ls -lh | tail -n +2 | awk '$9 != "RESUMO.md" {printf "%-34s %s\n", $9, $5}')
RESUMO.md                          (este arquivo)
\`\`\`

Integridade: \`manifesto.sha256\`.

## Linha do tempo

\`\`\`
$(cat "$EVENTOS")
\`\`\`
RESUMO
ok "RESUMO.md"

# ══════════════════════════════════════════════════════════ COMMIT ═════════
passo "commit e push"
( cd "$RAIZ" || exit 1
  for f in "$DIR"/*.pcap; do
    [ -f "$f" ] || continue
    MB=$(( $(stat -f %z "$f") / 1048576 ))
    if [ "$MB" -gt "$LIMITE_COMMIT_MB" ]; then
      aviso "$(basename "$f") tem ${MB} MB — fica FORA do commit (segue no disco, hash no manifesto)"
      mv "$f" "${f}.grande" 2>/dev/null
      echo "$(basename "$f") — ${MB} MB, fora do commit por tamanho; no disco em $DIR" >> "$DIR/ARQUIVOS-GRANDES.txt"
    fi
  done
  git add "$DIR" scripts/failover-prova-guiada.sh scripts/casab/sonda-failover-casab.ps1 2>/dev/null
  git commit -q -m "prova(failover): janela de ${JANELA}s com o cabo da porta $PORTA_TUNEL fora

Tunel saia por $IF_TUNEL ($IP_TUNEL_WAN); WAN sobrevivente $IF_OUTRA
($IP_OUTRA_WAN), com IP publico e carregando trafego.

rota migrou=$([ -n "$T_ROTA" ] && echo "sim, aos ${T_ROTA}s" || echo nao)
tunel restabelecido=$([ -n "$T_TUNEL" ] && echo "sim, aos ${T_TUNEL}s" || echo "NAO na janela")
handshakes novos durante a queda=${HS_CONTA:-0}
pacotes do tunel na sobrevivente=$P_OUTRA
pacotes totais na sobrevivente=$P_GERAL
lado B: provisionado em B para A=${EP_B_PROV:-?}; iniciacoes B->alvo=${PB_INIT_ALVO:-?} B->sobrevivente=${PB_INIT_SOBREV:-?}
sondas UDP de B para a sobrevivente: enviadas=${SONDA_B_ENV_Q:-?} chegaram=${P_SONDA_A_Q:-?}

Carimbos do relogio de cada gateway (desvio A-B=${DESVIO_AB}s). Manifesto SHA-256 no diretorio." \
    && ok "commitado" || aviso "nada a commitar"
  if [ "$PUSH" = "1" ]; then
    git push -q 2>/dev/null && ok "empurrado para o remoto" || aviso "push falhou — commit esta local"
  fi
)

titulo "PRONTO"
printf '  Pacote: %s%s%s\n' "$B" "$DIR" "$N"
printf '  Leia o %sRESUMO.md%s — e o que vai anexado ao ticket.\n\n' "$B" "$N"
