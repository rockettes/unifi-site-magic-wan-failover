<#
.SYNOPSIS
  Sonda EXTERNA da Casa B: prova, no protocolo, que a WAN sobrevivente da
  Casa A aceita conexao vinda da internet publica.

.DESCRIPTION
  POR QUE ELA EXISTE

  Ticket #5927426. A Ubiquiti respondeu que "o failover funciona desde que a
  WAN de backup tenha IP publicamente alcancavel". Esta sonda ataca exatamente
  essa precondicao, do lado de fora: a Casa B esta em outra operadora
  (ISP do site B) e, medido em 2026-09-18, o gateway B roteia os IPs publicos da Casa A
  por ppp0 (src <CGNAT-B>, CGNAT) e NAO pelo tunel Site Magic. Ela nao cai
  junto com o que esta sendo testado.

  POR QUE NAO E ICMP

  Medido em 2026-09-18: ICMP da Casa B nao passa para NENHUMA das duas WANs da
  Casa A. Sonda ICMP daria "nao alcancavel" para as duas e nao provaria nada.
  Medida negativa so vale para o metodo usado.

  O METODO QUE VALE

  A sonda ja tem os dois tuneis WireGuard de usuario instalados, um por WAN.

    site-a-isp-2 -> wan2.example.com  (WAN2 ISP-2)  padrao, sobe no boot
    site-a-isp-1  -> wan1.example.com   (WAN1 ISP-1)   reserva, parado

  ATENCAO -- CONFERIR O ENDPOINT, NAO O NOME. Ate 2026-09-19 eles se chamavam
  casa-a / site-a-2 e estavam CRUZADOS na maquina, o que fez esta sonda medir
  a WAN errada (ep=<WAN1-A> num teste que pedia a ISP-2). Foram
  renomeados, mas a licao fica: quem escolhe o tunel le o `Endpoint` em
  C:\homelab\<nome>.conf e resolve o nome. O `ep=` de cada amostra existe para
  que o log PROVE qual WAN respondeu, em vez de depender de suposicao.
  Subir o tunel que aponta para a WAN sobrevivente e conseguir HANDSHAKE mais
  uma resposta TCP atraves dele prova, no protocolo e de outra operadora, que
  aquela WAN aceita conexao de entrada da internet publica -- no mesmo instante
  em que o Site Magic se recusa a usa-la. Essa e a frase que o ticket precisa.

  CUIDADOS (Casa B nao tem socorro fisico rapido)

  - os dois tuneis dividem <VPN-IP>/32 (o tunel de usuario, que a propria sonda derruba), entao so UM pode estar ativo: para
    subir um e preciso parar o outro;
  - o watchdog (win-wg-failover.ps1) alterna tuneis sozinho e brigaria com a
    sonda: ela o desabilita e RESTAURA no fim;
  - todo estado alterado e anotado antes e devolvido num `finally`, inclusive
    se a sonda for morta no meio;
  - nada disto toca a rede local da sonda nem o SSH: o caminho do SSH e o tunel
    entre os gateways, nao o tunel de usuario do Windows.

  ARQUIVO EM ASCII PURO, DE PROPOSITO. Medido em 2026-09-18: publicado por scp
  em UTF-8, o Windows leu com a codepage local, travessao virou lixo e o parser
  quebrou o arquivo inteiro. Nada de acento, travessao ou emoji aqui dentro.

.PARAMETER Diagnostico
  Uma passada so, imprime na tela, NAO MUDA NADA. Valida o instrumento antes
  de confiar nele.

.PARAMETER Tunel
  Qual tunel subir: o que aponta para a WAN que vai sobreviver ao corte.
#>
param(
  [switch]$Diagnostico,
  [string]$Tunel = 'site-a-isp-2',
  [string]$TunelPadrao = 'site-a-isp-1',
  [int]$Segundos = 1800,
  [string]$Log = 'C:\homelab\sonda-failover.log',
  [int]$Intervalo = 10,
  # Alvo TCP do outro lado do tunel: um host que so responde se o tunel
# estiver de pe. Troque pelo seu.
  [string]$AlvoTcp = '192.168.1.1',
  [int]$PortaTcp = 443,
  [string]$TarefaWatchdog = 'homelab-wg-failover'
)

$ErrorActionPreference = 'SilentlyContinue'
$wgcli = 'C:\Program Files\WireGuard\wg.exe'

function Carimbo { (Get-Date).ToString('o') }
function Svc($t) { Get-Service -Name ("WireGuardTunnel`$" + $t) -ErrorAction SilentlyContinue }
function Estado($t) { $s = Svc $t; if ($s) { $s.Status.ToString() } else { 'ausente' } }

# Idade do ultimo handshake, em segundos. -1 quando nao ha handshake nenhum.
# ATENCAO: NAO usar Get-Date -UFormat %s. Medido na sonda em 2026-08-19, em
# Windows pt-BR, ele erra DUAS vezes: virgula como separador decimal, que
# quebra o cast, e hora LOCAL tratada como UTC, errando 3 horas.
function IdadeHandshake($t) {
  if (-not (Test-Path $wgcli)) { return -1 }
  $saida = & $wgcli show $t latest-handshakes 2>$null
  if (-not $saida) { return -1 }
  $ts = ((@($saida)[0]) -split '\s+')[-1]
  if (-not ($ts -match '^\d+$') -or [int64]$ts -eq 0) { return -1 }
  return [int64]([int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$ts)
}

# Sonda ATIVA: handshake e indicio, resposta e prova. TcpClient com timeout
# curto porque Test-NetConnection demora e nao aceita timeout.
# NAO usar ICMP: nao ha garantia de que o gateway responda ping na interface
# do tunel, e um "nao respondeu" viraria falso negativo.
# Endpoint REALMENTE em uso pelo tunel: o DDNS resolve na hora e o IP publico
# das duas WANs e DINAMICO. Sem isto o log prova "alguma WAN respondeu"; com
# isto ele nomeia QUAL, que e a frase de que o ticket precisa.
function EndpointDe($t) {
  if (-not (Test-Path $wgcli)) { return 'sem-wg' }
  $saida = & $wgcli show $t endpoints 2>$null
  if (-not $saida) { return 'sem-endpoint' }
  $ep = ((@($saida)[0]) -split '\s+')[-1]
  if (-not $ep -or $ep -eq '(none)') { return 'sem-endpoint' }
  return $ep
}

function TcpResponde($ip, $porta, $ms) {
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $r = $c.BeginConnect($ip, $porta, $null, $null)
    if ($r.AsyncWaitHandle.WaitOne($ms, $false) -and $c.Connected) { return $true }
    return $false
  } catch { return $false } finally { $c.Close() }
}

function Registrar($txt) {
  $dir = Split-Path $Log -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $txt | Out-File -FilePath $Log -Append -Encoding ascii
}

function Cabecalho {
  @(
    ('# sonda-failover-casab inicio=' + (Carimbo)),
    ('# host=' + $env:COMPUTERNAME + ' usuario=' + $env:USERNAME),
    ('# tunel_sondado=' + $Tunel + ' (aponta para a WAN que deve sobreviver)'),
    ('# tunel_padrao=' + $TunelPadrao + ' estado_inicial=' + (Estado $TunelPadrao)),
    ('# rodando_antes=' + $(if ($rodandoAntes) { $rodandoAntes } else { 'nenhum' }) + ' (e este que volta no fim)'),
    ('# alvo_ativo=' + $AlvoTcp + ':' + $PortaTcp + ' (interface WireGuard do gateway da Casa A)'),
    '# handshake em segundos; -1 = nunca houve. ok=True significa que a WAN',
    '# sobrevivente aceitou conexao VINDA DA INTERNET PUBLICA, de outra operadora.',
    '# ep=<ip:porta> e a WAN da Casa A que o tunel esta realmente usando.',
    '# formato: iso8601 tunel=<nome> ep=<ip:porta> hs=<s> tcp=<bool>'
  )
}

# ------------------------------------------------------------- diagnostico --
if ($Diagnostico) {
  Cabecalho | ForEach-Object { Write-Output $_ }
  Write-Output ''
  Write-Output '--- servicos WireGuard ---'
  Get-Service -Name 'WireGuardTunnel$*' | ForEach-Object {
    Write-Output ('  ' + $_.Name + '  ' + $_.Status + ' / ' + $_.StartType)
  }
  Write-Output ('  wg.exe presente: ' + (Test-Path $wgcli))
  Write-Output ''
  Write-Output '--- watchdog ---'
  $t = Get-ScheduledTask -TaskName $TarefaWatchdog -ErrorAction SilentlyContinue
  if ($t) { Write-Output ('  ' + $t.TaskName + ' = ' + $t.State) }
  else    { Write-Output ('  tarefa ' + $TarefaWatchdog + ' nao existe') }
  Write-Output ''
  Write-Output '--- tunel ativo agora ---'
  Write-Output ('  ' + $TunelPadrao + ': estado=' + (Estado $TunelPadrao) + ' handshake=' + (IdadeHandshake $TunelPadrao) + 's ep=' + (EndpointDe $TunelPadrao))
  Write-Output ('  ' + $Tunel       + ': estado=' + (Estado $Tunel)       + ' handshake=' + (IdadeHandshake $Tunel) + 's ep=' + (EndpointDe $Tunel))
  Write-Output ('  tcp ' + $AlvoTcp + ':' + $PortaTcp + ' pelo caminho atual = ' + (TcpResponde $AlvoTcp $PortaTcp 2500))
  Write-Output ''
  if (Test-Path $wgcli) { Write-Output 'VEREDITO: instrumento disponivel.' }
  else { Write-Output 'VEREDITO: wg.exe ausente. A sonda NAO pode rodar neste host.' }
  exit 0
}

# ------------------------------------------------------------------ sonda --
$estadoPadrao = Estado $TunelPadrao
$estadoAlvo   = Estado $Tunel

# QUEM ESTAVA DE PE, seja qual for o nome. E isto que tem de voltar no fim.
#
# ATENCAO -- defeito encontrado em 2026-09-19, antes do teste real: a
# restauracao antiga era "para o tunel da sonda; religa o PADRAO se ele estava
# Running". Quando a sonda sobe justamente o tunel que JA era o ativo (caso do
# teste em que a WAN sobrevivente e a padrao), o padrao estava Stopped -- e o
# final deixava OS DOIS parados, ou seja, a sonda sem tunel de usuario numa casa
# sem socorro fisico. Agora o estado inicial e gravado por observacao, nao
# deduzido dos papeis.
$rodandoAntes = (Get-Service 'WireGuardTunnel$*' -ErrorAction SilentlyContinue |
                 Where-Object { $_.Status -eq 'Running' } |
                 Select-Object -First 1)
$rodandoAntes = if ($rodandoAntes) { $rodandoAntes.Name -replace 'WireGuardTunnel\$','' } else { '' }
$watchdog     = Get-ScheduledTask -TaskName $TarefaWatchdog -ErrorAction SilentlyContinue
$watchdogEra  = if ($watchdog) { $watchdog.State.ToString() } else { 'ausente' }

Cabecalho | Out-File -FilePath $Log -Encoding ascii
Registrar ('# watchdog_estado_inicial=' + $watchdogEra)

try {
  if ($watchdog -and $watchdogEra -ne 'Disabled') {
    Disable-ScheduledTask -TaskName $TarefaWatchdog | Out-Null
    Registrar ((Carimbo) + ' watchdog desabilitado para nao brigar com a sonda')
  }
  if ($estadoPadrao -eq 'Running') {
    Stop-Service -Name ("WireGuardTunnel`$" + $TunelPadrao) -Force
    Registrar ((Carimbo) + ' ' + $TunelPadrao + ' parado (os dois dividem <VPN-IP>/32 (o tunel de usuario, que a propria sonda derruba))')
  }
  Start-Service -Name ("WireGuardTunnel`$" + $Tunel)
  Registrar ((Carimbo) + ' ' + $Tunel + ' iniciado, apontando para a WAN sobrevivente')

  # TETO SEMPRE: laco de sondagem sem limite ja virou zumbi neste repo.
  $fim = (Get-Date).AddSeconds($Segundos)
  while ((Get-Date) -lt $fim) {
    $hs  = IdadeHandshake $Tunel
    $ep  = EndpointDe $Tunel
    $tcp = TcpResponde $AlvoTcp $PortaTcp 2500
    Registrar ((Carimbo) + ' tunel=' + $Tunel + ' ep=' + $ep + ' hs=' + $hs + ' tcp=' + $tcp)
    Start-Sleep -Seconds $Intervalo
  }
}
finally {
  # RESTAURACAO: acontece mesmo se a sonda for morta no meio. Casa B nao tem
  # socorro fisico rapido; deixar a sonda com o tunel errado de pe nao e opcao,
  # e deixar os DOIS parados e pior ainda.
  Registrar ((Carimbo) + ' restaurando estado original')

  # 1. desfaz a sonda -- mas so se ela nao for justamente o que estava de pe
  if ($Tunel -ne $rodandoAntes) {
    Stop-Service -Name ("WireGuardTunnel`$" + $Tunel) -Force
  }
  # 2. devolve o que estava rodando no inicio, se caiu
  if ($rodandoAntes -and (Estado $rodandoAntes) -ne 'Running') {
    Start-Service -Name ("WireGuardTunnel`$" + $rodandoAntes)
    Start-Sleep -Seconds 3
  }
  # 3. REDE DE SEGURANCA: nada de terminar com zero tunel de pe. Se sobrou
  #    nenhum, sobe o da sonda -- e ele aponta para a WAN que sobreviveu.
  $vivosAgora = @(Get-Service 'WireGuardTunnel$*' -ErrorAction SilentlyContinue |
                  Where-Object { $_.Status -eq 'Running' })
  if ($vivosAgora.Count -eq 0) {
    Registrar ((Carimbo) + ' NENHUM tunel de pe apos restaurar -- subindo ' + $Tunel + ' como rede de seguranca')
    Start-Service -Name ("WireGuardTunnel`$" + $Tunel) -ErrorAction SilentlyContinue
  }
  if ($watchdog -and $watchdogEra -ne 'Disabled') { Enable-ScheduledTask -TaskName $TarefaWatchdog | Out-Null }
  Registrar ((Carimbo) + ' restaurado: ' + $TunelPadrao + '=' + (Estado $TunelPadrao) + ' ' + $Tunel + '=' + (Estado $Tunel) + ' watchdog=' + $watchdogEra)
  Registrar ('# fim=' + (Carimbo))
}
