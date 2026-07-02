# ClientGuard

**Versão atual: v1.6.0**

Sistema de detecção de clientes comprometidos via NetFlow para o provedor de internet.
Reaproveita passivamente o mesmo feed de NetFlow que já chega para o [FlowGuard](../flowguard)
(sem competir pelo socket dele, sem tocar em nenhum arquivo daquele projeto), agrega por
`src_ip` do cliente — não pelo prefixo de destino, que é o foco do FlowGuard — e roda
detectores de baixo esforço pra identificar hosts de clientes possivelmente
comprometidos (scan, spam, amplificação, C2, exfiltração).

## Etapas do projeto

1. **Coletor mínimo** — captura passiva de NetFlow via scapy na interface `lo`
   (porta UDP 2055), reaproveitando somente-leitura o parser `collector/netflow.py`
   do FlowGuard. Agregação por `src_ip` em SQLite próprio (`db/client_flow.sqlite`).
2. **Detectores de esforço baixo (v1)** — scan horizontal, scan vertical,
   amplificador hospedado, spam bot.
3. **Serviço systemd persistente** — `clientguard.service`, reinício automático em
   falha.
4. **Socket de controle + CLI** (`socket_server.py`, `clientguard-cli.py`) — mesmo
   padrão do `flowguard-cli`: status, top clientes, sinais suspeitos, resolver
   sinal, whitelist e cadastro de clientes via terminal.
5. **Cadastro de redes de clientes por CIDR** (`customers.yaml`) — deixou de
   resolver por IP exato pra resolver por rede: o bloco `/21` público da operadora
   dividido em `/24`, e o pool CGNAT `100.64.0.0/10` atrás do NAT de operadora
   (identifica o assinante individual, não o IP público compartilhado por 32
   clientes).
6. **Whitelist** de IPs/serviços legítimos que nunca devem gerar alerta.
7. **Alertas via webhook + explicação por IA** — cada sinal *novo* (não
   atualização de sinal já aberto) dispara webhook (`notifier.py`) e ganha uma
   explicação em português gerada por Claude Haiku (`ai_client.py`).
8. **Feed de reputação próprio** (`threat_feed.py`) — mescla Feodo Tracker,
   Spamhaus DROP/EDROP e ipsum num cache local, refeito a cada 6h. Detector
   `malicious_contact`.
9. **Correlação entre clientes** (`detect_shared_destination`) — mesmo
   `dst_ip:dst_port` (fora de portas web/DNS comuns) contatado por vários
   clientes ao mesmo tempo: indício de botnet/C2 coordenado.
10. **Enriquecimento GeoIP/ASN** (`geoip.py`) — `dst_asn`/`dst_country` via Team
    Cymru IP-to-ASN (bulk whois gratuito, sem chave de API).
11. **Detector de DNS tunneling** (`detect_dns_tunneling`) — volume anômalo de
    queries DNS pequenas pro mesmo resolver externo.
12. **Lock de granularidade fina** — o lock do SQLite protege só
    SELECT/INSERT/UPDATE, nunca as chamadas de rede de IA/webhook, pra não travar
    consultas via CLI/portal quando vários sinais disparam no mesmo ciclo.
13. **Aba no portal web** (repositório do portal) — status, top clientes, sinais
    suspeitos com painel de detalhe/IA, e CRUD de redes/whitelist, reaproveitando
    login/sessão do portal do FlowGuard.

**Pendente:** `alerts.webhook_url` ainda não configurado (aguardando destino).

## Estrutura

| Arquivo | Papel |
|---|---|
| `clientguard.py` | Daemon principal — captura, agregação, orquestra os detectores |
| `detector.py` | Os 7 detectores |
| `storage.py` | Schema e acesso ao SQLite |
| `configio.py` | Leitura/gravação de `customers.yaml`/`whitelist.yaml` |
| `customer_registry.py` | `resolve_customer_prefix` (matching CIDR) — sem dependência de scapy/FlowGuard, importável isoladamente |
| `socket_server.py` | Servidor de controle (Unix socket, protocolo JSON por linha) |
| `clientguard-cli.py` | Cliente de terminal |
| `control.py` | Client mínimo do socket, usado pelos CGI scripts do portal |
| `notifier.py` | Envio de webhook |
| `ai_client.py` | Explicação de sinais via Claude |
| `threat_feed.py` | Feed de reputação de IPs maliciosos |
| `geoip.py` | Enriquecimento ASN/país via Team Cymru |
| `tools/synth_client_flows.py` | Gerador de NetFlow sintético para testar os detectores |
| `tests/` | Suíte pytest (57 testes) — detectores, storage, configio, threat feed, geoip |

## Testes

```
./venv/bin/pytest        # 57 testes, ~2s, sem rede/captura real
```

## Uso

```
systemctl status clientguard
clientguard-cli status
clientguard-cli suspicious
clientguard-cli top
clientguard-cli whitelist add|del <ip>
clientguard-cli customers add|del <network> <prefix>
```

## Changelog

Formato livre, mais detalhado que o log do git — pense nisso como o "o que mudou e
por quê" de cada leva de trabalho.

### v1.6.0 — 2026-07-02 — Status da sessão BGP do FlowGuard no CLI
- `clientguard-cli status` e o monitor interativo passaram a mostrar
  "BGP (FlowGuard/ExaBGP): Up" ou "Down/Idle", consultando o comando
  `bgp_status` do socket do FlowGuard (`flowguard_socket` em `config.yaml`,
  só leitura — BGP continua 100% gerenciado pelo FlowGuard).

### v1.5.1 — 2026-07-02 — Renumeração do link com o roteador de borda
- IP do link ponto-a-ponto com o roteador de borda mudou; comentário de
  `capture.iface` em `config.yaml` (que explica por que sniffar em `lo`)
  atualizado pro novo endereço — comportamento de captura não muda, o
  tráfego pra qualquer IP local segue roteando via loopback.

### v1.5.0 — 2026-07-01 — Backend de consumo de dados por cliente (série temporal + top destinos)
- `storage.py`: `client_usage_timeseries` (bytes/bps bucketizados por tempo) e
  `client_top_destinations` (top dst_ip/porta/protocolo, já com ASN/país do
  GeoIP) — as duas usam `idx_client_flow_src (src_ip, ts)` existente, sem
  precisar de índice novo (confirmado com `EXPLAIN QUERY PLAN`).
- `socket_server.py`: comando novo `client_detail` (src_ip + window_s),
  bucket da série temporal escala com a janela (60s/5min/15min/1h).
- **Achado de performance**: `top_src_ips` numa janela de 7 dias levou ~0,9s
  com os dados reais atuais (agregação por `src_ip` sobre toda a retenção).
  Testei um índice de cobertura `(ts, src_ip, bytes, packets)` — **não ajudou**
  (mesmo tempo, o custo é inerente a tocar toda linha da janela pra agregar,
  não tem índice que evite isso). Não adicionei o índice; aceito como latência
  de uma consulta sob demanda (não é chamada em loop de polling).
- Suporta a aba "Top Clientes por Consumo de Dados" no portal (repositório do
  portal): tabela com janela 1h/6h/24h/7d + detalhe por cliente (gráfico de
  tráfego ao longo do tempo, top destinos).

### v1.4.0 — 2026-07-01 — CI no GitHub Actions
- `customer_registry.py` (novo) — `resolve_customer_prefix` extraído de
  `clientguard.py` pra um módulo sem dependência de scapy/FlowGuard. Não era só
  organização: `clientguard.py` importa scapy e insere `/root/flowguard` no
  `sys.path` no topo do arquivo — isso quebraria os testes num runner do GitHub,
  que não tem nem um nem outro. Confirmado bloqueando `scapy` manualmente antes e
  depois da extração.
- `.github/workflows/tests.yml` — roda os 57 testes a cada push/PR na `main`. Só
  instala `pytest`+`pyyaml` (não o `requirements.txt` inteiro) — nenhum módulo
  exercitado pelos testes precisa de scapy/anthropic/rich.
- `requirements.txt`/`requirements-dev.txt` novos (não existiam antes).

### v1.3.0 — 2026-07-01 — Endurecimento do systemd + suíte de testes automatizados
- `clientguard.service`: `NoNewPrivileges`, `ProtectSystem=strict`,
  `CapabilityBoundingSet` (só `CAP_NET_RAW`/`CAP_NET_ADMIN`, mesmo com `User=root`),
  `SystemCallFilter` e demais `Protect*`/`Restrict*`. Testado incrementalmente
  contra o serviço real (não só aplicado às cegas) — score do
  `systemd-analyze security` foi de **9.6 UNSAFE pra 4.0 OK**.
  - `ProtectHome=yes` foi tentado e removido: quebrava o `EXEC` do venv
    (`venv/bin/python3` é symlink pra `/usr/bin/python3`) mesmo reabrindo o
    diretório via `ReadWritePaths` — reproduzido isolado com `systemd-run`.
  - `@privileged` ficou fora do `SystemCallFilter`: bloqueá-lo matava o processo
    com `SIGSYS` no start, por interação com `CapabilityBoundingSet` nesta
    versão do systemd/kernel.
  - Captura via scapy, escrita de whitelist/customers e socket de controle
    revalidados após cada mudança.
- **Suíte pytest** (`tests/`, 57 testes) cobrindo os 7 detectores (acima/abaixo de
  limiar, whitelist, dedup de sinal, reabertura após resolver), `storage.py`,
  `configio.py`, `threat_feed.py`, `geoip.py` (rede mockada) e o matching CIDR de
  `resolve_customer_prefix`. Validada com teste de mutação (quebrei a query do
  scan horizontal e a lógica do amplificador de propósito — a suíte pegou os dois).

### v1.2.0 — 2026-07-01 — Cache de GeoIP persistente
- `geoip_cache` (tabela SQLite nova) — o cache ASN/país deixa de ser só em
  memória; sobrevive a restart do daemon, sem reconsultar a Team Cymru pra IPs
  já vistos. Testado ponta a ponta: enriquecido → gravado → sobrevive a
  `systemctl restart`.
- Corrigido no mesmo pente: falha de rede na consulta à Cymru não marca mais o
  IP como "sem dado" permanentemente — antes, qualquer instabilidade de rede
  virava um `(None, None)` cacheado para sempre (só reiniciava porque o cache
  era em memória; com persistência isso viraria permanente de verdade). Agora
  só grava resultado negativo quando a consulta teve resposta e o IP
  simplesmente não veio nela.

### v1.1.1 — 2026-07-01 — Índice de performance pra queries por dst_ip
- `idx_client_flow_dst (dst_ip, dst_port, ts)` — `detect_malicious_contact`
  (`dst_ip IN (...)`) e `detect_shared_destination` (lookup exato por
  `dst_ip`+`dst_port`) caíam pro índice de `ts` e filtravam `dst_ip` linha a
  linha; confirmado com `EXPLAIN QUERY PLAN` antes/depois. As queries por
  `GROUP BY src_ip` não precisaram de índice novo — o de `ts` já restringe bem
  à janela de detecção antes de agrupar.

### v1.1.0 — 2026-07-01 — CLI, alertas, IA, portal e detectores de correlação/reputação/DNS
- Socket de controle + `clientguard-cli.py`.
- `customers.yaml` migrado de IP exato para CIDR (`network`).
- Cadastradas as redes `x.x.x.0/21` (em 8×`/24`) e `100.64.0.0/10` (CGNAT).
- Whitelist inicial (IP de gerência interno).
- Alertas via webhook (`notifier.py`) — implementado, falta só a URL de destino.
- Explicação de sinais via IA (`ai_client.py`, Claude Haiku).
- Detector `malicious_contact` (feed de reputação próprio, `threat_feed.py`).
- Detector `coordinated_destination` (correlação entre clientes).
- Enriquecimento `dst_asn`/`dst_country` via Team Cymru (`geoip.py`).
- Detector `dns_tunneling`.
- Fix de latência: lock do banco de granularidade fina (não trava mais CLI/portal
  durante chamadas de IA/webhook).
- Aba ClientGuard no portal web (repositório separado).
- Publicado no GitHub.

### v1.0.1 — 2026-07-01 — Serviço systemd
- `clientguard.service`, reinício automático, correção da interface de captura
  (`lo`, tráfego pra IP local roteado via loopback).

### v1.0.0 — 2026-06-30/07-01 — Detectores de esforço baixo
- `port_scan_horizontal`, `port_scan_vertical`, `amplifier_hosted`, `spam_bot`.

### v0.1.0 — 2026-06-30 — Snapshot inicial
- Coletor mínimo (captura passiva via scapy), schema SQLite agregado por `src_ip`.
