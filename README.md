# ClientGuard

**Versão atual: v1.14.0**

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
14. **Configurações via portal** (`toggles.yaml`) — liga/desliga cada um dos 7
    detectores e a explicação por IA individualmente por checkbox, e um botão
    que marca todos os sinais suspeitos abertos como resolvidos de uma vez.

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
| `edge_mitigation.py` | Mitigação direta na borda via SSH (ACL) — dirigida por sinal, gatilho automático opcional |
| `tools/synth_client_flows.py` | Gerador de NetFlow sintético para testar os detectores |
| `tools/compact_client_flow_aggs.py` | Compactação offline de `client_flow_aggs` (rodar 1x, daemon parado) |
| `tests/` | Suíte pytest (126 testes) — detectores, storage, configio, threat feed, geoip, socket, mitigação de borda |

## Testes

```
./venv/bin/pytest        # 92 testes, ~1s, sem rede/captura real
```

## Uso

```
systemctl status clientguard
clientguard-cli status
clientguard-cli suspicious
clientguard-cli clear-suspicious
clientguard-cli top
clientguard-cli whitelist add|del <ip>
clientguard-cli customers add|del <network> <prefix>
clientguard-cli toggles list
clientguard-cli toggles set <funcao> on|off
```

## Changelog

Formato livre, mais detalhado que o log do git — pense nisso como o "o que mudou e
por quê" de cada leva de trabalho.

### v1.14.0 — 2026-07-02 — `block_add` marca `origin: clientguard` pro FlowGuard
Base pra aba "Regras" unificada do portal (histórico de toda interação com a
borda, separado por aplicação — ver CHANGELOG do `flowguard`): `_cmd_block_add`
agora manda `"origin": "clientguard"` junto do `flowspec_add` que pede pro
FlowGuard, além do `label` de texto livre que já existia. A regra "de verdade"
continua vivendo só no FlowGuard (única sessão BGP) — isto só marca quem pediu.
131 testes pytest (novo: assert de `origin` no payload de `block_add`).

### v1.13.0 — 2026-07-02 — Desempenho: fim dos timeouts constantes do portal
Usuário reportou "FlowGuard: timeout ao falar com o daemon" constante no portal.
Investigação achou DUAS causas reais, distintas e independentes:

1. **Contenção de lock (causa dominante)** — confirmado com `py-spy dump` no
   processo real: todo comando de LEITURA do socket (`status`, `top`,
   `suspicious`, `client_detail`, `edge_list`) compartilhava a MESMA conexão
   SQLite e o MESMO `db_lock` usado pela escrita (agregação + os 7
   detectores rodando a cada ciclo) — não era deadlock, era fila: uma query
   de detecção genuinamente lenta segurava o lock por vários segundos e
   travava até um `status` trivial atrás dela. Fix: `socket_server.py` ganhou
   `_read_only_conn()`/`_read_conn()` — os comandos de leitura agora abrem
   uma conexão SQLite dedicada e somente-leitura (`file:...?mode=ro`), fora
   do `db_lock` — SQLite em modo WAL permite leitores concorrentes sem
   bloquear nem ser bloqueado pelo escritor. Escrita continua 100% via
   `d.conn`/`d.db_lock`, sem mudança nenhuma aí. Resultado medido: `status`
   caiu de ~2-18s (variável, sob contenção) pra ~0.2s consistente;
   `suspicious`/`edge_list`/`toggles` ficaram sub-10ms mesmo com outras
   queries pesadas rodando ao mesmo tempo.
2. **`total_rows` recalculado do zero a cada `status`** — era um
   `COUNT(*)` sem `WHERE` sobre `client_flow_aggs` (~2s sob ~26M linhas),
   chamado a cada poll de 5s do portal. Fix: `ClientGuardDaemon.total_rows`
   agora é um contador incremental em memória (soma no insert, subtrai no
   prune), só faz UMA varredura completa no startup do daemon.

Também investigado e corrigido, embora com impacto menor do que o esperado:
`client_flow_aggs` já tinha ~30.6M linhas — a chave de agregação incluía a
porta de origem EFÊMERA do cliente (nenhum detector além de `amplifier_hosted`
olha essa porta), inflando a tabela sem ganho de detecção, mesma classe do bug
já corrigido no `flow_aggs` do FlowGuard. `clientguard.py`/`storage.py`
ganharam `bucket_client_port()` — colapsa a porta de origem pra 0 exceto
quando é uma das portas de amplificação configuradas (as únicas que um
detector precisa distinguir com exatidão). **Diferente do FlowGuard, aqui o
ganho foi modesto (~15-25%, não ~99%)** — a maior parte da cardinalidade do
ClientGuard é tráfego genuinamente distinto (centenas de clientes ativos, cada
um contatando dezenas/centenas de destinos reais por ciclo), não duplicação
artificial. Rodado uma vez em produção via `tools/compact_client_flow_aggs.py`
(novo, roda OFFLINE com o daemon parado): 30.627.912 → 26.137.846 linhas
(-14.7%, soma de bytes preservada — invariante checado no próprio script,
aborta se não bater). VACUUM reduziu o arquivo de 4.7G pra ~3.9G. **Achado
real na primeira rodada**: sem `ANALYZE` depois da reescrita da tabela, o
query planner escolheu um SCAN completo do índice `(src_ip, ts)` pra
`COUNT(DISTINCT src_ip)` mesmo filtrando só os últimos 30s (~2s) — rodar
`ANALYZE client_flow_aggs` (agora dentro de `compact_client_flow_aggs`, não
só no `prune_old_aggs` periódico) resolveu sem precisar de índice novo.

Timeout dos endpoints mais pesados do portal (`clientguard-top.sh`,
`clientguard-client-detail.sh` — fazem `GROUP BY`+`ORDER BY` sobre a tabela
inteira pra janelas longas como 7 dias) subiu de 5s pra 20s — mesmo com a
contenção de lock resolvida, essa consulta específica ainda leva ~10-16s sob
o volume atual de dados (confirmado com Playwright real: painel "Top
Clientes" com janela de 7d renderizou em ~9s, sem erro). Não é um problema
resolvido de vez — se o volume de clientes/tráfego crescer bastante mais,
provavelmente vale a pena um rollup pré-agregado (hora/dia) só pro portal,
separado da tabela de granularidade fina que a detecção usa.

Backup do banco antes da compactação preservado em
`db/client_flow.sqlite.bak-preCompact` (4.7G) — não removido automaticamente,
apagar manualmente quando confirmar que está tudo estável.

130 → 131 testes pytest (novo: `test_status_reports_total_rows_from_memory_not_a_query`,
mais os testes de `bucket_client_port`/`compact_client_flow_aggs` em
`test_storage.py`).

### v1.12.0 — 2026-07-02 — Mitigação direta na borda (SSH/ACL), sem depender do FlowGuard
- Até aqui o único jeito de bloquear um cliente abusivo era `block_add`/`del`/
  `list`: um proxy fino pro socket do FlowGuard, que anuncia uma regra FlowSpec
  via BGP — depende da sessão BGP do FlowGuard com o roteador estar de pé. Novo
  módulo `edge_mitigation.py` conecta via SSH (Netmiko) direto no roteador de
  borda e insere/remove uma regra de ACL por IP de origem — caminho
  independente, útil quando a sessão BGP está fora do ar ou como alternativa
  mais cirúrgica ao bloqueio via FlowSpec.
- Reaproveita a lista de equipamentos/credenciais já cadastrada no "Modo
  Guerra" do FlowGuard (`warmode.yaml`) por nome de equipamento
  (`warmode_device` em `edge_mitigation.yaml`) — evita duplicar senha SSH do
  mesmo roteador em dois lugares. A técnica (ACL, não comando EXEC livre) e o
  gatilho por sinal são exclusivos do ClientGuard.
- `acl_number`/`apply_commands`/`revert_commands` em `edge_mitigation.yaml`
  são um template (`{ip}`/`{acl_number}` substituídos a cada chamada) —
  ajustar a sintaxe exata e o número do ACL real antes de habilitar em
  produção; só editável direto no arquivo (não exposto por portal/CLI), pra
  não abrir um canal de injeção de comando arbitrário via formulário web.
- Gatilho automático por tipo de detector (`auto_mitigate` em
  `edge_mitigation.yaml`) — desabilitado por padrão em todos os 7 detectores
  (opt-in explícito), editável via `clientguard-cli edge auto set` ou pelo
  portal. Disparo em thread separada (fire-and-forget) pra não travar o ciclo
  de agregação esperando uma conexão SSH.
- Idempotente: aplicar numa origem que já tem mitigação ativa só estende o
  TTL, não empilha regra duplicada no ACL. TTL vencido é revertido sozinho a
  cada ciclo de agregação (`edge_mitigation.expire_due`, mesmo princípio do
  `ttl_s` que já existia no bloqueio via FlowSpec).
- Novo comando de socket `edge_apply`/`edge_revert`/`edge_list`/`edge_config`/
  `edge_set_auto`, subcomando `clientguard-cli edge apply|revert|list|auto`, e
  seção "Mitigação na borda" no portal (aplicar por linha na tabela de sinais
  suspeitos, tabela de mitigações ativas/histórico, config dos gatilhos
  automáticos).
- `netmiko`/`paramiko` novos em `requirements.txt` e no workflow de CI (só
  usados por `test_edge_mitigation.py` pra montar os mocks — nenhum teste
  conecta de verdade via rede). `test_socket_server.py` é novo e, de
  passagem, também cobriu `block_add/del/list`, que não tinham teste
  automatizado antes.

### v1.11.0 — 2026-07-02 — Migra WhatsApp de CallMeBot pra Evolution API self-hosted
- `notifier.py`: `send_whatsapp()` reescrito pra falar com a Evolution API
  self-hosted (`/root/evolution-api/`) em vez da CallMeBot — mesma migração do
  FlowGuard, ver CHANGELOG de lá pro detalhe da conexão. Assinatura simplificou
  pra `send_whatsapp(message)`: destino (grupo/número) e apikey agora vêm de
  `/root/evolution-api/notify.yaml`/`.env`, compartilhados com o FlowGuard — só
  existe UMA sessão WhatsApp real, configurável pelo portal.
- `detector.py`: `_record_signal` chama `notifier.send_whatsapp(message)` sem
  mais passar `wa_dest`/`wa_apikey` (removidos de `config.yaml`) — `wa_cfg`
  continua roteado por todos os detectores só pra decidir *se* alerta
  (`alerts.whatsapp`/`min_confidence_wa`), não mais o destino.

### v1.10.0 — 2026-07-02 — Aplicar várias funções de uma vez, de forma atômica
- `save_feature_toggles`/socket `set_toggles` (novo) aplicam N mudanças numa
  única leitura+escrita, com lock dedicado (`_TOGGLES_LOCK`) no socket.
  Achado real ao revisar o botão "Aplicar novas configurações" recém-criado
  no portal: ele mandava 1 requisição por checkbox marcado, em paralelo — como
  o socket do ClientGuard atende conexões em threads de verdade
  (`ThreadingUnixStreamServer`, não asyncio), duas dessas requisições
  concorrentes podiam intercalar leitura/escrita de `toggles.yaml` e perder
  uma mudança silenciosamente (thread A lê, thread B lê o mesmo estado antigo,
  A grava, B grava por cima sem ver a mudança de A). `set_toggle` (1 chave) e
  `clientguard-cli toggles set` continuam funcionando — passaram a delegar
  pra `set_toggles` internamente.
- Testes novos em `test_configio.py` cobrindo aplicação em lote, validação de
  chave desconhecida (não escreve nada se alguma chave for inválida) e o
  cenário de regressão específico (várias chaves de uma vez não pode perder
  nenhuma).

### v1.9.0 — 2026-07-02 — Alertas via WhatsApp (CallMeBot)
- `notifier.py` ganhou `send_whatsapp()` (CallMeBot, mesmo provedor/lógica do
  FlowGuard, deliberadamente duplicado — os dois projetos continuam
  independentes) ao lado do `send_webhook()` já existente.
- `detector.py`: `_record_signal` dispara WhatsApp pra qualquer sinal NOVO
  (não atualização de sinal já aberto) quando `alerts.whatsapp` está ligado e
  a confiança do sinal atinge `alerts.min_confidence_wa` (default 0.8, pra
  não virar spam com sinais de baixa confiança). `wa_cfg` foi roteado como
  novo parâmetro opcional por todos os 7 detectores até `run_all`, mesmo
  padrão já usado pra `webhook_url`.
- `config.yaml`: `alerts.whatsapp`/`wa_dest`/`wa_apikey`/`min_confidence_wa`
  (novos), ao lado do `webhook_url` já existente.

### v1.8.0 — 2026-07-02 — Configurações via portal: liga/desliga detectores + limpar suspeitos
- `toggles.yaml` (novo, separado do `config.yaml` — mesmo motivo de
  whitelist/customers: editar via portal não pode reescrever/perder os
  comentários do config principal) guarda o estado de cada um dos 7
  detectores e da explicação por IA. Chave ausente ou arquivo inexistente =
  habilitado, então quem nunca mexe nisso não tem mudança de comportamento.
- `detector.run_all` passou a aceitar `toggles` e pula qualquer detector
  desabilitado; `ai_explanations=false` passa `ai_client=None` pros
  detectores nesse ciclo, sem tocar em `ai_client.py`.
- Novos comandos no socket do daemon: `toggles` (lista o estado atual),
  `set_toggle` (liga/desliga um, recarrega o daemon) e `clear_suspicious`
  (marca TODOS os sinais abertos como resolvidos de uma vez — usa
  `resolved=1`, igual `resolve_signal`, então o histórico/evidência/
  explicação de IA continuam consultáveis na aba "Resolvidos").
- `clientguard-cli toggles list|set` e `clientguard-cli clear-suspicious`.
- Portal: nova seção "Configurações — Funções do ClientGuard" na aba
  ClientGuard, com um checkbox por função (`clientguard-toggles.sh`, novo) e
  um botão "Limpar hosts suspeitos" (com confirmação, reaproveita
  `clientguard-suspicious.sh` com `clear_all: true`).
- Achado ao testar em produção: `malicious_contact` continuava disparando
  mesmo com `threat_feed.enabled: false` no `config.yaml` — esse flag só
  controla o loop de atualização do feed em segundo plano, nunca gateou o
  detector em si. O toggle novo é o primeiro jeito de desligar esse detector
  de fato sem editar `detector.py`/reiniciar o daemon.

### v1.7.0 — 2026-07-02 — Bloqueio manual de IP via portal/CLI
- Novo comando `block_add`/`block_del`/`block_list` no socket do daemon
  (`clientguard-cli block add|del|list`) e endpoint no portal — bloqueia
  cliente abusivo por src_prefix. É um proxy fino: a regra FlowSpec real
  (com TTL, expiração etc.) é criada e vive só no FlowGuard, que é quem
  fala BGP com o roteador; o ClientGuard nunca guarda estado próprio disso.

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
