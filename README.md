# ClientGuard

**Versão atual: v1.31.0**

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

### v1.31.0 — 2026-07-08 — Liga malicious_contact/coordinated_destination + bloqueio progressivo por reincidência

Pedido do usuário, no seguimento de uma revisão de proteção: os 2 detectores
que faltavam ligar (`malicious_contact`, `coordinated_destination` —
implementados há tempos, sempre desligados em `toggles.yaml` e
`flowspec_mitigation.yaml`) + escalonamento progressivo de bloqueio (estilo
fail2ban) pros 7 detectores.

**Achado real que bloqueava ligar isso com segurança**: `detect_malicious_contact`
e `detect_shared_destination` nunca passavam `mitigation_match` pra
`_record_signal` — diferente de `detect_dns_tunneling`, que já tinha essa
correção (bug real de 2026-07-03, ver changelog antigo). Sem o `mitigation_match`,
ligar `auto_mitigate: discard` nesses dois bloquearia o cliente **inteiro**
(qualquer destino) só por ele ter tocado 1 IP de threat feed ou participado de
1 grupo de destino coordenado — falso positivo caro (derruba a internet do
cliente). Corrigido primeiro: os dois agora escopam a regra FlowSpec ao
destino específico (`dst_prefix=<ip malicioso>/32` / `dst_prefix=<destino
coordenado>/32` + `dst_port`), mesmo padrão que já existia pro túnel DNS.
Só depois disso `toggles.yaml`/`flowspec_mitigation.yaml` foram ligados de
fato (`discard` nos dois).

**Bloqueio progressivo** (`escalation.py`, novo): TTL da próxima mitigação de
um `src_ip` = `base_ttl_s * factor ^ min(reincidências, max_steps)`, até o
teto `max_ttl_s`. Reincidência contada via `edge_mitigations` (histórico
nunca deletado, mecanismo-agnóstico — conta SSH legado e FlowSpec juntos).
Hook único em `flowspec_mitigation.trigger_async` (o único caminho automático
real — a rota manual do portal/CLI continua com TTL escolhido pelo
operador), cobrindo os 7 detectores de uma vez sem tocar em cada um
individualmente. Novo `escalation.yaml`. Socket
(`_cmd_escalation_config`/`_cmd_escalation_set_config`), CLI
(`clientguard-cli escalation list|set`) e portal (nova seção "Bloqueio
Progressivo" na aba ClientGuard) seguem o padrão já existente de
`flowspec_mitigation_config`/`edge_set_auto`. 16 testes novos
(`test_escalation.py` + 2 em `test_detector.py` pro scoping do
`mitigation_match`), 282 no total, todos passando.

**Rollout recomendado**: ligar os toggles e observar `suspicious_clients`
por um tempo antes de armar o bloqueio automático de fato — mesma prática já
usada nesta sessão pros outros detectores.

### v1.30.0 — 2026-07-08 — Série temporal de tráfego por rede inteira (pro gráfico do portal)

Pedido do usuário: a rede CGNAT não aparecia nos gráficos do portal. Causa:
o gráfico de tráfego (aba Gráficos do `flowguard-portal`) só falava com o
FlowGuard (`flow_aggs`, agregado por prefixo PROTEGIDO); o ClientGuard só
tinha série temporal por `src_ip` individual (`client_detail`), nunca por
`customer_prefix` inteiro. Novo comando de socket `network_series`
(`socket_server.py`) + `storage.network_usage_timeseries()`, mesmo padrão de
`client_usage_timeseries` trocando `src_ip` por `customer_prefix` — soma
todos os clientes daquela rede por bucket de tempo.

**Achado real e não trivial durante a implementação**: `client_flow_aggs`
tem **280 milhões de linhas / 42GB** hoje — quase 10x mais que os ~26-30M
registrados há 6 dias (checkpoint de 2026-07-02, ver CHANGELOG daquela
versão). Investigado a fundo (só leitura, nada alterado): **não é bug de
cardinalidade** — `bucket_client_port` (fix de 2026-07-02) segue
funcionando, `src_port` hoje só assume 2 valores reais na amostra
verificada. A causa real são dois commits operacionais de 2026-07-03
(`cc1bbe5`/`e7a6847`, troca de feed capturado, só PPPoE sem sampling) que
derrubaram "sem cliente identificado" de ~90% pra ~0% — quase todo tráfego
que antes era descartado silenciosamente (não virava linha) agora é
atribuído e gravado de verdade. A baseline de 30M foi medida ANTES dessa
troca; comparar direto contra o volume de hoje não é comparação justa.
`dst_port`/`dst_ip` não têm folga pra bucketizar como o `bucket_client_port`
fez com a porta do cliente — `scan_horizontal`/`scan_vertical`/
`coordinated_destination` dependem exatamente dessa granularidade pra
funcionar. **Não é bug, é o novo patamar real de volume** — decisão de
capacidade (reduzir retenção de 7 dias, ou pré-agregação por hora/dia só
pro portal, separada da granularidade fina que a detecção usa — já cogitada
no checkpoint de 2026-07-02, ainda não feita) fica como pendência própria,
fora do escopo desta mudança.

**Por isso**: `network_usage_timeseries()` não ganhou índice dedicado por
`customer_prefix` nesta versão — cheguei a adicionar um `CREATE INDEX
idx_client_flow_customer` no schema, mas revertido antes de commitar: numa
tabela de 280M linhas, construir esse índice ao vivo travaria as escritas
do daemon por um tempo não estimado (SQLite não suporta index build
concorrente), sem stress-test em ambiente controlado antes. Medido direto
(read-only, sem índice): janela de 1h ~0.6s, 6h ~4.2s (aceitável, usa o
range scan do índice de `ts` já existente sobre uma fatia pequena da
retenção) — 24h não terminou em 3+ minutos de teste, matada. O
`flowguard-portal` (ver CHANGELOG de lá) por isso só oferece 1h/6h pra
redes do ClientGuard no seletor de gráfico; 24h/7d ficam desabilitadas até
o índice ser construído num momento controlado (ou o volume da tabela ser
endereçado à parte). Serviço reiniciado em produção sem downtime
perceptível (só código novo, sem migração de schema desta vez).

### v1.29.1 — 2026-07-07 — Ajuste operacional: template cdn migra de 16 pra 17, IA de explicação desligada
`customers.yaml`: template `cdn` sai de `177.86.16.0/24` e passa pra
`177.86.17.0/24` — decisão operacional do usuário, sem mudança de código.
`toggles.yaml`: `ai_explanations` desligado (consistente com a IA estar sem
crédito na conta Anthropic — ver CHANGELOG do `flowguard` v1.27.0 — evita
tentativa de chamada que só vai falhar).

### v1.29.0 — 2026-07-05 — Ajuste fino de limiares e templates via backend/socket
Pedido do usuário: expor "estas novas configurações" (limiares de detecção da
v1.27.0 + templates cgnat/cdn da v1.28.0) editáveis via portal, com ajuste
fino sem precisar mexer em YAML na mão. Esta entrada é a camada de backend;
a UI do portal entra em commit próprio no repositório do site.

**Novo mecanismo de override, sem tocar em config.yaml**: `detection_overrides.yaml`
(novo, vazio por padrão) guarda só as chaves que o operador realmente ajustou —
aplicado por cima de `config.yaml::detection` na carga E no `reload` (comando
`clientguard-cli reload` ou qualquer ação que já disparava `reload_config`),
**sem precisar reiniciar o daemon**. `config.yaml` continua sendo a fonte dos
valores padrão/documentados; o override é só a camada de ajuste pontual, mesmo
espírito de `toggles.yaml`/`edge_mitigation.yaml`.

**Templates ganham CRUD completo**: `configio.save_detection_template`/
`delete_detection_template` — salvar com um nome já existente SUBSTITUI o
template inteiro (não é mescla de campo), validação de nome (slug minúsculo)
e de valores (inteiro positivo).

**Novos comandos no socket** (`socket_server.py`): `detection_cfg` (GET),
`detection_cfg_set` (aplica override + reload), `detection_templates` (GET),
`detection_templates_set`/`detection_templates_del` (CRUD + reload).
`customers_add` ganha `template`/`client_multiplier` opcionais (valida que o
template citado existe); novo `customers_edit` atualiza `name`/
`client_multiplier`/`template` de uma rede JÁ cadastrada sem precisar
del+add — passar valor vazio remove o campo (volta ao comportamento padrão).

**Achado ao implementar**: `customers_add/del` e agora `detection_templates_set/
del` reescrevem o arquivo inteiro a cada chamada (mesmo padrão de
`save_feature_toggles`) — os cabeçalhos-comentário (`CUSTOMERS_HEADER`/
`DETECTION_TEMPLATES_HEADER`) precisaram ser enriquecidos com a documentação
completa de `client_multiplier`/`template`/ordem de precedência, senão a
primeira edição via portal apagava silenciosamente esses comentários
(reproduzido e corrigido ainda nesta leva).

29 testes novos (`test_configio.py`, `test_socket_server.py`) cobrindo o
CRUD de templates, o override read-modify-write, e `customers_edit`
(incluindo limpar campo com valor vazio e rejeitar template inexistente).

### v1.28.0 — 2026-07-05 — Templates de limiar por perfil de rede (cgnat/cdn)
Pedido do usuário: depois de aprender o tráfego real (v1.27.0), gerar templates
de CGNAT e CDN pra facilitar ajustar os limites de cada barramento `/24` sem
recalibrar os mesmos números na mão pra cada rede nova do mesmo perfil.

**Achado que motivou reabrir o limiar global**: analisando só os prefixos SEM
CGNAT (177.86.17/18/19/22/23), o p99.9 de scan_vertical parecia 2217 — bem
acima do que o resto da base precisa — mas isso vinha de UM host só
(`177.86.17.51`) claramente um relay/TURN interno (conectando a dezenas de
clientes CGNAT com centenas/milhares de portas por destino, sustentado por
horas, com volume real — confirmado com o usuário como serviço próprio da
POX). **Esse IP já estava coberto por uma faixa existente em `whitelist.yaml`
(177.86.17.48/29)** — não precisou de mudança ali, só confirma que o
mecanismo certo pra exceção de 1 host específico é whitelist, não afrouxar o
limiar de toda uma `/24`. Sem esse outlier, o limiar "normal" real fica bem
mais baixo — por isso os limiares globais da v1.27.0 (250/300, calibrados só
com dados do CGNAT-PPPOE) voltam pra 50/150, mais sensíveis pra quem não é
CGNAT nem infra própria.

**Novo mecanismo**: `detection_templates.yaml` (novo) define perfis nomeados
de limiar (`cgnat`: 250/300, mesmos números da v1.27.0; `cdn`: 15000/15000,
calibrado nos 2 casos reais de infra própria encontrados — core com fan-out
extremo pra muitos destinos, relay com fan-out extremo de portas). Cada rede
em `customers.yaml` ganha um campo opcional `template:` — resolvido em
`detector.py::_effective_threshold` com prioridade template > global, e o
`client_multiplier` (população combinada) continua aplicando por cima disso
quando os dois se acumulam (ex.: pool CGNAT pós-NAT com template E
multiplier). Sem `template`, o prefixo cai no limiar global normalmente —
nenhuma mudança de comportamento pra quem não usa a feature.

Atribuído nesta leva: `100.64.0.0/10` (CGNAT-PPPOE) e `177.86.20.0/24`/
`177.86.21.0/24` (CGNAT-B20/B21, mantendo o `client_multiplier: 32` já
existente) → `cgnat`; `177.86.16.0/24` (core da POX) → `cdn`.

10 testes novos (`test_configio.py`, `test_detector.py`) cobrindo o loader,
a resolução isolada por template e a combinação template+multiplier;
aplicado com restart do daemon (mesmo motivo da v1.27.0: limiares vêm de
config/customers, só lidos na inicialização).

### v1.27.0 — 2026-07-05 — Recalibra limiares de scan com base em monitoramento real de flow
Pedido do usuário: monitorar o consumo real via flow pra reajustar os limiares
de regra sem risco de bloquear por engano, considerando as redes CGNAT.

**Achado principal**: os limiares antigos (30 hosts/portas) foram pensados pra
"1 cliente = poucos destinos", mas tráfego legítimo de app moderno rotineiramente
ultrapassa isso. Monitorando 12h de flow real do prefixo CGNAT-PPPOE
(100.64.0.0/10, maior diversidade de app residencial): p99 de scan_vertical já
era 37 portas, p99 de scan_horizontal (fora ICMP/portas comuns) era 234 hosts —
ou seja, o limiar de 30 capturava tráfego normal, não abuso. BitTorrent sozinho
gera até ~600 hosts distintos por cliente; jogos/relay P2P empurram
scan_vertical pra 50-250+ portas no mesmo destino rotineiramente.

**Sobre CGNAT especificamente** (o usuário pediu pra lembrar dessas redes):
confirmado que `100.64.0.0/10` (CGNAT-PPPOE) **não precisa de `client_multiplier`**
— o NetFlow captura o IP PRÉ-NAT (1 IP = 1 sessão PPPoE ≈ 1 cliente real), bem
diferente do caso `CGNAT-B20`/`CGNAT-B21` (multiplier=32, IP PÓS-NAT visível
pode ser até 32 clientes reais combinados). O volume alto observado é de apps
legítimas de alto fan-out, não população combinada — por isso a correção foi
nos limiares base, não num multiplicador novo.

Mudanças:
- `scan_horizontal_hosts`: 30 → 250; `scan_vertical_ports`: 30 → 300 (acima do
  p99.5 observado, ainda capturam os casos claramente anômalos confirmados nos
  dados reais — ex. varredura de SSH porta 22 com 403 hosts distintos).
- `common_service_ports` ganha 993 (IMAPS), 6881 (BitTorrent), 51820
  (WireGuard), 5349 (TURN/TLS), 19132 (Minecraft Bedrock), 64738 (Mumble) —
  todos confirmados nos dados reais como causa de falso positivo em massa.
- `detect_scan_horizontal`/`detect_scan_vertical` passam a excluir protocol=1
  (ICMP): o campo "porta" gravado pro ICMP é um artefato do NetFlow (type/code),
  não uma porta de verdade — gerava dst_port como 0/771/2048 com milhares de
  hosts distintos (praticamente todo cliente gera ICMP variado) sem relação
  com scan. Detecção de ping sweep de verdade ficaria pra um detector dedicado,
  fora de escopo aqui.

Aplicado com restart do daemon (limiares vêm de `config.yaml`, só lido na
inicialização — `reload` não cobre essa seção). 2 testes novos confirmando a
exclusão de ICMP nos dois detectores; suíte completa sem regressão.

### v1.26.1 — 2026-07-05 — Sobe orçamento de regras FlowSpec do ClientGuard (20 → 30)
Decisão operacional após a auditoria da v1.26.0 (1189 ocorrências reais do
aviso de orçamento atingido em ~2 dias): `max_active_rules` em
`flowspec_mitigation.yaml` sobe de 20 pra 30, dentro do teto total
compartilhado do FlowGuard (`mitigation.max_rules: 50`) — ainda sobram 20
vagas de margem reservada pra mitigação real de DDoS, que é sempre
prioridade sobre bloqueio de scan. Padrão de código (`DEFAULT_CONFIG` em
`flowspec_mitigation.py`) continua em 20 — só a config já em produção mudou.

Aplicado via `clientguard-cli reload` (recarrega `flowspec_mitigation_cfg`
sem precisar reiniciar o daemon, sem interromper mitigações já ativas).

### v1.26.0 — 2026-07-05 — "sem proteção" não aparece mais pra sinal que já parou de verdade
Pedido do usuário: mesmo com o indicador de atividade da v1.25.0, o selo de
mitigação continuava mostrando "⚠ sem proteção" pra sinais que já não tinham
reconfirmação real há um tempo (🟡 sem atividade) — na prática já parados,
só aguardando o fechamento automático (rede de segurança de 6h).

`_fmt_mitigation_cell` agora só mostra "⚠ sem proteção" quando o sinal está
GENUINAMENTE em andamento (nova `_is_genuinely_active`: mesmo critério do
🟢/🟡 — `resolved=0` E `ts_last_seen` reconfirmado há menos de 90s). Se está
aberto mas sem atividade recente, volta a mostrar "encerrada" (neutro).

**Auditoria à parte, sobre por que muitos sinais mostram "sem mitigação"**
(nenhuma regra jamais tentada): confirmado nos dados reais que a causa
principal é `max_active_rules` (orçamento próprio do ClientGuard no budget
compartilhado de regras FlowSpec do FlowGuard, hoje 20) genuinamente
saturado — as 20 vagas ativas no momento da auditoria estavam TODAS ocupadas
por sinais legítimos e recentes (a maioria com atividade a poucos segundos/
minutos), não por regras órfãs/vencidas que deveriam ter liberado espaço.
Confirmado no log: o aviso "orçamento de regras FlowSpec do ClientGuard
atingido" apareceu **1189 vezes** desde 2026-07-03 — volume de scans
concorrentes está genuinamente acima da capacidade reservada. `port_scan_*`
é reavaliado a cada ciclo (`detector.py` já re-dispara `trigger_async`
enquanto o sinal seguir aberto sem mitigação — sem bug de "só tenta uma
vez"), então assim que uma vaga libera o próximo scan pendente é mitigado
sozinho no ciclo seguinte. Fica como decisão operacional em aberto: subir
`max_active_rules` (reduz a margem reservada pro FlowGuard) ou aceitar que
nem todo scan simultâneo será bloqueado.

Validado com Playwright real e testes unitários da lógica de gating (4 casos
de borda: aberto+fresco, aberto+parado, resolvido, sem ts_last_seen).

### v1.25.0 — 2026-07-04 — Indicador "atividade recente" no CLI (suspicious)
Pedido do usuário: "aberto" sozinho não diz se o sinal está REALMENTE
acontecendo agora — validado ao vivo logo após a v1.24.0: a maioria dos
sinais abertos já estava sem reconfirmação há minutos, ainda dentro da janela
de 6h que os deixa "abertos" (rede de segurança da v1.24.0). Faltava uma
forma rápida de diferenciar isso a olho.

`clientguard-cli suspicious` ganha a coluna "Atividade", calculada a partir
de `ts_last_seen` (já existente): 🟢 "em andamento" quando a última
reconfirmação foi há menos de 90s (~3 ciclos de agregação de 30s, com
folga), senão 🟡 "sem atividade há Xm/Xh". Só exibido pra sinais ainda
abertos — resolvidos mostram "-".

Puramente de exibição no CLI, nenhuma mudança de schema/backend. Contraparte
no portal e no FlowGuard entram em commits próprios.

### v1.24.0 — 2026-07-04 — Sinal suspeito não fica "aberto" pra sempre quando a mitigação expira
Pedido do usuário (mesma correção do FlowGuard, aplicada aqui): um sinal
suspeito continuava "aberto" mesmo muito depois de a mitigação associada já
ter expirado.

Causa raiz: `detector.py` é 100% orientado a evidência nova — cada detector só
toca um sinal quando a condição bate de novo; se o cliente realmente parou
(scan/spam/etc encerrado), o sinal simplesmente nunca mais é tocado e fica
"aberto" pra sempre, sem nenhum fechamento automático por inatividade (bem
mais grave que o caso do FlowGuard, que já fechava sozinho quando o tráfego
caía — aqui não existia fechamento automático nenhum).

- `suspicious_clients` ganha `resolved_reason` ('manual' | 'auto_stale') pra
  distinguir clique manual em "Resolver" de resolução automática.
- Novo `resolve_stale_signals`, rodando 1x/hora junto do prune de retenção:
  resolve sozinho qualquer sinal sem atualização (`ts_last_seen`) há mais de
  `detection.signal_stale_resolve_s` (padrão 6h).
- Selo de mitigação (aba Sinais Suspeitos, portal e CLI) muda de "encerrada"
  (neutro) pra "⚠ sem proteção" (vermelho) quando o sinal segue aberto mas a
  última mitigação já não está mais em vigor.

Validado ao vivo: restart do daemon (junto com o do FlowGuard, que zera as
regras BGP ativas — ver reconciliação automática) fez aparecer corretamente
vários selos "⚠ sem proteção" nos sinais cuja mitigação tinha acabado de cair,
tanto no CLI quanto no portal, sem erro de console. 4 testes novos em
`tests/test_storage.py`.

### v1.23.0 — 2026-07-04 — Repassa trigger_type pro FlowGuard + equipamento na aba Regras
Pedido do usuário: aba Regras sinalizar mecanismo/equipamento/gatilho/status
em toda mitigação em andamento, tanto do ClientGuard quanto do FlowSpec —
mesmo padrão da aba Sinais Suspeitos (v1.22.0). O ClientGuard já tinha toda
essa informação em `edge_mitigations` (`mechanism`/`trigger_type`/`status`);
faltava só o **equipamento**, que agora `_cmd_edge_list` resolve por
mecanismo: `mechanism='ssh'` usa `edge_mitigation.yaml.warmode_device`
(único ACL global); `mechanism='flowspec'` sempre vai pro peer `pppoe` do
FlowGuard (achado real de bug já documentado), reaproveitando o nome já
configurado em `flowspec_mitigation.yaml.pbr_bypass.warmode_device` — sem
duplicar config nem perguntar ao FlowGuard.

**Achado real**: `apply_and_record` (mitigação automática via proxy FlowSpec)
já sabia se a mitigação era `'auto'` (é o próprio parâmetro `trigger_type`
que ele recebe), mas nunca repassava isso pro FlowGuard — toda regra
automática do ClientGuard gravava `trigger_type='manual'` do lado de lá (ver
FlowGuard v1.25.0, que introduziu a coluna). Agora o payload de
`flowspec_add` inclui `"trigger_type": trigger_type`.

`clientguard-cli edge list`/`block list` ganharam colunas Mecanismo/
Equipamento/Gatilho. 6 testes novos (221 no total). Validado em produção
real: uma mitigação automática nova gravou `trigger_type='auto'` e o nome
correto do peer PPPoE/CGNAT como `device_name` do lado do FlowGuard,
confirmado direto no socket.

### v1.22.0 — 2026-07-04 — Selo de mitigação na aba Sinais Suspeitos
Pedido do usuário: sinalizar, na aba Sinais Suspeitos do ClientGuard, se
aquele `src_ip` já participa de alguma mitigação e se ela está em vigor agora
— sem precisar ir na aba Regras conferir cruzado. Nova `storage.
get_latest_edge_mitigation(conn, src_ip)` (diferente de
`get_active_edge_mitigation`, que só olha `status='active'` e é usada pra
decidir se dispara mitigação nova): pega a mitigação MAIS RECENTE desse
`src_ip` independente do status, pra distinguir "nunca foi mitigado" de "já
foi mitigado, mas não está mais em vigor" — essa segunda situação é
exatamente o gap que a reconciliação da v1.21.0 existe pra corrigir, então
vale a pena o operador ver isso destacado. `_cmd_suspicious` (socket) enriquece
cada sinal com `mitigation: {status, mechanism, trigger_type, ts_applied,
ts_expires} | null`. `flowguard-cli suspicious` ganhou coluna "Mitigação"
(🛡 ativa / falhou / encerrada / sem mitigação).

7 testes novos (216 no total). Validado contra o daemon real via socket
direto (`control.send_command`) — confirmado o campo `mitigation` populado
corretamente pra clientes com mitigação ativa.

### v1.21.0 — 2026-07-04 — Corrige mitigações "fantasma": reconciliação com o FlowGuard + redisparo em sinal contínuo
Pedido do usuário: auditar as mitigações ativas do ClientGuard pra saber se
estavam funcionando de verdade. **Achado real e crítico**: `flowguard.service`
reiniciar retira TODAS as regras FlowSpec/RTBH ativas da borda no shutdown
gracioso (`BgpManager.withdraw_all`, comportamento intencional do FlowGuard)
— mas nada avisa o ClientGuard disso. Confirmado em produção: 2 restarts do
`flowguard.service` na mesma sessão fizeram 20 mitigações automáticas
(scanners) sobreviverem só no banco local do ClientGuard, marcadas "active"
por até 6h (`default_ttl_s`) sem bloquear nada de verdade na borda — 32 sinais
de scan continuavam abertos pros mesmos IPs, alguns escaneando no exato
momento da auditoria.

Duas causas compostas, corrigidas juntas:
1. **Sem reconciliação**: o ClientGuard nunca conferia se a regra
   correspondente (`flowspec_rule_id`) ainda existia de verdade no FlowGuard —
   só confiava no próprio prazo local. Nova `flowspec_mitigation.
   reconcile_with_flowguard()`, chamada a cada ciclo de agregação (30s) junto
   com `expire_due` — só faz round-trip ao FlowGuard se houver pelo menos 1
   mitigação `flowspec` "active" localmente. Reaproveita `revert_and_record`
   pra cada mitigação órfã encontrada (mesma lógica que já trata "regra já
   está inativa" como sucesso e já limpa a exceção de PBR associada — nenhuma
   lógica de revert nova).
2. **Sinal contínuo nunca redisparava mitigação**: `apply_and_record` só
   estende o TTL local de uma mitigação "já ativa" (nunca reanuncia), e
   `detector._record_signal` só disparava mitigação em sinal **novo** — um
   cliente que continuasse abusando com o MESMO sinal (nunca fecha sozinho)
   ficava permanentemente sem chance de ser remitigado, mesmo depois da
   reconciliação acima corrigir o registro local. Agora, quando um sinal já
   aberto é "tocado" de novo, o detector confere se há mitigação
   **realmente ativa** pra aquele `src_ip` (`storage.get_active_edge_mitigation`)
   e redispara `trigger_async` se não houver — não é o caminho comum (a
   maioria dos ciclos não tem nada pra fazer), só o reparo desse gap
   específico.

Dois achados reais de concorrência durante a validação em produção (mitigação
de emergência tem que aguentar exatamente esse tipo de rajada — muitos
gatilhos de uma vez):

- Sem uma trava de "já em andamento", a reconciliação redisparava revert pro
  MESMO id a cada ciclo de 30s enquanto a reversão anterior (SSH síncrono pra
  remover a exceção de PBR, serializado por equipamento) ainda estava
  rodando. `expire_due` e `reconcile_with_flowguard` agora compartilham
  `_revert_async` com um conjunto `_reverting_ids` em memória que pula o
  disparo se já houver uma reversão em andamento pro mesmo id.
- Pelo mesmo motivo, o REDISPARO em sinal contínuo (item 2 acima) também
  duplicava: `apply_and_record` de um `src_ip` que já tinha um em andamento
  ainda não tinha gravado a linha local (mesmo lock de PBR do equipamento
  represando várias aplicações de uma vez), então `get_active_edge_mitigation`
  não achava nada e `trigger_async` disparava OUTRA aplicação pro MESMO
  `src_ip` — confirmado em produção criando até 7 regras FlowSpec duplicadas
  (redundantes, não incorretas) pro mesmo cliente/vítima. `trigger_async`
  ganhou a mesma proteção (`_applying_src_ips`), por `src_ip` em vez de por id
  (aqui o que se quer deduplicar é "aplicar duas vezes pro mesmo cliente", não
  um id específico que ainda nem existe).

10 testes novos (209 no total). Validado em produção real (não só testes):
reiniciei o `flowguard.service` (as duas vezes que causaram o gap, durante
outra sessão de trabalho) e depois o `clientguard.service` com o fix — logs
confirmaram as 20 mitigações órfãs sendo detectadas e revertidas
corretamente, e sinais de scan contínuos sendo redisparados com mitigação de
verdade nos ciclos seguintes. As duplicatas criadas antes da 2ª trava existir
foram limpas manualmente via `flowguard-cli flowspec del` (mantendo só a mais
recente por cliente) — o ClientGuard reconciliou sozinho os registros locais
órfãos resultantes disso, confirmando o loop fechado reconciliação → redisparo
funcionando ponta a ponta sob condição real de rajada, não só no caminho feliz.

### v1.20.0 — 2026-07-03 — Revisão do fix de PBR: 4 bugs reais na própria correção
Revisão de código (5 frentes independentes) na correção v1.19.0 achou que a
correção do bypass de PBR podia falhar do mesmo jeito silencioso que o bug
original — corrigido:

- **Falha do push SSH era ignorada** (`apply_and_record`) — se o SSH da exceção
  de PBR falhasse depois do FlowSpec anunciado com sucesso, a mitigação ainda
  ficava gravada/retornada como "active". Agora o status reflete os dois
  passos: só é "active" de verdade se FlowSpec **e** a exceção de PBR deram
  certo; se a exceção falhar, status vira "failed" com o erro registrado.
- **`rate_limit` também recebia bypass de PBR** — errado: `spam_bot`/
  `amplifier_hosted` (destinos da internet, não internos) usam `rate_limit`
  porque a intenção é só desacelerar, não bloquear. Tirar esse tráfego do
  CGNAT quebra a tradução de endereço do fluxo inteiro (IP do pool CGNAT não é
  roteável na internet sem NAT) — um sinal que devia só ficar mais lento virava
  corte total de conexão. `push_pbr_bypass` agora só age em ações `discard`.
- **Reversão removia a exceção mesmo quando o `flowspec_del` falhava de
  verdade** (não só a corrida "já está inativa") — a regra FlowSpec continuava
  ativa protegendo, mas o bypass sumia, voltando a expor o cliente ao
  redirecionamento antes do FlowSpec agir. `revert_and_record` só remove a
  exceção quando o FlowSpec realmente saiu do ar, e agora também reporta (no
  banco e no retorno) se a própria remoção da exceção falhar.
- **Bloqueio manual (`_cmd_block_add`/`_cmd_block_del`) nunca passava por essa
  correção** — o botão "Bloquear IP manualmente" da aba ClientGuard mandava o
  comando direto pro FlowGuard sem `peer="pppoe"` (mesmo bug de peer errado já
  corrigido pro caminho automático) nem a exceção de PBR. Os dois agora ganham
  os mesmos dois ajustes. Resíduo conhecido: um bloqueio manual cujo TTL expira
  sozinho no FlowGuard (sem passar por "Remover" no portal) ainda pode deixar
  uma exceção órfã na ACL — só o caminho automático (via `expire_due`) tem
  rastreamento completo de ciclo de vida hoje.
- Também corrigido, com risco menor: sessões SSH concorrentes pro mesmo
  equipamento agora são serializadas por um lock (`_PBR_BYPASS_LOCK` — dois
  commits simultâneos no modelo de candidate-config do VRP podiam colidir);
  `expire_due` deixou de bloquear a thread principal do daemon (cada reversão
  expirada roda numa thread própria, mesmo padrão fire-and-forget de
  `trigger_async` — evita atrasar o próximo ciclo de agregação de NetFlow se
  várias mitigações expirarem juntas); ações de bypass passaram a ser
  auditadas no mesmo `logs/edge-audit.jsonl` de qualquer outra ação SSH do
  sistema (antes ficavam invisíveis por chamar `_run_commands` direto).
- Generalizado o nome do equipamento nesta entrada de changelog (era citado
  nominalmente, violando a regra de sanitização antes do GitHub).
- 10 testes novos (199 no total) cobrindo cada um dos cenários de falha acima.

### v1.19.0 — 2026-07-03 — FlowSpec era "aplicado" mas não bloqueava de verdade (PBR)
Usuário reportou: mitigação FlowSpec aparecia "ativa" no banco/portal, mas o
cliente não era bloqueado de verdade — testado e confirmado por ele. Diagnóstico
via SSH read-only na caixa PPPoE (roteador de borda, credenciais já em
`warmode.yaml` do FlowGuard) + captura real do NetFlow:

- **BGP FlowSpec estava sendo entregue corretamente** — `display bgp flow peer
  10.77.10.2 verbose` mostrou as rotas recebidas e válidas (`* >`), batendo
  exatamente com as regras ativas do FlowGuard (a checagem inicial com
  `display bgp peer ... verbose` sem `flow` só mostra a AFI unicast, vazia
  nesta sessão — pareceu "0 recebidas" por engano).
- **Causa raiz real**: a caixa PPPoE tem uma `traffic-policy P-CGNAT` GLOBAL
  (`inbound global-acl`) que redireciona todo tráfego de cliente pro A10
  (CGNAT) com precedência MAIOR que o filtro instalado pelo FlowSpec.
  Confirmado com dado real: um cliente com regra `discard` ativa e válida no
  roteador continuava gerando tráfego pro alvo que deveria estar bloqueado,
  inclusive chegando até o IP interno do A10 (`10.71.71.4`).
- A própria política já tinha uma válvula de escape: o classificador
  `C-CGNAT-BYPASS` (ACL 3001), precedência mais alta, comportamento vazio
  (não redireciona — tráfego cai na rota normal, onde o FlowSpec finalmente
  atua).
- **Restrição do usuário, crítica pro design**: a mitigação não pode tirar o
  cliente do ar — só o tráfego sujo deve ser bloqueado, o resto continua
  navegando normal. Por isso a exceção na ACL 3001 **espelha exatamente o
  mesmo match da regra FlowSpec** (`_bypass_rule_clause`, novo) — nunca mais
  amplo (mesmo src+dst+protocolo+porta que já estava sendo bloqueado) — só
  aquele fluxo específico sai do redirecionamento pro CGNAT, o resto do
  tráfego do cliente continua sendo traduzido e saindo normalmente.
- `flowspec_mitigation.py` ganha `pbr_bypass` (novo, desabilitado por padrão
  em `DEFAULT_CONFIG` — habilitado manualmente em produção após validação):
  `push_pbr_bypass`/`remove_pbr_bypass` reaproveitam
  `edge_mitigation._run_commands` (mesma conexão SSH/Netmiko já usada pelo
  mecanismo legado) pra inserir/remover, via `rule_id_base + flowspec_rule_id`
  (determinístico, sem precisar consultar o roteador pra saber o ID
  atribuído), uma regra na ACL configurada (`acl_number`, `warmode_device`).
  Acionado automaticamente dentro de `apply_and_record`/`revert_and_record`/
  `expire_due` — nenhuma mudança de comportamento pra quem não habilitar
  `pbr_bypass.enabled`.
- **Achado de plataforma**: a plataforma do roteador de borda usa modelo de
  candidate-config — precisa de `commit` explícito depois de editar a ACL
  (confirmado nos comandos manuais que o usuário já usava em `warmode.yaml`).
  `send_config_set` do Netmiko entra/sai de `system-view`/ACL automaticamente,
  mas `quit` (sair da sub-view da ACL) + `commit` explícitos são incluídos em
  todo comando gerado por este módulo.
- Validado em produção: aplicado retroativamente (backfill manual, script
  avulso) nas 7 mitigações FlowSpec já ativas no momento — confirmado via
  `display acl 3001` que as 7 regras (50181-50188) foram commitadas, e via
  `client_flow_aggs` que os 7 clientes deixaram de gerar tráfego pro alvo/porta
  específicos que estavam sendo escaneados enquanto continuavam gerando
  tráfego normal (navegação) sem interrupção. Sem teste controlado
  ponta-a-ponta (não dá pra gerar tráfego como se fosse o cliente real a
  partir daqui) — correlação temporal forte (7/7 pararam simultaneamente ao
  aplicar o fix), mas não 100% definitivo; sugerido ao usuário validar com um
  teste ao vivo próprio se quiser certeza total.
- 189 testes pytest (12 novos: tradução CIDR→wildcard Huawei, montagem da
  cláusula de ACL espelhando o match do FlowSpec, push/remove via SSH mockado,
  integração com `apply_and_record`/`revert_and_record`).

### v1.18.0 — 2026-07-03 — Mitigação de port scan mais precisa + 2 bugs reais
- Antes, mitigar um scan (discard ou rate_limit) sempre mirava o cliente
  inteiro (`src_prefix/32`) — rate_limit mal freava o scan de verdade (sonda
  é pacote pequeno, não banda) e discard custava caro (derrubava toda a
  conexão do cliente). Agora `port_scan_horizontal` recorta pela porta
  escaneada e `port_scan_vertical` pelo IP vítima — e com esse recorte,
  passam a usar `discard` (seguro agora, só afeta a porta/vítima específica).
- `dns_tunneling` ganhou o `dst_prefix` do resolver suspeito no recorte
  (já tinha protocol/dst_port, faltava isso) — rate-limit não afeta mais
  consultas a resolvers legítimos.
- **2 bugs reais corrigidos** (ambos faziam a mitigação "aplicar" no banco
  sem efeito real nenhum): (1) toda mitigação ia pro peer BGP errado
  ('main'/NE8000BGP em vez de 'pppoe'/NE8000-PPPOE, que é por onde o
  tráfego de cliente realmente passa desde a v1.17.1); (2) `build_rule()`
  descartava o recorte inteiro no branch `discard`, só aplicava no
  `rate_limit`.

### v1.17.1 — 2026-07-03 — Escuta só a caixa PPPOE, desliga a caixa BGP
- Pedido do usuário: parar de escutar as 2 caixas (NE8000BGP na porta 2055,
  mesmo feed do FlowGuard, + NE8000-PPPOE na 2060) — agora só a PPPOE.
  `bpf_filter` de `"udp port 2055 or udp port 2060"` para `"udp port 2060"`.
- Confirmado em produção: volume por ciclo caiu de ~110-125k pra ~20-30k
  flows, e "sem cliente identificado" caiu de ~16k pra ~1 por ciclo — a
  maior parte do tráfego não-identificável vinha da caixa BGP (tráfego
  geral de internet dos prefixos monitorados, não sessão de cliente PPPoE).

### v1.17.0 — 2026-07-03 — Captura passa do A10 (CGNAT) pro NE8000-PPPOE
- Pedido do usuário: escutar mais um equipamento de NetFlow (o A10 que faz
  CGNAT) além do NE8000 já observado. Confirmado por captura real que o
  `src_ip` desse feed é PRÉ-NAT (IP interno do cliente em `100.64.0.0/16`,
  um IP por cliente) — cada cliente já chega identificável, sem precisar de
  `client_multiplier`.
- **Achado real na validação**: o A10 não preenche o campo `SAMPLING_INTERVAL`
  do NetFlow e não tem sampling configurado no equipamento (log completo,
  não amostrado) — volume de ~157 mil flows/25s estourou a fila interna do
  daemon (200k, drenada 1x por ciclo de 30s de agregação), causando descarte
  silencioso de dezenas de milhares de flows por minuto. Novo campo de
  config `capture.sampling_rate_by_peer` (por IP de origem do export)
  resolveria o cálculo de bytes/pacotes, mas não o problema de volume em si.
- A pedido do usuário, a captura do A10 foi pausada (removida do
  `bpf_filter`) e substituída pelo NetFlow do NE8000-PPPOE (mesmo roteador
  usado pro Modo Guerra/ACL, exportando numa porta separada) — volume bem
  menor (~155 flows/s), sem risco de estourar a fila. Também confirmado
  pré-NAT, mesma lógica de sampling ausente (assumido 1:1).
- **Incidente durante a validação**: ao tentar reiniciar o serviço isolando
  essa mudança do trabalho em progresso (migração pra mitigação via FlowSpec,
  ainda não commitada), uma versão temporária de `clientguard.py` ficou
  inconsistente com `detector.py` (`edge_cfg` vs `mitigation_cfg`),
  derrubando o daemon em crash-loop por ~1min até ser corrigido restaurando
  o arquivo completo. Lição: nunca isolar um arquivo do trabalho em
  progresso de outra pessoa sem conferir consistência com os arquivos que
  ele importa/chama antes de reiniciar um serviço de produção.
- **Pendência em aberto**: `client_multiplier: 32` em `customers.yaml` pra
  `100.64.0.0/10` pressupõe IP compartilhado por vários clientes (pós-NAT) —
  mas confirmamos que é pré-NAT (1 IP = 1 cliente). Ainda não corrigido,
  precisa de decisão do usuário.

### v1.16.0 — 2026-07-02 — Detalhe de mitigação de borda + falha passa a ficar registrada
- `edge_mitigations` ganhou 4 colunas (`apply_commands`, `apply_output`,
  `revert_commands`, `revert_output`) — os comandos VRP exatos resolvidos
  (com o IP já substituído) e a saída bruta do equipamento, tanto pra
  aplicar quanto pra reverter. Botão "Detalhes" novo na aba Regras
  (ClientGuard → Mitigação direta na borda) mostra tudo isso.
- **Mudança de comportamento importante**: antes, uma tentativa de aplicar
  que FALHASSE não deixava rastro nenhum além do audit log em disco
  (`logs/edge-audit.jsonl`) — `apply_and_record` só gravava em
  `edge_mitigations` quando dava certo. Agora grava sempre, com
  `status='failed'` quando falha, erro incluído — resolve exatamente o
  cenário "apliquei e não apareceu em lugar nenhum" (era um bug de driver
  Netmiko, ver v1.15.0, mas o sintoma "não aparece" também era esse: falha
  nunca virava visível na UI).
- `clientguard-cli edge apply/revert` ganhou timeout de 25s (era 6s, curto
  demais pra uma conexão SSH de verdade — mesmo timeout que o CGI do portal
  já usava pra essa ação).
- 3 testes novos (134 no total).

### v1.15.0 — 2026-07-02 — Corrige driver Netmiko: mitigação de borda não estava aplicando de verdade
- **Bug real** (mesma causa raiz documentada no CHANGELOG do `flowguard`):
  `warmode.yaml` tinha o equipamento `NE8000BGP` com `device_type:
  huawei_vrp`, mas esse NE8000 de carrier usa o modelo de config candidata
  do VRP — ao aplicar uma ACL via `edge_mitigation.py`
  (`conn.send_config_set(...)`), o equipamento pergunta interativamente se
  deve commitar antes de sair do modo de configuração, e o driver
  `huawei_vrp` não sabe responder isso: a chamada travava até o timeout
  (`Pattern not detected: '>' in output`), sempre falhando. Como
  `apply_and_record` só grava em `edge_mitigations` quando a aplicação
  funciona, TODA tentativa de mitigação na borda falhava silenciosamente —
  sem erro visível na aba ClientGuard do portal e sem aparecer em nenhuma
  lista, só no audit log (`logs/edge-audit.jsonl`).
- Corrigido trocando `device_type` pra `huawei_vrpv8` em `warmode.yaml`
  (fora do git, ajuste direto no servidor). Validado ponta a ponta contra o
  equipamento real: `edge_mitigation.apply_block()`/`revert_block()`
  aplicaram e removeram uma regra de ACL de teste (prefixo RFC 5737) com
  sucesso pela primeira vez.
- **Se você aplicou uma mitigação pela aba ClientGuard antes desta correção
  e ela não apareceu em lugar nenhum, é esse bug — não era um problema de
  onde procurar na tela, o comando SSH nunca chegou a aplicar nada de
  verdade no equipamento.**

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
