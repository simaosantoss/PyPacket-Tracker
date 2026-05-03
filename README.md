# Packet Sniffer em Python com Scapy

Projeto académico de Redes de Computadores para capturar, ler e analisar pacotes de rede. O objetivo é mostrar, de forma simples e legível, o funcionamento base de um sniffer: escolha da fonte, filtros, parsing de protocolos, deteção de eventos com algum estado, logging estruturado, estatísticas finais e consulta de pacotes processados.

Este README é o guia completo de exploração do projeto. Basta seguir as secções abaixo para testar todas as funcionalidades implementadas.

O projeto não pretende substituir ferramentas como Wireshark ou tcpdump. Foi feito para demonstração, aprendizagem e extensão.

## Funcionalidades

- Captura live numa interface de rede.
- Leitura offline de ficheiros `.pcap`.
- Validação clara dos argumentos da CLI.
- Filtros por IP, IP de origem, IP de destino, MAC, protocolo, porta de origem, porta de destino, fragmentação IPv4, identificador IPv4 e flag `MF`.
- Suporte de expressões BPF em modo live.
- Combinação de expressões BPF com filtros da CLI em modo live.
- Escrita opcional da captura crua para `.pcap`.
- Parsing de Ethernet, ARP, IPv4, ICMP, TCP e UDP.
- Resumo curto por pacote com número, fonte, timestamp, protocolo, endpoints, TTL, flags TCP, serviços reconhecidos e tamanho.
- Vista detalhada interativa de pacotes no fim da execução.
- Deteção simples de fragmentação IPv4, incluindo `id`, `offset` e `MF`.
- Acompanhamento lógico de conjuntos de fragmentos IPv4 e deteção heurística de conjuntos completos.
- Identificação conservadora de serviços:
  - DNS: porta 53.
  - DHCP: portas UDP 67/68.
  - HTTP: porta TCP 80.
- Reconhecimento de alguns detalhes UDP quando o Scapy decodifica a camada:
  - `DNS query`
  - `DNS response`
  - `DHCP Discover`
  - `DHCP Offer`
  - `DHCP Request`
  - `DHCP ACK`
- Tracking simples de:
  - ARP request/reply.
  - ICMP echo-request/echo-reply.
  - DNS query/response, com referência à linha da query.
  - TCP 3-way handshake.
  - término TCP por `FIN` ou `RST`.
  - possível traceroute por TTL crescente.
  - fragmentos IPv4 do mesmo datagrama.
- Referências entre pacotes relacionados, como `request in line 12` ou `fragmento do conjunto em 211 e 212`.
- Logging estruturado em `txt`, `csv` e JSON Lines.
- Estatísticas finais por protocolo, top talkers e eventos detetados.

## Estrutura

```text
main.py            CLI, validação de argumentos, filtros e resumo final
capture.py         captura live/offline e processamento de cada pacote
parsing.py         parsing, filtros da CLI, resumos, logs e detalhe interativo
tracking.py        tracking de ARP, ICMP, DNS, TCP, traceroute e fragmentação IPv4
logging_output.py  escrita de logs em txt, csv e json
stats.py           estatísticas finais da execução
README.md          guia único de instalação, exploração e demonstração
```

## Requisitos

O projeto usa Python 3 e Scapy.

Criar e ativar uma virtualenv é recomendado:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install scapy
```

Confirmar que o Scapy ficou instalado:

```bash
python3 -m pip show scapy
```

A ajuda da CLI funciona mesmo sem Scapy instalado, porque o Scapy só é carregado quando é preciso capturar ou ler pacotes:

```bash
python3 main.py --help
```

Em modo live, normalmente são necessários privilégios de administrador.

macOS, normalmente com interface `en0`:

```bash
sudo .venv/bin/python main.py -i en0
```

Linux/CORE, normalmente com `eth0`, `ens33` ou `wlan0`:

```bash
sudo python3 main.py -i eth0
```

No macOS, quando for usada uma virtualenv, recomenda-se chamar explicitamente `.venv/bin/python` com `sudo`. Assim evita-se usar outro Python sem Scapy instalado.

## Identificar a interface

macOS:

```bash
ifconfig
```

Linux/CORE:

```bash
ip addr
```

Nos exemplos seguintes, `en0` ou `eth0` devem ser substituídos pela interface real do ambiente de teste.

## CLI completa

```text
-h, --help                   mostra a ajuda
-i, --interface INTERFACE    interface de rede para captura em tempo real
-r, --pcap PCAP              ficheiro .pcap para leitura offline
-c, --count COUNT            número máximo de pacotes; 0 significa sem limite
--bpf BPF                    expressão BPF, por exemplo "tcp port 80"
--ip IP                      filtrar por IP de origem ou destino
--src-ip SRC_IP              filtrar por IP de origem
--dst-ip DST_IP              filtrar por IP de destino
--mac MAC                    filtrar por MAC de origem ou destino
--protocol PROTOCOL          filtrar por arp, ip, icmp, tcp ou udp
--src-port SRC_PORT          filtrar por porta TCP/UDP de origem
--dst-port DST_PORT          filtrar por porta TCP/UDP de destino
--fragmented                 aceitar apenas pacotes IPv4 fragmentados
--ip-id IP_ID                filtrar por identificador IPv4
--mf-only                    aceitar apenas pacotes IPv4 com flag MF ativa
--write-pcap WRITE_PCAP      guardar a captura crua live num ficheiro .pcap
--timeout TIMEOUT            tempo limite da captura live, em segundos
--log-file LOG_FILE          ficheiro de saída para logging estruturado
--log-format {txt,csv,json}  formato do log
```

Regras importantes:

- Deve ser usada exatamente uma fonte: `--interface` ou `--pcap`.
- `--write-pcap` só funciona em modo live.
- `--bpf` só funciona em modo live.
- Em modo offline, devem ser usados os filtros por opções da CLI, como `--protocol`, `--ip` ou `--dst-port`.
- `--log-file` e `--log-format` têm de ser usados em conjunto.
- `--write-pcap` deve apontar para um ficheiro com extensão `.pcap`.
- `--protocol ip` aceita qualquer pacote IPv4, incluindo ICMP, TCP e UDP.

## Fluxo rápido inicial

Este é o percurso mais curto para provar que o projeto está funcional antes de seguir para os testes completos. Para explorar todas as funcionalidades, deve ser consultada também a secção "Roteiro de validação completa".

1. Ver a ajuda:

```bash
python3 main.py --help
```

2. Fazer uma captura live curta.

macOS:

```bash
sudo .venv/bin/python main.py -i en0 -c 10
```

Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 10
```

3. Gerar um PCAP para testes offline:

macOS:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
```

4. Ler o PCAP gerado:

```bash
python3 main.py -r captura.pcap -c 10
```

5. Gerar um log CSV:

```bash
python3 main.py -r captura.pcap -c 10 --log-file captura.csv --log-format csv
```

6. Fazer uma captura filtrada:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp -c 10
```

7. No fim da execução, se o terminal for interativo, pode ser escolhido um número de pacote na prompt. A saída é feita com `0`.

## Formato do output

Cada pacote processado aparece numa linha curta:

```text
[12] [live:en0] [14:02:10] Ethernet | IPv4 | UDP | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | DNS query | 72 bytes
```

Quando o pacote vem de PCAP, a fonte aparece como `offline`:

```text
[3] [offline:captura.pcap] [14:05:31] Ethernet | ARP | reply | 10.0.0.2 -> 10.0.0.1 | aa:bb:cc:dd:ee:ff -> ff:ff:ff:ff:ff:ff | request in line 2 | 42 bytes
```

Quando o tracker relaciona pacotes, o resumo inclui uma referência:

```text
[13] [live:en0] [14:02:11] Ethernet | IPv4 | UDP | 8.8.8.8:53 -> 10.0.0.1:53000 | ttl=64 | DNS response | 72 bytes | request in line 12
```

## Captura live

Capturar sem filtros:

```bash
sudo .venv/bin/python main.py -i en0
sudo python3 main.py -i eth0
```

Capturar um número limitado de pacotes:

```bash
sudo .venv/bin/python main.py -i en0 -c 50
```

Capturar durante um tempo limitado:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30
```

Interromper manualmente:

```text
Ctrl+C
```

Resultado esperado: o programa imprime os pacotes observados, a mensagem de interrupção se aplicável, o resumo final, as estatísticas e a prompt interativa quando houver pacotes e o terminal permitir input.

## Leitura offline de PCAP

Ler um PCAP:

```bash
python3 main.py -r captura.pcap
```

Ler apenas os primeiros 20 pacotes processados:

```bash
python3 main.py -r captura.pcap -c 20
```

Ler um PCAP com filtros:

```bash
python3 main.py -r captura.pcap --protocol udp --dst-port 53
```

Resultado esperado: os pacotes são processados a partir do ficheiro, com prefixo `[offline:captura.pcap]`.

Nota: o repositório não inclui PCAPs de exemplo. O ficheiro `captura.pcap` pode ser criado com `--write-pcap`, ou pode ser usado outro PCAP disponível no ambiente de teste.

## Filtros por opções da CLI

Os filtros seguintes funcionam em modo live e offline. Em live, são convertidos para uma expressão de captura. Em offline, são avaliados em Python durante a leitura do PCAP.

Filtrar por IP de origem ou destino:

```bash
sudo .venv/bin/python main.py -i en0 --ip 10.0.0.1
python3 main.py -r captura.pcap --ip 10.0.0.1
```

Filtrar por IP de origem:

```bash
sudo .venv/bin/python main.py -i en0 --src-ip 10.0.0.1
python3 main.py -r captura.pcap --src-ip 10.0.0.1
```

Filtrar por IP de destino:

```bash
sudo .venv/bin/python main.py -i en0 --dst-ip 8.8.8.8
python3 main.py -r captura.pcap --dst-ip 8.8.8.8
```

Filtrar por MAC de origem ou destino:

```bash
sudo .venv/bin/python main.py -i en0 --mac aa:bb:cc:dd:ee:ff
python3 main.py -r captura.pcap --mac aa:bb:cc:dd:ee:ff
```

Filtrar por protocolo:

```bash
sudo .venv/bin/python main.py -i en0 --protocol arp
sudo .venv/bin/python main.py -i en0 --protocol ip
sudo .venv/bin/python main.py -i en0 --protocol icmp
sudo .venv/bin/python main.py -i en0 --protocol tcp
sudo .venv/bin/python main.py -i en0 --protocol udp
```

Filtrar por porta TCP/UDP de origem:

```bash
sudo .venv/bin/python main.py -i en0 --src-port 53000
python3 main.py -r captura.pcap --src-port 53000
```

Filtrar por porta TCP/UDP de destino:

```bash
sudo .venv/bin/python main.py -i en0 --dst-port 53 --protocol udp
python3 main.py -r captura.pcap --dst-port 53 --protocol udp
```

Combinar filtros:

```bash
sudo .venv/bin/python main.py -i en0 --src-ip 10.0.0.1 --dst-port 53 --protocol udp
python3 main.py -r captura.pcap --ip 10.0.0.1 --protocol tcp
```

## Fragmentação IPv4

O parser mostra campos de fragmentação quando um pacote IPv4 está fragmentado:

- `id`: identificador IPv4.
- `offset`: fragment offset em bytes.
- `MF`: flag More Fragments.

Filtros disponíveis:

```bash
python3 main.py -r fragmentado.pcap --fragmented
python3 main.py -r fragmentado.pcap --ip-id 12345
python3 main.py -r fragmentado.pcap --mf-only
```

Resultado esperado:

- `--fragmented`: mostra apenas pacotes com `offset > 0` ou `MF` ativa.
- `--ip-id 12345`: mostra apenas pacotes IPv4 com esse identificador.
- `--mf-only`: mostra apenas pacotes com a flag `MF` ativa.
- fragmentos posteriores podem incluir `fragmento do conjunto em ...`.
- quando o conjunto observado parece completo, aparece o evento `Fragmentos IPv4 completos`.

Exemplo de resumo:

```text
[211] [offline:fragmentado.pcap] [16:20:01] Ethernet | IPv4 | UDP | 192.168.1.10:4444 -> 8.8.8.8:53 | ttl=64 | id=12345 | offset=0 | MF | DNS query | 1500 bytes
[212] [offline:fragmentado.pcap] [16:20:01] Ethernet | IPv4 | proto=17 | 192.168.1.10 -> 8.8.8.8 | ttl=64 | id=12345 | offset=1480 | fragmento do conjunto em 211 | 620 bytes
[evento] Fragmentos IPv4 completos | 192.168.1.10 -> 8.8.8.8 | id=12345
```

O ficheiro `fragmentado.pcap` não vem incluído. Para demonstrar esta parte de forma fiável, deve ser preparado um PCAP com fragmentos IPv4. Em modo live, também é possível tentar gerar tráfego grande com `ping`, mas isso depende do sistema, da rede, do MTU e de a flag DF estar ou não ativa.

## Expressões BPF

BPF significa Berkeley Packet Filter. Neste projeto, `--bpf` permite passar ao Scapy/libpcap um filtro de captura escrito na sintaxe clássica de ferramentas como `tcpdump`.

Em termos simples: com BPF, o filtro é aplicado durante a captura live, antes de o pacote chegar ao código Python. Isto reduz o tráfego que o programa tem de processar.

Diferença para os filtros por opções da CLI:

- filtros por opções da CLI: opções como `--protocol udp`, `--dst-port 53` ou `--ip 8.8.8.8`;
- expressão BPF: uma expressão textual como `"udp port 53"` ou `"host 8.8.8.8"`;
- em modo live, ambos podem ser usados;
- em modo offline, devem ser usados apenas os filtros por opções da CLI, porque este projeto não aplica expressões BPF ao ler PCAPs.

Sintaxe BPF útil para testar:

```text
host 8.8.8.8       tráfego de/para 8.8.8.8
udp port 53        tráfego UDP na porta 53, normalmente DNS
tcp port 80        tráfego TCP na porta 80, normalmente HTTP
tcp port 443       tráfego TCP na porta 443, normalmente HTTPS
icmp               tráfego ICMP
arp                tráfego ARP
```

### Teste 1: BPF por host

Terminal 1, executar o sniffer:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "host 8.8.8.8"
```

Terminal 2, gerar tráfego:

```bash
ping 8.8.8.8
```

Resultado esperado: aparecem pacotes associados a `8.8.8.8`.

### Teste 2: BPF para DNS

Terminal 1, executar o sniffer:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "udp port 53"
```

Terminal 2, gerar uma query DNS:

```bash
dig example.com
```

Se `dig` não existir:

```bash
nslookup example.com
```

Resultado esperado: aparecem pacotes UDP na porta 53, possivelmente com `DNS query`, `DNS response` e `request in line ...`.

### Teste 3: BPF para HTTP/HTTPS

Terminal 1, executar o sniffer:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

Terminal 2, gerar tráfego HTTP:

```bash
curl http://example.com
```

Resultado esperado: aparecem pacotes TCP na porta 80, com serviço `HTTP` e flags TCP como `SYN`, `ACK`, `FIN` ou `RST`.

Nota: em algumas redes atuais, browsers, proxies ou ferramentas do sistema podem encaminhar tráfego web por HTTPS ou por ligações já existentes na porta 443. Se `tcp port 80` não mostrar pacotes, deve ser testada a variante HTTPS:

Terminal 1:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 443"
```

Terminal 2:

```bash
curl -I https://example.com
```

Resultado esperado: aparecem pacotes TCP na porta 443. O projeto identifica o protocolo como TCP, mas não chama a isto HTTP porque o reconhecimento conservador de serviço HTTP está associado à porta 80.

### Combinar BPF com filtros da CLI

Exemplo:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80" --ip 10.0.0.2
```

Resultado esperado: o sniffer só processa tráfego que respeite as duas condições: BPF `tcp port 80` e IP `10.0.0.2`.

### Teste de erro em modo offline

```bash
python3 main.py -r captura.pcap --bpf "tcp port 80"
```

Resultado esperado: erro a indicar que expressões BPF em modo offline não são suportadas e que devem ser usados filtros por opções da CLI.

## Guardar captura crua em PCAP

Guardar 100 pacotes:

```bash
sudo .venv/bin/python main.py -i en0 -c 100 --write-pcap saida.pcap
```

Guardar apenas ICMP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp -c 50 --write-pcap icmp.pcap
```

Validar o PCAP criado:

```bash
python3 main.py -r saida.pcap -c 5
```

Resultado esperado: o ficheiro `.pcap` é criado e pode ser lido em modo offline.

## Logging estruturado

O logging não substitui o output da consola. O programa imprime os pacotes e, ao mesmo tempo, escreve o ficheiro configurado.

TXT:

```bash
python3 main.py -r captura.pcap --log-file captura.txt --log-format txt
```

CSV:

```bash
python3 main.py -r captura.pcap --log-file captura.csv --log-format csv
```

JSON Lines:

```bash
python3 main.py -r captura.pcap --log-file captura.jsonl --log-format json
```

Também funciona em live:

```bash
sudo .venv/bin/python main.py -i en0 -c 50 --log-file demo.csv --log-format csv
```

Campos principais dos logs:

```text
packet_number
timestamp
source_type
source_name
protocol
src_ip
dst_ip
src_port
dst_port
ttl
length
ip_id
fragment_offset
more_fragments
service
summary
```

Notas:

- `timestamp` é ISO e `timestamp_display` aparece no JSON.
- TXT usa uma linha semelhante à consola.
- CSV tem cabeçalho fixo.
- JSON Lines escreve um objeto JSON por linha.
- Eventos do tracker são impressos na consola e contados nas estatísticas finais, mas não são registados como linhas próprias no ficheiro de log.
- As referências como `request in line 12` aparecem no campo `summary`.

## Consulta interativa de pacotes

No fim da execução, se existirem pacotes processados e o programa estiver num terminal interativo, surge:

```text
Selecione o pacote que quer analisar (ou prima 0 para terminar):
```

Deve ser introduzido um número de pacote, por exemplo:

```text
3
```

Resultado esperado: aparece uma vista textual mais detalhada com os campos disponíveis.

Exemplo:

```text
Detalhe do pacote 3
  tipo de fonte: offline
  fonte: captura.pcap
  timestamp: 2026-05-03T14:05:31
  resumo: Ethernet | IPv4 | TCP [SYN] | 10.0.0.1:54321 -> 10.0.0.2:80 | ttl=64 | HTTP | 60 bytes

Ethernet:
  src_mac: aa:bb:cc:dd:ee:ff
  dst_mac: ff:ee:dd:cc:bb:aa
  ethertype: IPv4 (0x0800)

IPv4:
  src_ip: 10.0.0.1
  dst_ip: 10.0.0.2
  ttl: 64
  length: 60
  header_length: 20 bytes
  protocol: TCP
  ip_id: 1234
  fragment_offset: 0
  more_fragments: False

TCP:
  src_port: 54321
  dst_port: 80
  flags: SYN
  service: HTTP
```

Sair da consulta:

```text
0
```

Se o programa não estiver num terminal interativo, esta prompt é omitida.

## Protocolos suportados

Nos exemplos com dois comandos, o sniffer deve ficar a correr num terminal e o tráfego deve ser gerado noutro terminal.

### Ethernet

Mostra:

- MAC origem.
- MAC destino.
- EtherType.

Exemplo:

```text
Ethernet | IPv4 (...)
Ethernet | ARP (...)
Ethernet | Outro | ethertype=0x86dd | tipo não suportado nesta fase
```

IPv6 e outros EtherTypes podem aparecer como `Outro`, porque o projeto só faz parsing detalhado de ARP e IPv4.

### ARP

Mostra:

- operação `request` ou `reply`;
- IP origem/destino;
- MAC origem/destino;
- referência ao pedido quando um reply corresponde a um request observado.

Como gerar:

```bash
sudo .venv/bin/python main.py -i en0 --protocol arp
ping 10.0.0.2
```

Em CORE, usar dois nós na mesma rede e fazer `ping` entre eles. Se o ARP estiver em cache, pode não aparecer imediatamente.

### IPv4

Mostra:

- IP origem/destino;
- TTL;
- tamanho total;
- protocolo transportado;
- header length na vista detalhada;
- `id`, `offset` e `MF` quando houver fragmentação.

Comando:

```bash
python3 main.py -r captura.pcap --protocol ip
```

### ICMP

Mostra:

- tipo;
- código;
- `echo-request` e `echo-reply` quando aplicável;
- referência ao pedido quando o reply corresponde a um request observado.

Como gerar:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
ping 8.8.8.8
```

Resultado esperado:

```text
[evento] ICMP reply recebido | 8.8.8.8 respondeu a 10.0.0.1
```

### TCP

Mostra:

- portas origem/destino;
- flags principais `SYN`, `ACK`, `FIN` e `RST`;
- serviço `HTTP` quando a porta 80 está envolvida;
- evento de handshake;
- evento de fim de sessão por `FIN` ou `RST`.

Como gerar:

```bash
sudo .venv/bin/python main.py -i en0 --protocol tcp
curl http://example.com
```

Em CORE, se existir um servidor HTTP num nó:

```bash
curl http://10.0.0.2
```

Resultado esperado:

```text
[evento] TCP handshake concluído | 10.0.0.1:54321 -> 10.0.0.2:80
[evento] TCP sessão terminada | 10.0.0.1:54321 -> 10.0.0.2:80 | FIN
```

### UDP, DNS e DHCP

Mostra:

- portas origem/destino;
- serviço `DNS` para porta 53;
- serviço `DHCP` para portas UDP 67/68;
- `DNS query` e `DNS response` quando a camada DNS é reconhecida;
- `DHCP Discover`, `DHCP Offer`, `DHCP Request` e `DHCP ACK` quando a camada DHCP é reconhecida.

Como gerar DNS:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp --dst-port 53
dig example.com
```

Se `dig` não existir:

```bash
nslookup example.com
```

Para observar queries e responses no mesmo comando, pode ser melhor filtrar só por protocolo:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
dig example.com
```

Resultado esperado:

```text
DNS query
DNS response
request in line ...
```

DHCP depende do ambiente e da possibilidade de renovar lease. Em CORE ou numa rede controlada, captura UDP 67/68:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp --dst-port 67
sudo .venv/bin/python main.py -i en0 --protocol udp --src-port 67
```

Resultado esperado, quando houver tráfego DHCP:

```text
DHCP Discover
DHCP Offer
DHCP Request
DHCP ACK
```

## Eventos detetados

### ARP resolvido

Ocorre quando o sniffer observa um ARP request e depois o ARP reply correspondente.

```text
[evento] ARP resolvido | 10.0.0.2 está em aa:bb:cc:dd:ee:ff
```

### ICMP reply recebido

Ocorre quando o sniffer observa um echo-request e depois o echo-reply correspondente.

```text
[evento] ICMP reply recebido | 10.0.0.2 respondeu a 10.0.0.1
```

### TCP handshake concluído

Ocorre quando o sniffer observa a sequência `SYN`, `SYN-ACK`, `ACK` do mesmo fluxo.

```text
[evento] TCP handshake concluído | 10.0.0.1:54321 -> 10.0.0.2:80
```

### TCP sessão terminada

Ocorre quando é observado `FIN` ou `RST`.

```text
[evento] TCP sessão terminada | 10.0.0.1:54321 -> 10.0.0.2:80 | FIN
```

### Possível traceroute detetado

Ocorre por heurística quando o tracker observa TTL crescente no mesmo fluxo.

Como gerar:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
traceroute -I 8.8.8.8
```

Também é possível testar a variante UDP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
traceroute 8.8.8.8
```

Resultado esperado:

```text
[evento] Possível traceroute detetado | 10.0.0.1 -> 8.8.8.8
```

### Fragmentos IPv4 completos

Ocorre quando os fragmentos observados parecem cobrir todo o datagrama esperado.

```text
[evento] Fragmentos IPv4 completos | 192.168.1.10 -> 8.8.8.8 | id=12345
```

A deteção é heurística e não reconstrói o payload completo.

## Estatísticas finais

No fim da execução, incluindo quando a captura é interrompida com `Ctrl+C`, o programa imprime:

- tipo de fonte;
- fonte usada;
- filtros configurados;
- total de pacotes processados;
- contagem e percentagem por protocolo;
- top 3 IPs de origem;
- contagem de eventos detetados.

Exemplo:

```text
Resumo:
  tipo de fonte: live
  fonte: eth0
  filtro configurado: --protocol tcp
  pacotes processados: 120

Estatísticas:
  protocolos:
    TCP: 70 (58.3%)
    UDP: 15 (12.5%)
    ICMP: 20 (16.7%)
    ARP: 10 (8.3%)
    Outro: 5 (4.2%)

  top talkers:
    1. 10.0.0.1 - 45 pacotes
    2. 10.0.0.2 - 31 pacotes
    3. 8.8.8.8 - 12 pacotes

  eventos:
    ARP resolvido: 3
    ICMP reply recebido: 4
    TCP handshake concluído: 2
    TCP sessão terminada: 2
```

Se não houver pacotes ou eventos, o relatório mostra mensagens como `(sem pacotes classificados)`, `(sem IPs de origem)` ou `(sem eventos detetados)`.

## Testes de validação da CLI

Estes testes confirmam que a aplicação rejeita combinações inválidas com mensagens claras.

Executar sem fonte:

```bash
python3 main.py
```

Resultado esperado: erro a pedir exatamente uma fonte, `--interface` ou `--pcap`.

Usar live e offline ao mesmo tempo:

```bash
python3 main.py -i en0 -r captura.pcap
```

Resultado esperado: erro a indicar que deve ser indicada exatamente uma fonte.

Protocolo inválido:

```bash
python3 main.py -i en0 --protocol dns
```

Resultado esperado: erro a listar os protocolos suportados: `arp`, `icmp`, `ip`, `tcp`, `udp`.

IP inválido:

```bash
python3 main.py -i en0 --ip 999.999.999.999
```

Resultado esperado: erro de endereço IP inválido.

MAC inválido:

```bash
python3 main.py -i en0 --mac aa:bb:cc
```

Resultado esperado: erro a pedir o formato `aa:bb:cc:dd:ee:ff`.

Porta inválida:

```bash
python3 main.py -i en0 --dst-port 70000
```

Resultado esperado: erro a indicar que a porta tem de estar entre 0 e 65535.

Contagem negativa:

```bash
python3 main.py -i en0 -c -1
```

Resultado esperado: erro a indicar que `--count` não pode ser negativo.

Timeout inválido:

```bash
python3 main.py -i en0 --timeout 0
```

Resultado esperado: erro a indicar que `--timeout` tem de ser maior do que zero.

PCAP inexistente:

```bash
python3 main.py -r nao_existe.pcap
```

Resultado esperado: erro a indicar que o ficheiro PCAP não foi encontrado.

Logging incompleto:

```bash
python3 main.py -i en0 --log-file teste.csv
```

Resultado esperado: erro a indicar que `--log-file` e `--log-format` têm de ser usados em conjunto.

`--write-pcap` em modo offline:

```bash
python3 main.py -r captura.pcap --write-pcap saida.pcap
```

Resultado esperado: erro a indicar que `--write-pcap` só é suportado em modo live.

`--write-pcap` sem extensão `.pcap`:

```bash
python3 main.py -i en0 --write-pcap saida.txt
```

Resultado esperado: erro a indicar que a extensão deve ser `.pcap`.

## Demonstração no CORE

1. Abrir a topologia no CORE.
2. Iniciar a sessão.
3. Abrir terminal no nó onde o sniffer vai ser executado.
4. Entrar na pasta do projeto.

Exemplo:

```bash
cd /home/core/Desktop/RCTP2PL68
```

5. Se necessário, garantir que o Python encontra o Scapy instalado no ambiente do CORE:

```bash
export PYTHONPATH=/home/core/.local/lib/python3.10/site-packages:$PYTHONPATH
```

6. Confirmar a interface:

```bash
ip addr
```

7. Executar o sniffer:

```bash
sudo env PYTHONPATH=$PYTHONPATH python3 main.py -i eth0
```

8. Gerar tráfego ICMP entre nós:

```bash
ping 10.0.0.2
```

Mostrar:

- parsing Ethernet/IPv4/ICMP;
- números de pacote;
- timestamps;
- `echo-request` e `echo-reply`;
- evento `ICMP reply recebido`;
- referência `request in line ...`;
- estatísticas finais após `Ctrl+C`;
- consulta interativa de um pacote.

9. Gerar tráfego TCP, se houver um serviço HTTP:

```bash
curl http://10.0.0.2
```

Mostrar:

- portas TCP;
- flags `SYN`, `SYN-ACK`, `ACK`, `FIN` ou `RST`;
- evento `TCP handshake concluído`;
- evento `TCP sessão terminada`;
- serviço `HTTP`.

10. Demonstrar logs:

```bash
sudo env PYTHONPATH=$PYTHONPATH python3 main.py -i eth0 -c 20 --log-file core.csv --log-format csv
```

11. Demonstrar PCAP:

```bash
sudo env PYTHONPATH=$PYTHONPATH python3 main.py -i eth0 -c 30 --write-pcap core.pcap
python3 main.py -r core.pcap -c 10
```

12. Demonstrar traceroute:

```bash
sudo env PYTHONPATH=$PYTHONPATH python3 main.py -i eth0 --protocol icmp
traceroute -I 8.8.8.8
```

13. Demonstrar fragmentação com PCAP preparado:

```bash
python3 main.py -r fragmentado.pcap
python3 main.py -r fragmentado.pcap --fragmented
python3 main.py -r fragmentado.pcap --log-file fragmentado.csv --log-format csv
```

No CORE podem surgir avisos como `sudo: unable to resolve host ...` ou `WARNING: Could not retrieve the OS's nameserver !`. Esses avisos não impedem necessariamente a captura.

## Demonstração numa interface real

Nos exemplos abaixo, deve ser iniciado primeiro o sniffer, mantendo esse terminal aberto. Depois, o comando que gera tráfego deve ser executado noutro terminal.

### macOS

Captura curta:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30
```

ICMP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
ping 8.8.8.8
```

DNS:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
dig example.com
```

BPF:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

Traceroute:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
traceroute -I 8.8.8.8
```

PCAP:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
python3 main.py -r captura.pcap -c 10
```

### Linux

Captura curta:

```bash
sudo python3 main.py -i eth0 --timeout 30
```

ICMP:

```bash
sudo python3 main.py -i eth0 --protocol icmp
ping 8.8.8.8
```

DNS:

```bash
sudo python3 main.py -i eth0 --protocol udp
dig example.com
```

BPF:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80"
```

Traceroute:

```bash
sudo python3 main.py -i eth0 --protocol icmp
traceroute -I 8.8.8.8
```

PCAP:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
python3 main.py -r captura.pcap -c 10
```

## Roteiro de validação completa

Foi confirmada a capacidade de mostrar:

- `python3 main.py --help`.
- Erro ao correr sem `--interface` nem `--pcap`.
- Captura live com `-i`.
- Limite por pacotes com `-c`.
- Limite por tempo com `--timeout`.
- Interrupção com `Ctrl+C` e resumo final.
- Escrita com `--write-pcap`.
- Leitura offline com `-r`.
- Filtro por `--ip`.
- Filtro por `--src-ip`.
- Filtro por `--dst-ip`.
- Filtro por `--mac`.
- Filtro por `--protocol arp`.
- Filtro por `--protocol ip`.
- Filtro por `--protocol icmp`.
- Filtro por `--protocol tcp`.
- Filtro por `--protocol udp`.
- Filtro por `--src-port`.
- Filtro por `--dst-port`.
- Filtro por `--fragmented`.
- Filtro por `--ip-id`.
- Filtro por `--mf-only`.
- BPF live com `--bpf "tcp port 80"` ou, se a rede encaminhar web por HTTPS, `--bpf "tcp port 443"`.
- Erro esperado ao usar `--bpf` em modo offline.
- Logging TXT.
- Logging CSV.
- Logging JSON Lines.
- Parsing Ethernet.
- Parsing ARP.
- Parsing IPv4.
- Parsing ICMP.
- Parsing TCP.
- Parsing UDP.
- Reconhecimento de DNS.
- Reconhecimento de DHCP, se o ambiente gerar DHCP.
- Reconhecimento de HTTP por porta 80.
- Evento `ARP resolvido`.
- Evento `ICMP reply recebido`.
- Evento `TCP handshake concluído`.
- Evento `TCP sessão terminada`.
- Evento `Possível traceroute detetado`.
- Evento `Fragmentos IPv4 completos`, com PCAP preparado.
- Referências `request in line ...`.
- Referências `fragmento do conjunto em ...`.
- Estatísticas finais.
- Consulta interativa de pacote pelo número.
