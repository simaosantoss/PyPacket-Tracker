# Exemplos de Comandos

Coleção de comandos úteis para testar e demonstrar o packet sniffer. No ambiente real de teste em macOS foi usada a interface `en0`. Em Linux/CORE, `eth0` continua a ser um exemplo comum.

Quando a captura live é executada em macOS com uma virtualenv, usar preferencialmente:

```bash
sudo .venv/bin/python main.py ...
```

Isto garante que o Python executado com `sudo` usa o Scapy instalado na virtualenv.

As linhas mostradas na consola incluem agora o número do pacote, o prefixo da fonte e um timestamp curto, por exemplo:

```text
[12] [live:en0] [14:02:10] Ethernet | IPv4 | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | UDP | DNS query | 72 bytes
[13] [offline:captura.pcap] [14:05:31] Ethernet | ARP | reply | 10.0.0.2 -> 10.0.0.1 | aa:bb:cc:dd:ee:ff -> ff:ff:ff:ff:ff:ff | request in line 12
```

Quando o sniffer consegue relacionar pedidos e respostas, acrescenta uma referência curta ao número da linha do pedido, como `request in line 12`.

## Fluxo prático completo em macOS

1. Confirmar a CLI:

```bash
python3 main.py --help
```

2. Testar captura live em `en0`:

```bash
sudo .venv/bin/python main.py -i en0 -c 10
```

3. Gerar um ficheiro PCAP, se ainda não existir:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

4. Testar modo offline com o PCAP gerado:

```bash
python3 main.py -r captura.pcap -c 10
```

## Fluxo prático completo em Linux/CORE

1. Confirmar a interface com `ip addr`. Neste exemplo usa-se `eth0`.

2. Testar captura live:

```bash
sudo python3 main.py -i eth0 -c 10
```

3. Gerar um ficheiro PCAP, se ainda não existir:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
```

4. Testar modo offline com o PCAP gerado:

```bash
python3 main.py -r captura.pcap -c 10
```

## Comandos básicos em macOS

Captura live sem filtros:

```bash
sudo .venv/bin/python main.py -i en0
```

Captura live com limite de pacotes:

```bash
sudo .venv/bin/python main.py -i en0 -c 50
```

Captura live com timeout:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30
```

Leitura offline de PCAP:

```bash
python3 main.py -r captura.pcap
```

Leitura offline limitada:

```bash
python3 main.py -r captura.pcap -c 20
```

## Filtros amigáveis

Filtro por IP:

```bash
sudo .venv/bin/python main.py -i en0 --ip 10.0.0.1
```

Filtro por IP de origem:

```bash
sudo .venv/bin/python main.py -i en0 --src-ip 10.0.0.1
```

Filtro por IP de destino:

```bash
sudo .venv/bin/python main.py -i en0 --dst-ip 8.8.8.8
```

Filtro por MAC:

```bash
sudo .venv/bin/python main.py -i en0 --mac aa:bb:cc:dd:ee:ff
```

Filtro por ARP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol arp
```

Filtro por ICMP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
```

Filtro por TCP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol tcp
```

Filtro por UDP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
```

Filtro por porta de origem:

```bash
sudo .venv/bin/python main.py -i en0 --src-port 53000
```

Filtro por porta de destino:

```bash
sudo .venv/bin/python main.py -i en0 --dst-port 53 --protocol udp
```

Filtro por pacotes IPv4 fragmentados:

```bash
python3 main.py -r fragmentado.pcap --fragmented
```

Filtro por identificador IPv4:

```bash
python3 main.py -r fragmentado.pcap --ip-id 12345
```

Filtro por pacotes com MF ativa:

```bash
python3 main.py -r fragmentado.pcap --mf-only
```

Combinar filtros amigáveis:

```bash
sudo .venv/bin/python main.py -i en0 --ip 10.0.0.1 --protocol tcp
```

Combinar IP de origem, porta de destino e protocolo:

```bash
sudo .venv/bin/python main.py -i en0 --src-ip 10.0.0.1 --dst-port 53 --protocol udp
```

## BPF bruto em modo live

Capturar tráfego TCP na porta 80:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

Capturar tráfego DNS:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "udp port 53"
```

Capturar tráfego associado a um host:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "host 8.8.8.8"
```

Combinar BPF com filtro amigável:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80" --ip 10.0.0.2
```

## Escrita para PCAP

Guardar captura crua:

```bash
sudo .venv/bin/python main.py -i en0 -c 100 --write-pcap saida.pcap
```

Gerar o PCAP usado nos testes offline:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

Ler o PCAP guardado:

```bash
python3 main.py -r captura.pcap
```

Guardar PCAP e filtrar por protocolo:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp --write-pcap icmp.pcap -c 50
```

## Logging

Os logs guardam também timestamp por pacote:

- TXT: a hora aparece na própria linha.
- CSV: existe a coluna `timestamp`.
- JSON Lines: cada objeto inclui `timestamp`.

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

Exemplos curtos de registos:

```text
[12] [live:en0] [14:02:10] Ethernet | IPv4 | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | UDP | DNS query | 72 bytes
```

```csv
packet_number,timestamp,source_type,source_name,protocol,src_ip,dst_ip,src_port,dst_port,ttl,length,ip_id,fragment_offset,more_fragments,service,summary
12,2026-04-16T14:02:10,live,en0,UDP,10.0.0.1,8.8.8.8,53000,53,64,72,54321,0,False,DNS,Ethernet | IPv4 | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | UDP | DNS query | 72 bytes
```

```json
{"packet_number":12,"timestamp":"2026-04-16T14:02:10","timestamp_display":"14:02:10","source_type":"live","source_name":"en0","source_display":"live:en0","protocol":"UDP","src_ip":"10.0.0.1","dst_ip":"8.8.8.8","src_port":53000,"dst_port":53,"ttl":64,"length":72,"ip_id":54321,"fragment_offset":0,"more_fragments":false,"service":"DNS","summary":"Ethernet | IPv4 | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | UDP | DNS query | 72 bytes"}
```

Captura live com log CSV:

```bash
sudo .venv/bin/python main.py -i en0 -c 50 --log-file live.csv --log-format csv
```

Captura live com log JSON:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30 --log-file live.jsonl --log-format json
```

## Referências entre pedidos e respostas

ARP reply com referência ao request:

```text
[13] [live:en0] [11:22:13] Ethernet | ARP | reply | 10.0.0.2 -> 10.0.0.1 | 11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff | request in line 12
```

ICMP echo-reply com referência ao echo-request:

```text
[41] [live:en0] [11:22:15] Ethernet | IPv4 | 8.8.8.8 -> 10.0.0.1 | ttl=64 | ICMP | echo-reply | request in line 40
```

DNS response com referência à query:

```text
[92] [live:en0] [11:22:20] Ethernet | IPv4 | 8.8.8.8:53 -> 10.0.0.1:53000 | ttl=64 | UDP | DNS response | request in line 91
```

Quando não há relação conhecida, o formato continua limpo:

```text
[93] [live:en0] [11:22:21] Ethernet | IPv4 | 10.0.0.1:12345 -> 1.1.1.1:443 | ttl=64 | TCP [SYN]
```

## Fragmentação IPv4

Leitura offline de um PCAP com fragmentação IPv4:

```bash
python3 main.py -r fragmentado.pcap
```

Leitura offline com logging CSV:

```bash
python3 main.py -r fragmentado.pcap --log-file fragmentado.csv --log-format csv
```

Teste live, quando a rede e o MTU o permitirem:

```bash
sudo .venv/bin/python main.py -i en0
ping -s 4000 8.8.8.8
```

ou, em Linux/CORE:

```bash
sudo python3 main.py -i eth0
ping -s 4000 8.8.8.8
```

Exemplo de output:

```text
Ethernet | IPv4 | 10.0.0.1 -> 10.0.0.2 | ttl=64 | id=12345 | offset=1400 | MF | proto=UDP
```

Exemplo de evento:

```text
[evento] Fragmentos IPv4 completos | 10.0.0.1 -> 10.0.0.2 | id=12345
```

## Traceroute

A variante ICMP com `traceroute -I` tende a ser mais limpa para demonstração, porque é mais fácil observar e explicar o padrão de TTL crescente.

macOS, traceroute ICMP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
traceroute -I 8.8.8.8
```

macOS, traceroute UDP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
traceroute 8.8.8.8
```

Linux/CORE, traceroute ICMP:

```bash
sudo python3 main.py -i eth0 --protocol icmp
traceroute -I 8.8.8.8
```

Linux/CORE, traceroute UDP:

```bash
sudo python3 main.py -i eth0 --protocol udp
traceroute 8.8.8.8
```

Evento que pode surgir:

```text
[evento] Possível traceroute detetado | 172.26.204.185 -> 8.8.8.8
```

## Tráfego para gerar durante testes

Gerar ICMP:

```bash
ping 8.8.8.8
```

Gerar TCP/HTTP:

```bash
curl http://example.com
```

Servidor TCP simples com `nc` no destino:

```bash
nc -l 8080
```

Cliente TCP com `nc` na origem:

```bash
nc 10.0.0.2 8080
```

Gerar UDP com `nc`, se a versão instalada suportar `-u`:

```bash
nc -u 10.0.0.2 9999
```

Gerar DNS, se houver acesso a DNS:

```bash
dig example.com
```

ou:

```bash
nslookup example.com
```

Gerar traceroute ICMP:

```bash
traceroute -I 8.8.8.8
```

Gerar traceroute UDP:

```bash
traceroute 8.8.8.8
```

## Exemplos para CORE ou Linux

Em CORE/Linux, a interface pode ser `eth0`, mas deve ser confirmada com `ip addr`.

Capturar tudo num nó CORE:

```bash
sudo python3 main.py -i eth0
```

Capturar só ICMP e gerar ping:

```bash
sudo python3 main.py -i eth0 --protocol icmp
ping 10.0.0.2
```

Capturar TCP na porta 80:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80"
curl http://10.0.0.2
```

Guardar log CSV no CORE:

```bash
sudo python3 main.py -i eth0 -c 50 --log-file core.csv --log-format csv
```

Guardar PCAP no CORE:

```bash
sudo python3 main.py -i eth0 -c 50 --write-pcap core.pcap
```

Ler um PCAP com fragmentação IPv4 no CORE/Linux:

```bash
python3 main.py -r fragmentado.pcap
```

## Erros esperados úteis para demonstrar validação

Nos comandos que recebem interface, substituir `<interface>` por `en0` em macOS ou por `eth0`/interface obtida com `ip addr` em Linux/CORE.

Sem fonte de captura:

```bash
python3 main.py
```

Duas fontes ao mesmo tempo:

```bash
python3 main.py -i <interface> -r captura.pcap
```

Protocolo inválido:

```bash
python3 main.py -i <interface> --protocol dns
```

Logging incompleto:

```bash
python3 main.py -i <interface> --log-file teste.csv
```
