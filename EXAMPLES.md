# Exemplos de Comandos

Coleção de comandos úteis para testar e demonstrar o packet sniffer. No ambiente real de teste em macOS foi usada a interface `en0`. Em Linux/CORE, `eth0` continua a ser um exemplo comum.

Quando a captura live é executada em macOS com uma virtualenv, usar preferencialmente:

```bash
sudo .venv/bin/python main.py ...
```

Isto garante que o Python executado com `sudo` usa o Scapy instalado na virtualenv.

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

Combinar filtros amigáveis:

```bash
sudo .venv/bin/python main.py -i en0 --ip 10.0.0.1 --protocol tcp
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

Captura live com log CSV:

```bash
sudo .venv/bin/python main.py -i en0 -c 50 --log-file live.csv --log-format csv
```

Captura live com log JSON:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30 --log-file live.jsonl --log-format json
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
