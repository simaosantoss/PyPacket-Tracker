# Exemplos de Comandos

Coleção de comandos úteis para testar e demonstrar o packet sniffer. Substituir `eth0`, `en0`, `10.0.0.1`, `10.0.0.2` e `captura.pcap` pelos valores do ambiente real.

## Comandos básicos

Mostrar ajuda:

```bash
python3 main.py --help
```

Captura live sem filtros:

```bash
sudo python3 main.py -i eth0
```

Captura live com limite de pacotes:

```bash
sudo python3 main.py -i eth0 -c 50
```

Captura live com timeout:

```bash
sudo python3 main.py -i eth0 --timeout 30
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
sudo python3 main.py -i eth0 --ip 10.0.0.1
```

Filtro por MAC:

```bash
sudo python3 main.py -i eth0 --mac aa:bb:cc:dd:ee:ff
```

Filtro por ARP:

```bash
sudo python3 main.py -i eth0 --protocol arp
```

Filtro por ICMP:

```bash
sudo python3 main.py -i eth0 --protocol icmp
```

Filtro por TCP:

```bash
sudo python3 main.py -i eth0 --protocol tcp
```

Filtro por UDP:

```bash
sudo python3 main.py -i eth0 --protocol udp
```

Combinar filtros amigáveis:

```bash
sudo python3 main.py -i eth0 --ip 10.0.0.1 --protocol tcp
```

## BPF bruto em modo live

Capturar tráfego TCP na porta 80:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80"
```

Capturar tráfego DNS:

```bash
sudo python3 main.py -i eth0 --bpf "udp port 53"
```

Capturar tráfego entre hosts:

```bash
sudo python3 main.py -i eth0 --bpf "host 10.0.0.2"
```

Combinar BPF com filtro amigável:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80" --ip 10.0.0.2
```

## Escrita para PCAP

Guardar captura crua:

```bash
sudo python3 main.py -i eth0 -c 100 --write-pcap saida.pcap
```

Ler o PCAP guardado:

```bash
python3 main.py -r saida.pcap
```

Guardar PCAP e filtrar por protocolo:

```bash
sudo python3 main.py -i eth0 --protocol icmp --write-pcap icmp.pcap -c 50
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
sudo python3 main.py -i eth0 -c 50 --log-file live.csv --log-format csv
```

Captura live com log JSON:

```bash
sudo python3 main.py -i eth0 --timeout 30 --log-file live.jsonl --log-format json
```

## Tráfego para gerar durante testes

Gerar ICMP:

```bash
ping 10.0.0.2
```

Gerar TCP/HTTP:

```bash
curl http://10.0.0.2
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

## Exemplos para CORE

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

## Exemplos para interface real

macOS, interface comum `en0`:

```bash
sudo python3 main.py -i en0 --timeout 30
```

Linux, interface comum `eth0`:

```bash
sudo python3 main.py -i eth0 --timeout 30
```

Reduzir ruído com ICMP:

```bash
sudo python3 main.py -i en0 --protocol icmp
ping 8.8.8.8
```

Capturar DNS:

```bash
sudo python3 main.py -i en0 --bpf "udp port 53"
dig example.com
```

## Erros esperados úteis para demonstrar validação

Sem fonte de captura:

```bash
python3 main.py
```

Duas fontes ao mesmo tempo:

```bash
python3 main.py -i eth0 -r captura.pcap
```

Protocolo inválido:

```bash
python3 main.py -i eth0 --protocol dns
```

Logging incompleto:

```bash
python3 main.py -i eth0 --log-file teste.csv
```
