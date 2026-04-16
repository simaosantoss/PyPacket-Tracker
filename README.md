# Packet Sniffer em Python com Scapy

Projeto académico de Redes de Computadores para captura, leitura e análise simples de pacotes de rede. O objetivo é demonstrar, de forma clara e extensível, os passos principais de um sniffer: escolher a fonte, filtrar tráfego, desencapsular protocolos, detetar alguns eventos com estado simples, guardar logs e apresentar estatísticas finais.

O projeto privilegia simplicidade e legibilidade. Não pretende substituir ferramentas como Wireshark ou tcpdump.

## Funcionalidades implementadas

- Captura live numa interface de rede.
- Leitura offline de ficheiros `.pcap`.
- Filtros amigáveis por IP, MAC e protocolo.
- Suporte de BPF bruto em modo live.
- Escrita opcional da captura crua para `.pcap`.
- Parsing de Ethernet, ARP, IPv4, ICMP, TCP e UDP.
- Identificação conservadora de serviços por porta e alguns casos UDP claramente reconhecíveis:
  - DNS: porta 53
  - DHCP: portas 67/68 em UDP
  - HTTP: porta 80 em TCP
- Timestamp por pacote no output e no logging estruturado.
- Tracking simples de estado para ARP, ICMP e TCP.
- Logging estruturado em `txt`, `csv` e JSON Lines.
- Estatísticas finais por protocolo, top talkers e eventos detetados.

## Estrutura do projeto

```text
main.py            CLI, validação de argumentos e resumo final
capture.py         captura live/offline e callback por pacote
parsing.py         parsing, filtros amigáveis e resumos de pacotes
tracking.py        rastreio simples de ARP, ICMP e TCP
logging_output.py  escrita de logs em txt, csv e json
stats.py           estatísticas finais da execução
```

Documentação de apoio:

```text
TEST_PLAN.md       plano de testes por funcionalidade
DEMO_CHECKLIST.md  checklist para demonstração/defesa
EXAMPLES.md        comandos prontos para testes e demonstração
```

## Dependências

O projeto usa Python 3 e Scapy.

Instalação recomendada:

```bash
python3 -m pip install scapy
```

Em modo live, normalmente são necessários privilégios de administrador para capturar pacotes.

macOS, normalmente com interface `en0`:

```bash
sudo .venv/bin/python main.py -i en0
```

Linux/CORE, normalmente com `eth0`, `ens33` ou `wlan0`:

```bash
sudo python3 main.py -i eth0
```

No macOS, se o projeto estiver numa virtualenv, é preferível chamar explicitamente o Python da virtualenv quando se usa `sudo`, para garantir que o Scapy correto é usado. Em Linux/CORE, confirmar primeiro a interface com `ip addr`.

## Como executar

### Captura live sem filtros

macOS:

```bash
sudo .venv/bin/python main.py -i en0
```

Linux/CORE:

```bash
sudo python3 main.py -i eth0
```

### Leitura offline de PCAP

Se ainda não existir um PCAP, pode ser criado primeiro com `--write-pcap`.

macOS:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
```

Depois, a leitura offline é feita com:

```bash
python3 main.py -r captura.pcap
```

### Captura com filtros amigáveis

Nos exemplos live seguintes, usar `sudo .venv/bin/python ... -i en0` em macOS ou `sudo python3 ... -i eth0` em Linux/CORE, ajustando sempre a interface real.

```bash
sudo .venv/bin/python main.py -i en0 --ip 10.0.0.1 --protocol tcp
```

Filtros suportados:

```bash
--ip 10.0.0.1
--mac aa:bb:cc:dd:ee:ff
--protocol arp|ip|icmp|tcp|udp
```

### Captura live com BPF bruto

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

Nota: nesta versão, BPF bruto só é suportado em modo live. Em modo offline, devem ser usados os filtros amigáveis.

### Limitar número de pacotes ou tempo de captura

```bash
sudo .venv/bin/python main.py -i en0 -c 50
sudo .venv/bin/python main.py -i en0 --timeout 30
```

### Guardar captura crua em PCAP

```bash
sudo .venv/bin/python main.py -i en0 --write-pcap saida.pcap
```

### Logging em ficheiro

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

O logging não substitui o output da consola. Ambos acontecem em simultâneo. Os eventos do tracker são impressos na consola, mas não são registados no ficheiro nesta versão.

Cada registo inclui timestamp por pacote:

- TXT: a linha textual inclui a hora do pacote.
- CSV: existe uma coluna estável `timestamp`.
- JSON Lines: cada objeto inclui o campo `timestamp`.

## Protocolos suportados

O sniffer reconhece e resume:

- Ethernet: MAC origem, MAC destino e EtherType.
- ARP: operação, IP origem/destino e MAC origem/destino.
- IPv4: IP origem/destino, TTL, tamanho e protocolo transportado.
- ICMP: tipo, código e nomes simples para `echo-request` e `echo-reply`.
- TCP: portas origem/destino e flags principais (`SYN`, `ACK`, `FIN`, `RST`).
- UDP: portas origem/destino e, quando for claro, resumos curtos como `DNS query`, `DNS response`, `DHCP Discover`, `DHCP Offer`, `DHCP Request` e `DHCP ACK`.

Exemplo de output:

```text
[live:en0] [14:02:10] IPv4 | 10.0.0.1:53000 -> 8.8.8.8:53 | ttl=64 | UDP | DNS query | 72 bytes
```

## Eventos detetados pelo tracker

O tracker mantém estado simples em memória e deteta eventos best effort:

- ARP request seguido de ARP reply:

```text
[evento] ARP resolvido | 10.0.0.2 está em aa:bb:cc:dd:ee:ff
```

- ICMP echo-request seguido de echo-reply:

```text
[evento] ICMP reply recebido | 10.0.0.2 respondeu a 10.0.0.1
```

- TCP 3-way handshake:

```text
[evento] TCP handshake concluído | 10.0.0.1:54321 -> 10.0.0.2:80
```

- TCP terminado por FIN ou RST:

```text
[evento] TCP sessão terminada | 10.0.0.1:54321 -> 10.0.0.2:80 | FIN
```

## Estatísticas finais

No fim da execução, incluindo quando a captura é interrompida com `Ctrl+C`, o programa imprime:

- total de pacotes processados;
- contagem e percentagem por protocolo principal;
- top 3 IPs de origem;
- contagem de eventos detetados pelo tracker.

Exemplo:

```text
Resumo:
  tipo de fonte: live
  fonte: eth0
  filtro configurado: (sem filtro)
  pacotes processados: 120

Estatísticas:
  protocolos:
    ARP: 10 (8.3%)
    ICMP: 20 (16.7%)
    TCP: 70 (58.3%)
    UDP: 15 (12.5%)
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

## Exemplos de comandos

Capturar TCP numa interface:

```bash
sudo python3 main.py -i eth0 --protocol tcp
```

Ler apenas tráfego UDP de um PCAP:

```bash
python3 main.py -r captura.pcap --protocol udp
```

Capturar HTTP com BPF e guardar log CSV:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80" --log-file http.csv --log-format csv
```

Capturar 100 pacotes e guardar a captura crua:

```bash
sudo python3 main.py -i eth0 -c 100 --write-pcap saida.pcap
```

Ler um PCAP e gerar JSON Lines:

```bash
python3 main.py -r captura.pcap --log-file captura.jsonl --log-format json
```

## Limitações conhecidas

- Não faz parsing profundo de payload de aplicação.
- Não reconstrói streams TCP.
- Não implementa timeouts avançados para o estado do tracker.
- O tracking é best effort e depende da ordem dos pacotes observados.
- BPF bruto está limitado ao modo live.
- O modo offline aplica apenas filtros amigáveis.
- Não há deteção agressiva de protocolos de aplicação; os serviços são sugeridos apenas por portas conhecidas.

## Demonstração no CORE e numa interface real

### No CORE

1. Criar uma topologia simples com dois ou mais nós.
2. Iniciar a sessão e abrir terminal no nó onde o sniffer vai correr.
3. Identificar a interface do nó, por exemplo com:

```bash
ip addr
```

4. Correr o sniffer:

```bash
sudo python3 main.py -i eth0
```

5. Gerar tráfego entre nós:

```bash
ping 10.0.0.2
curl http://10.0.0.2
```

6. Observar pacotes, eventos ICMP/TCP e estatísticas finais.

Também é possível guardar logs:

```bash
sudo python3 main.py -i eth0 --log-file core.csv --log-format csv
```

### Numa interface real

1. Listar interfaces disponíveis no sistema.
   - macOS: `ifconfig`, normalmente `en0`.
   - Linux: `ip addr`, normalmente `eth0`, `ens33` ou `wlan0`.
2. Escolher a interface ativa.
3. Executar com privilégios adequados.

macOS:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30
```

Linux:

```bash
sudo python3 main.py -i eth0 --timeout 30
```

4. Para uma demonstração controlada, usar filtros:

macOS:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

Linux:

```bash
sudo python3 main.py -i eth0 --protocol icmp
sudo python3 main.py -i eth0 --bpf "tcp port 80"
```

5. Interromper com `Ctrl+C` para ver o resumo final quando não for usado `--count` ou `--timeout`.
