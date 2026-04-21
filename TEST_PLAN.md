# Plano de Testes

Este plano cobre os testes principais para validar o packet sniffer antes da demonstração. Os comandos devem ser ajustados ao nome real da interface e aos endereços IP usados no ambiente de teste.

Assume-se:

- interface macOS usada na demonstração real: `en0`
- interface genérica em Linux/CORE: `eth0`
- ficheiro PCAP de exemplo: `captura.pcap`, gerado durante os testes se ainda não existir
- IPs de exemplo: `10.0.0.1` e `10.0.0.2`

Em macOS, os comandos live devem usar preferencialmente `sudo .venv/bin/python main.py ...`, para garantir que o Scapy instalado na virtualenv é usado mesmo com `sudo`.

Em Linux/CORE, o equivalente habitual é `sudo python3 main.py -i eth0 ...`, ajustando `eth0` à interface real indicada por `ip addr`.

## 1. Arranque da aplicação

### Ajuda da CLI

Objetivo: confirmar que a aplicação arranca e apresenta as opções disponíveis.

Comando:

```bash
python3 main.py --help
```

Resultado esperado: aparece a ajuda com opções como `--interface`, `--pcap`, `--bpf`, `--log-file` e `--log-format`.

### Execução sem fonte

Objetivo: confirmar que a aplicação exige exatamente uma fonte de captura.

Comando:

```bash
python3 main.py
```

Resultado esperado: erro claro a indicar que deve ser usado `--interface` ou `--pcap`.

## 2. Validação de argumentos

Os exemplos usam `en0`; em Linux/CORE pode ser usado `eth0` ou qualquer interface real. Nestes testes, o objetivo é validar argumentos, não capturar tráfego.

### Duas fontes em simultâneo

Objetivo: garantir que não é possível usar live e offline ao mesmo tempo.

Comando:

```bash
python3 main.py -i en0 -r captura.pcap
```

Resultado esperado: erro a indicar que deve ser indicada exatamente uma fonte.

### Protocolo inválido

Objetivo: validar a lista fechada de protocolos suportados nos filtros amigáveis.

Comando:

```bash
python3 main.py -i en0 --protocol dns
```

Resultado esperado: erro a indicar os protocolos suportados: `arp`, `icmp`, `ip`, `tcp`, `udp`.

### Logging incompleto

Objetivo: confirmar que `--log-file` e `--log-format` são usados em conjunto.

Comando:

```bash
python3 main.py -i en0 --log-file teste.csv
```

Resultado esperado: erro a indicar que `--log-file` e `--log-format` têm de ser usados em conjunto.

## 3. Captura live

Objetivo: confirmar captura em tempo real numa interface.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 -c 10
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 10
```

Resultado esperado: até 10 linhas de pacotes na consola, seguidas de resumo e estatísticas finais.
Cada linha de pacote deve incluir a origem da captura, timestamp e resumo do protocolo.

## 4. Leitura offline

Objetivo: confirmar leitura de um ficheiro PCAP.

Se `captura.pcap` ainda não existir, gerar primeiro:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
```

Comando:

```bash
python3 main.py -r captura.pcap -c 10
```

Resultado esperado: até 10 pacotes lidos do PCAP gerado, prefixados com `[offline:captura.pcap]`, cada um com timestamp e resumo do protocolo, seguidos de resumo e estatísticas.

## 5. Filtros amigáveis

Os comandos seguintes usam macOS/`en0`. Em Linux/CORE, trocar por `sudo python3 main.py -i eth0 ...`.

### Filtro por IP

Objetivo: processar apenas pacotes associados a um IP.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --ip 10.0.0.1 -c 10
```

Resultado esperado: pacotes capturados relacionados com `10.0.0.1`.

### Filtro por MAC

Objetivo: processar apenas pacotes associados a um MAC.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --mac aa:bb:cc:dd:ee:ff -c 10
```

Resultado esperado: pacotes associados ao MAC indicado, se existirem.

### Filtro por protocolo

Objetivo: filtrar por protocolo suportado.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp -c 10
```

Resultado esperado: apenas pacotes ICMP, quando houver tráfego ICMP.

## 6. BPF em modo live

O exemplo principal usa macOS/`en0`; em Linux/CORE, usar `sudo python3 main.py -i eth0 --bpf "tcp port 80" -c 10`.

Objetivo: confirmar suporte de BPF bruto em captura live.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80" -c 10
```

Resultado esperado: apenas pacotes que correspondam ao BPF, tipicamente tráfego TCP na porta 80.

## 7. Escrita para PCAP

Objetivo: confirmar que a captura crua pode ser guardada.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 -c 20 --write-pcap saida.pcap
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 20 --write-pcap saida.pcap
```

Resultado esperado: ficheiro `saida.pcap` criado com pacotes capturados.

Validação adicional:

```bash
python3 main.py -r saida.pcap -c 5
```

Resultado esperado: leitura offline do PCAP criado.

## 8. Logging TXT, CSV e JSON

### TXT

Objetivo: confirmar uma linha textual por pacote.

Comando:

```bash
python3 main.py -r captura.pcap -c 5 --log-file teste.txt --log-format txt
```

Resultado esperado: `teste.txt` com linhas no formato `[n] [fonte] [hora] resumo`.

### CSV

Objetivo: confirmar cabeçalho e colunas estáveis.

Comando:

```bash
python3 main.py -r captura.pcap -c 5 --log-file teste.csv --log-format csv
```

Resultado esperado: `teste.csv` com cabeçalho e campos estáveis, incluindo `timestamp`, `packet_number`, `protocol`, `src_ip`, `dst_ip` e `summary`.

### JSON Lines

Objetivo: confirmar um objeto JSON por linha.

Comando:

```bash
python3 main.py -r captura.pcap -c 5 --log-file teste.jsonl --log-format json
```

Resultado esperado: `teste.jsonl` com uma linha JSON por pacote, incluindo um campo `timestamp` em cada objeto.

## 9. Parsing ARP

Os testes de parsing e eventos usam macOS/`en0` nos comandos. Em Linux/CORE, usar a mesma opção com `sudo python3 main.py -i eth0 ...`.

Objetivo: validar resumo de pacotes ARP.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol arp
```

Tráfego a gerar:

```bash
ping 10.0.0.2
```

Resultado esperado: linhas com `ARP | request` ou `ARP | reply`, contendo IPs e MACs quando disponíveis.

## 10. Parsing ICMP

Objetivo: validar identificação de ICMP e nomes de echo.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
```

Tráfego a gerar:

```bash
ping 10.0.0.2
```

Resultado esperado: linhas com `ICMP | echo-request` e/ou `ICMP | echo-reply`.

## 11. Parsing TCP

Objetivo: validar portas, flags e hint HTTP.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol tcp
```

Tráfego a gerar:

```bash
curl http://10.0.0.2
```

Resultado esperado: linhas IPv4 com `TCP [SYN]`, `TCP [SYN-ACK]`, `TCP [ACK]` e `HTTP` quando a porta 80 estiver envolvida.

## 12. Parsing UDP

Objetivo: validar portas UDP e hint DNS/DHCP quando aplicável.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
```

Tráfego a gerar, se houver DNS disponível:

```bash
dig example.com
```

Resultado esperado: linhas IPv4 com `UDP` e, quando o pacote o permitir de forma clara, resumos como `DNS query`, `DNS response`, `DHCP Discover`, `DHCP Offer`, `DHCP Request` ou `DHCP ACK`.

## 13. Evento ARP

Objetivo: detetar resolução ARP request -> reply.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol arp
```

Tráfego a gerar:

```bash
ping 10.0.0.2
```

Resultado esperado:

```text
[evento] ARP resolvido | 10.0.0.2 está em aa:bb:cc:dd:ee:ff
```

## 14. Evento ICMP

Objetivo: detetar echo-request seguido de echo-reply.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
```

Tráfego a gerar:

```bash
ping 10.0.0.2
```

Resultado esperado:

```text
[evento] ICMP reply recebido | 10.0.0.2 respondeu a 10.0.0.1
```

## 15. Evento TCP

Objetivo: detetar 3-way handshake e encerramento por FIN/RST quando observados.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol tcp
```

Tráfego a gerar:

```bash
curl http://10.0.0.2
```

Resultado esperado:

```text
[evento] TCP handshake concluído | 10.0.0.1:54321 -> 10.0.0.2:80
[evento] TCP sessão terminada | 10.0.0.1:54321 -> 10.0.0.2:80 | FIN
```

## 16. Possível traceroute

### Cenário A: traceroute ICMP

Objetivo: validar a heurística simples de possível traceroute com `traceroute -I`, que tende a ser mais limpa de demonstrar.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0 --protocol icmp
```

Tráfego a gerar:

```bash
traceroute -I 8.8.8.8
```

Resultado esperado: pacotes ICMP relacionados com o mesmo destino, TTLs crescentes ou quase crescentes, mensagens ICMP de TTL exceeded quando surgirem e um evento como:

```text
[evento] Possível traceroute detetado | 172.26.204.185 -> 8.8.8.8
```

### Cenário B: traceroute UDP

Objetivo: validar a mesma heurística em traceroute UDP tradicional.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --protocol udp
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0 --protocol udp
```

Tráfego a gerar:

```bash
traceroute 8.8.8.8
```

Resultado esperado: pacotes UDP para o mesmo destino com TTL crescente ou quase crescente e um evento como `Possível traceroute detetado`, de forma best effort.

## 17. Fragmentação IPv4

Objetivo: validar a identificação simples de fragmentos IPv4, o agrupamento lógico por datagrama e o evento de fragmentos que parecem completos.

### Cenário A: PCAP gerado com Scapy

Comando:

```bash
python3 main.py -r fragmentado.pcap
```

Comando opcional com logging CSV:

```bash
python3 main.py -r fragmentado.pcap --log-file fragmentado.csv --log-format csv
```

Forma prática de preparar o teste: usar um PCAP gerado previamente com Scapy contendo um datagrama IPv4 fragmentado. Esta é a forma mais fiável de validar a funcionalidade.

Resultado esperado:

- linhas IPv4 com campos como `id=...`, `offset=...` e `MF` quando aplicável;
- evento como:

```text
[evento] Fragmentos IPv4 completos | 192.168.1.10 -> 8.8.8.8 | id=12345
```

- se houver logging CSV, presença das colunas `ip_id`, `fragment_offset` e `more_fragments`.

### Cenário B: teste live opcional

Comando:

```bash
sudo .venv/bin/python main.py -i en0
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0
```

Tráfego a gerar, quando o sistema, a rede e o MTU o permitirem:

```bash
ping -s 4000 8.8.8.8
```

Resultado esperado: podem surgir fragmentos IPv4 com `id=...`, `offset=...` e `MF`, além do evento `Fragmentos IPv4 completos`. Este teste é prudente e dependente do ambiente; o cenário com PCAP continua a ser o mais fiável.

## 18. Estatísticas finais

Objetivo: confirmar o relatório final.

Comando:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30
```

Equivalente Linux/CORE:

```bash
sudo python3 main.py -i eth0 --timeout 30
```

Resultado esperado: no fim aparecem `Resumo` e `Estatísticas`, incluindo protocolos, top talkers e eventos detetados.
