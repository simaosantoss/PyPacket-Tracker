# Plano de Testes

Este plano cobre os testes principais para validar o packet sniffer antes da demonstração. Os comandos devem ser ajustados ao nome real da interface e aos endereços IP usados no ambiente de teste.

Assume-se:

- interface de exemplo: `eth0`
- ficheiro PCAP de exemplo: `captura.pcap`
- IPs de exemplo: `10.0.0.1` e `10.0.0.2`

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

### Duas fontes em simultâneo

Objetivo: garantir que não é possível usar live e offline ao mesmo tempo.

Comando:

```bash
python3 main.py -i eth0 -r captura.pcap
```

Resultado esperado: erro a indicar que deve ser indicada exatamente uma fonte.

### Protocolo inválido

Objetivo: validar a lista fechada de protocolos suportados nos filtros amigáveis.

Comando:

```bash
python3 main.py -i eth0 --protocol dns
```

Resultado esperado: erro a indicar os protocolos suportados: `arp`, `icmp`, `ip`, `tcp`, `udp`.

### Logging incompleto

Objetivo: confirmar que `--log-file` e `--log-format` são usados em conjunto.

Comando:

```bash
python3 main.py -i eth0 --log-file teste.csv
```

Resultado esperado: erro a indicar que `--log-file` e `--log-format` têm de ser usados em conjunto.

## 3. Captura live

Objetivo: confirmar captura em tempo real numa interface.

Comando:

```bash
sudo python3 main.py -i eth0 -c 10
```

Resultado esperado: até 10 linhas de pacotes na consola, seguidas de resumo e estatísticas finais.

## 4. Leitura offline

Objetivo: confirmar leitura de um ficheiro PCAP.

Comando:

```bash
python3 main.py -r captura.pcap -c 10
```

Resultado esperado: até 10 pacotes lidos do PCAP, prefixados com `[offline:captura.pcap]`, seguidos de resumo e estatísticas.

## 5. Filtros amigáveis

### Filtro por IP

Objetivo: processar apenas pacotes associados a um IP.

Comando:

```bash
sudo python3 main.py -i eth0 --ip 10.0.0.1 -c 10
```

Resultado esperado: pacotes capturados relacionados com `10.0.0.1`.

### Filtro por MAC

Objetivo: processar apenas pacotes associados a um MAC.

Comando:

```bash
sudo python3 main.py -i eth0 --mac aa:bb:cc:dd:ee:ff -c 10
```

Resultado esperado: pacotes associados ao MAC indicado, se existirem.

### Filtro por protocolo

Objetivo: filtrar por protocolo suportado.

Comando:

```bash
sudo python3 main.py -i eth0 --protocol icmp -c 10
```

Resultado esperado: apenas pacotes ICMP, quando houver tráfego ICMP.

## 6. BPF em modo live

Objetivo: confirmar suporte de BPF bruto em captura live.

Comando:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80" -c 10
```

Resultado esperado: apenas pacotes que correspondam ao BPF, tipicamente tráfego TCP na porta 80.

## 7. Escrita para PCAP

Objetivo: confirmar que a captura crua pode ser guardada.

Comando:

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

Resultado esperado: `teste.txt` com linhas no formato `[n] [fonte] resumo`.

### CSV

Objetivo: confirmar cabeçalho e colunas estáveis.

Comando:

```bash
python3 main.py -r captura.pcap -c 5 --log-file teste.csv --log-format csv
```

Resultado esperado: `teste.csv` com cabeçalho e campos como `packet_number`, `protocol`, `src_ip`, `dst_ip`, `summary`.

### JSON Lines

Objetivo: confirmar um objeto JSON por linha.

Comando:

```bash
python3 main.py -r captura.pcap -c 5 --log-file teste.jsonl --log-format json
```

Resultado esperado: `teste.jsonl` com uma linha JSON por pacote.

## 9. Parsing ARP

Objetivo: validar resumo de pacotes ARP.

Comando:

```bash
sudo python3 main.py -i eth0 --protocol arp
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
sudo python3 main.py -i eth0 --protocol icmp
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
sudo python3 main.py -i eth0 --protocol tcp
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
sudo python3 main.py -i eth0 --protocol udp
```

Tráfego a gerar, se houver DNS disponível:

```bash
dig example.com
```

Resultado esperado: linhas IPv4 com `UDP` e `DNS` se houver tráfego na porta 53.

## 13. Evento ARP

Objetivo: detetar resolução ARP request -> reply.

Comando:

```bash
sudo python3 main.py -i eth0 --protocol arp
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
sudo python3 main.py -i eth0 --protocol icmp
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
sudo python3 main.py -i eth0 --protocol tcp
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

## 16. Estatísticas finais

Objetivo: confirmar o relatório final.

Comando:

```bash
sudo python3 main.py -i eth0 --timeout 30
```

Resultado esperado: no fim aparecem `Resumo` e `Estatísticas`, incluindo protocolos, top talkers e eventos detetados.
