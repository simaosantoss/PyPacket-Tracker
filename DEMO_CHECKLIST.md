# Checklist de Demonstração

Checklist prática para preparar e executar a demonstração do packet sniffer.

## Antes da demonstração

- [ ] Confirmar que o projeto contém os ficheiros principais:
  - `main.py`
  - `capture.py`
  - `parsing.py`
  - `tracking.py`
  - `logging_output.py`
  - `stats.py`
  - `README.md`
  - `TEST_PLAN.md`
  - `EXAMPLES.md`
- [ ] Confirmar que Python 3 está instalado.
- [ ] Confirmar que Scapy está instalado:

```bash
python3 -m pip show scapy
```

- [ ] Se necessário, instalar Scapy:

```bash
python3 -m pip install scapy
```

- [ ] Confirmar que a CLI arranca:

```bash
python3 main.py --help
```

- [ ] Preparar um ficheiro PCAP de teste, por exemplo `captura.pcap`.
- [ ] Identificar a interface a usar na demonstração:

```bash
ip addr
```

ou, em macOS:

```bash
ifconfig
```

## Comandos prontos

Captura live curta:

```bash
sudo python3 main.py -i eth0 -c 20
```

Leitura offline:

```bash
python3 main.py -r captura.pcap -c 20
```

Filtro ICMP:

```bash
sudo python3 main.py -i eth0 --protocol icmp
```

Filtro TCP com BPF:

```bash
sudo python3 main.py -i eth0 --bpf "tcp port 80"
```

Logging CSV:

```bash
sudo python3 main.py -i eth0 -c 50 --log-file demo.csv --log-format csv
```

Guardar captura crua:

```bash
sudo python3 main.py -i eth0 -c 50 --write-pcap demo.pcap
```

## Demonstração no CORE

- [ ] Abrir a topologia no CORE.
- [ ] Iniciar a sessão.
- [ ] Abrir terminal no nó onde o sniffer vai correr.
- [ ] Confirmar a interface do nó com `ip addr`.
- [ ] Correr o sniffer:

```bash
sudo python3 main.py -i eth0
```

- [ ] Gerar ICMP entre nós:

```bash
ping 10.0.0.2
```

- [ ] Mostrar:
  - parsing IPv4/ICMP;
  - eventos `ICMP reply recebido`;
  - estatísticas finais após `Ctrl+C`.

- [ ] Gerar TCP, se houver um serviço HTTP no destino:

```bash
curl http://10.0.0.2
```

- [ ] Mostrar:
  - portas TCP;
  - flags `SYN`, `SYN-ACK`, `ACK`;
  - evento `TCP handshake concluído`;
  - hint `HTTP` quando a porta 80 for usada.

- [ ] Demonstrar logging:

```bash
sudo python3 main.py -i eth0 -c 20 --log-file core.csv --log-format csv
```

- [ ] Abrir ou mostrar o ficheiro `core.csv`.

## Demonstração numa interface real

- [ ] Identificar a interface real ativa.
- [ ] Usar uma captura curta com timeout:

```bash
sudo python3 main.py -i en0 --timeout 30
```

- [ ] Usar filtro para reduzir ruído:

```bash
sudo python3 main.py -i en0 --protocol icmp
```

- [ ] Gerar tráfego ICMP:

```bash
ping 8.8.8.8
```

- [ ] Demonstrar BPF:

```bash
sudo python3 main.py -i en0 --bpf "tcp port 80"
```

- [ ] Demonstrar escrita para PCAP:

```bash
sudo python3 main.py -i en0 -c 30 --write-pcap real.pcap
```

- [ ] Ler o PCAP gerado:

```bash
python3 main.py -r real.pcap -c 10
```

## Pontos principais a explicar

- A aplicação separa responsabilidades em módulos simples.
- `main.py` trata da CLI e validação.
- `capture.py` trata da captura live/offline e do callback.
- `parsing.py` faz desencapsulamento e resumos.
- `tracking.py` mantém estado simples para ARP, ICMP e TCP.
- `logging_output.py` escreve TXT, CSV e JSON Lines.
- `stats.py` agrega estatísticas finais.
- O tracking é best effort, adequado para demonstração académica, mas não é um motor completo de flows.
- O service hinting é conservador e baseado apenas em portas conhecidas.
- O projeto não faz parsing profundo de payload nem reconstrução de streams TCP.

## Plano B

- Se a captura live falhar por permissões, executar com `sudo`.
- Se não houver tráfego suficiente, gerar `ping`, `curl` ou `nc`.
- Se a interface real estiver ruidosa, usar `--protocol icmp`, `--protocol tcp` ou BPF.
- Se o ambiente live estiver instável, demonstrar com um ficheiro `.pcap` preparado.
