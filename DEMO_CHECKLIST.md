# Checklist de Demonstração

Checklist prática para preparar e executar a demonstração do packet sniffer em macOS, Linux ou CORE. O ambiente real observado usou macOS com a interface `en0`, mas os comandos equivalentes para Linux/CORE também estão indicados.

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
- [ ] Criar a virtualenv, se ainda não existir:

```bash
python3 -m venv .venv
```

- [ ] Ativar a virtualenv:

```bash
source .venv/bin/activate
```

- [ ] Confirmar que Scapy está instalado na virtualenv:

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

- [ ] Identificar a interface a usar na demonstração:

macOS, normalmente `en0`:

```bash
ifconfig
```

Linux/CORE, normalmente `eth0`, `ens33` ou `wlan0`:

```bash
ip addr
```

- [ ] Se for preciso testar modo offline e ainda não existir `captura.pcap`, gerar primeiro um PCAP:

macOS:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

Linux/CORE:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
```

- [ ] Confirmar que o PCAP gerado pode ser lido:

```bash
python3 main.py -r captura.pcap -c 10
```

## Comandos prontos para macOS

Captura live curta em `en0`:

```bash
sudo .venv/bin/python main.py -i en0 -c 20
```

Leitura offline do PCAP gerado:

```bash
python3 main.py -r captura.pcap -c 20
```

Filtro ICMP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
```

Filtros mais específicos por IP, porta e fragmentação:

```bash
sudo .venv/bin/python main.py -i en0 --src-ip 10.0.0.1 --dst-port 53 --protocol udp
python3 main.py -r fragmentado.pcap --fragmented
```

Traceroute ICMP:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
traceroute -I 8.8.8.8
```

Filtro TCP com BPF:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

Logging CSV:

```bash
sudo .venv/bin/python main.py -i en0 -c 50 --log-file demo.csv --log-format csv
```

Guardar captura crua:

```bash
sudo .venv/bin/python main.py -i en0 -c 50 --write-pcap demo.pcap
```

Fragmentação IPv4 em PCAP:

```bash
python3 main.py -r fragmentado.pcap
```

Nota: `fragmentado.pcap` não vem incluído no repositório e deve ser gerado ou preparado localmente para a demonstração.

Consulta interativa no fim da execução:

```bash
python3 main.py -r captura.pcap -c 5
```

## Demonstração no CORE

- [ ] Abrir a topologia no CORE.
- [ ] Iniciar a sessão.
- [ ] Abrir terminal no nó onde o sniffer vai correr.
- [ ] Confirmar a interface do nó com `ip addr`. Em CORE/Linux, `eth0` é um exemplo comum.
- [ ] Correr o sniffer:

```bash
sudo python3 main.py -i eth0
```

- [ ] Gerar ICMP entre nós:

```bash
ping 10.0.0.2
```

- [ ] Mostrar:
  - linhas por pacote com número e timestamp;
  - parsing IPv4/ICMP;
  - eventos `ICMP reply recebido`;
  - referência `request in line ...` quando o echo-reply corresponder a um request observado;
  - existência de filtros mais específicos por IP de origem/destino, porta e fragmentação IPv4;
  - eventual evento `Possível traceroute detetado`, quando o padrão de TTL crescente surgir;
  - estatísticas finais após `Ctrl+C`;
  - consulta interativa de um pacote pelo número no fim da execução, quando houver pelo menos um pacote.

- [ ] Gerar TCP, se houver um serviço HTTP no destino:

```bash
curl http://10.0.0.2
```

- [ ] Mostrar:
  - timestamp por pacote no output;
  - portas TCP;
  - flags `SYN`, `SYN-ACK`, `ACK`;
  - evento `TCP handshake concluído`;
  - hint `HTTP` quando a porta 80 for usada.

- [ ] Demonstrar logging:

```bash
sudo python3 main.py -i eth0 -c 20 --log-file core.csv --log-format csv
```

- [ ] Abrir ou mostrar o ficheiro `core.csv`.
- [ ] Confirmar que o log mostra timestamp por pacote.
- [ ] Mostrar que ARP, ICMP e DNS podem incluir referências simples como `request in line ...`.
- [ ] Se for útil para a defesa, correr `traceroute -I 8.8.8.8` e mostrar o evento `Possível traceroute detetado`.
- [ ] Se houver um PCAP preparado com fragmentação IPv4, abri-lo e mostrar os campos `id`, `offset` e `MF`, bem como o evento `Fragmentos IPv4 completos`.

## Demonstração numa interface real macOS

- [ ] Confirmar que a interface ativa é `en0` ou ajustar os comandos se for outra.
- [ ] Usar uma captura curta com timeout:

```bash
sudo .venv/bin/python main.py -i en0 --timeout 30
```

- [ ] Usar filtro para reduzir ruído:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
```

- [ ] Gerar tráfego ICMP:

```bash
ping 8.8.8.8
```

- [ ] Demonstrar BPF:

```bash
sudo .venv/bin/python main.py -i en0 --bpf "tcp port 80"
```

- [ ] Demonstrar possível traceroute com a variante ICMP, que tende a ser mais limpa:

```bash
sudo .venv/bin/python main.py -i en0 --protocol icmp
traceroute -I 8.8.8.8
```

- [ ] Demonstrar fragmentação IPv4 com um PCAP preparado, ou tentar geração live com `ping` grande se a rede o permitir:

```bash
python3 main.py -r fragmentado.pcap
```

- [ ] Demonstrar escrita para PCAP. Se `captura.pcap` ainda não existir, este é o passo que o cria:

```bash
sudo .venv/bin/python main.py -i en0 -c 30 --write-pcap captura.pcap
```

- [ ] Ler o PCAP gerado em modo offline:

```bash
python3 main.py -r captura.pcap -c 10
```

- [ ] Depois de o programa terminar, escolher um número de pacote na prompt interativa.
- [ ] Mostrar o detalhe textual desse pacote.
- [ ] Sair com `0`.

## Demonstração numa interface real Linux

- [ ] Confirmar a interface ativa com `ip addr`. Exemplos comuns: `eth0`, `ens33`, `wlan0`.
- [ ] Usar uma captura curta com timeout:

```bash
sudo python3 main.py -i eth0 --timeout 30
```

- [ ] Usar filtro para reduzir ruído:

```bash
sudo python3 main.py -i eth0 --protocol icmp
```

- [ ] Demonstrar possível traceroute com a variante ICMP:

```bash
sudo python3 main.py -i eth0 --protocol icmp
traceroute -I 8.8.8.8
```

- [ ] Demonstrar fragmentação IPv4 com um PCAP preparado, ou tentar geração live com `ping` grande se o ambiente o permitir:

```bash
python3 main.py -r fragmentado.pcap
```

- [ ] Demonstrar escrita para PCAP, caso ainda não exista um ficheiro para modo offline:

```bash
sudo python3 main.py -i eth0 -c 30 --write-pcap captura.pcap
```

- [ ] Ler o PCAP gerado:

```bash
python3 main.py -r captura.pcap -c 10
```

## Pontos principais a explicar

- A aplicação separa responsabilidades em módulos simples.
- `main.py` trata da CLI e validação.
- `capture.py` trata da captura live/offline e do callback.
- `parsing.py` faz desencapsulamento e resumos.
- `tracking.py` mantém estado simples para ARP, ICMP, TCP, possível traceroute e fragmentação IPv4.
- `logging_output.py` escreve TXT, CSV e JSON Lines.
- `stats.py` agrega estatísticas finais.
- Cada pacote mostrado na consola inclui número do pacote e timestamp.
- Os logs TXT, CSV e JSON Lines também guardam timestamp por pacote.
- O tracking é best effort, adequado para demonstração académica, mas não é um motor completo de flows.
- Os filtros amigáveis suportam agora critérios mais específicos por IP de origem/destino, porta TCP/UDP, fragmentação IPv4, `id` e flag `MF`.
- O resumo pode indicar relações simples entre pacotes, como `request in line ...` para ARP, ICMP e DNS.
- No fim da execução, o programa pode rever um pacote específico pelo número.
- Essa vista detalhada reutiliza a informação já extraída durante o parsing, sem alterar o output normal da captura.
- A deteção de possível traceroute usa uma heurística simples baseada em TTL crescente.
- A fragmentação IPv4 é identificada por campos como `id`, `offset` e `MF`.
- Os fragmentos são agrupados de forma lógica por datagrama, sem reconstrução profunda de payload.
- Quando o conjunto observado parece completo, surge o evento `Fragmentos IPv4 completos`.
- É possível observar traceroute em UDP ou em ICMP com `traceroute -I`; a variante ICMP tende a ser mais limpa para demonstrar.
- O service hinting é conservador e baseado apenas em portas conhecidas.
- Em UDP, quando for claro, o resumo pode distinguir casos como `DNS query`/`DNS response` e alguns tipos DHCP.
- O projeto não faz parsing profundo de payload nem reconstrução de streams TCP.

## Plano B

- Se a captura live falhar por permissões, executar com `sudo`.
- Em macOS, quando se usa `sudo`, preferir `sudo .venv/bin/python main.py ...` para garantir que é usado o Scapy instalado na virtualenv.
- Se não houver tráfego suficiente, gerar `ping`, `curl` ou `nc`.
- Se a interface real estiver ruidosa, usar `--protocol icmp`, `--protocol tcp` ou BPF.
- Se ainda não houver PCAP para modo offline, gerar `captura.pcap` com `--write-pcap`.
