<div align="center">

# 🌐 NetLab Educacional

### Monitor de Redes com Motor Pedagógico
*Transformando pacotes de rede em conhecimento didático em tempo real*

---

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-6.x-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.x-FF6B35?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/Licença-Acadêmica%20%2F%20Educacional-green?style=for-the-badge)

**TCC — Curso Técnico em Informática**  
**Instituto Federal Farroupilha — Campus Uruguaiana**  
**Autor: Yuri Gonçalves Pavão · Versão 4.0 · Abril de 2026**

</div>

---

## Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Arquitetura do Sistema](#arquitetura-do-sistema)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Requisitos do Sistema](#requisitos-do-sistema)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Detalhes Técnicos](#detalhes-técnicos)
- [Contexto Acadêmico](#contexto-acadêmico)
- [Limitações Conhecidas](#limitações-conhecidas)
- [Licença](#licença)

---

## Sobre o Projeto

O **NetLab Educacional** é um software desktop de análise de redes concebido como ferramenta pedagógica para o ensino de redes de computadores em ambiente escolar. O software captura tráfego real da rede e, em vez de exibir apenas dados brutos, traduz cada evento automaticamente em **explicações acessíveis em três níveis de profundidade**.

O projeto foi desenvolvido como **Trabalho de Conclusão de Curso (TCC)** do Curso Técnico em Informática do **Instituto Federal Farroupilha (IFFar) — Campus Uruguaiana**, com foco em tornar conceitos complexos de redes — como pacotes IP, handshakes TCP, consultas DNS e vulnerabilidades HTTP — compreensíveis para estudantes de qualquer nível.

### Por que o NetLab existe?

O ensino de redes frequentemente esbarra em uma barreira: ferramentas profissionais como Wireshark são poderosas, mas mostram dados técnicos crus que intimidam iniciantes. O NetLab preenche essa lacuna ao:

- **Capturar tráfego real** da rede local sem intermediários
- **Explicar automaticamente** cada evento em linguagem simples, técnica ou como dump bruto
- **Visualizar a topologia** da rede de forma interativa e intuitiva
- **Demonstrar vulnerabilidades** de segurança de forma controlada e didática (HTTP vs HTTPS, força bruta, DoS)

---

## Funcionalidades

### Captura e Análise de Pacotes
- Captura em tempo real via **Scapy + Npcap** com suporte a TCP, UDP, DNS, ARP, ICMP, HTTP, HTTPS, DHCP, SSH, FTP, SMB e RDP
- **Deep Packet Inspection (DPI)** para HTTP: extrai método, caminho, headers, corpo do formulário e credenciais em texto puro
- Parser HTTP em **C nativo (ctypes)** para hot-path de alta performance, com fallback Python transparente
- Detecção automática de **campos sensíveis** (senhas, tokens, e-mails, CPF, etc.) e alertas de segurança em tempo real
- Identificação de OS por TTL e **fabricante por OUI (MAC address)** com base atualizável via internet
- Auto-detecção da interface de rede ativa e do CIDR da rede local (PowerShell + ipconfig + Scapy)

### Motor Pedagógico com 3 Níveis de Explicação
- **Nível Simples** — linguagem do dia a dia, sem jargão técnico, acessível a qualquer estudante
- **Nível Técnico** — detalhes de protocolo, portas, flags, vulnerabilidades e boas práticas
- **Pacote Bruto** — conteúdo exato como trafegou na rede, com hexdump + ASCII e visualização de headers HTTP destacados
- Análise automática de **indicadores de ataque**: injeção SQL, XSS, métodos HTTP incomuns, cookies expostos, headers de segurança ausentes
- **Cooldown inteligente por evento** para evitar flood na interface em redes movimentadas
- Backpressure nos workers pedagógicos: máximo 8 eventos por ciclo de 2s, prevenindo travamento da UI

### Visualizador de Topologia Interativo
- Mapa gráfico da rede local com zoom (scroll), pan (arrastar) e seleção de nós
- Tamanho dos nós proporcional ao volume de tráfego (escala logarítmica)
- Tooltip com hostname/apelido ao passar o mouse; painel de detalhes ao clicar
- Destaque de conexões ao selecionar um dispositivo
- Exibição de **fabricante** (OUI) e **apelido personalizado** no painel de detalhes
- Duplo clique em um nó para definir um apelido customizado (persistido em JSON)
- **ARP sweep automático** com múltiplas rodadas e retry para descoberta de hosts
- Importação da tabela ARP do sistema operacional (a cada 60s, sem varredura ativa)
- Agrupamento de IPs externos em nó "Internet"
- Classificação CONFIRMADO (ARP) vs OBSERVADO (captura passiva) por dispositivo
- Suporte opcional à exibição de sub-redes com borda visual por segmento

### Painel de Tráfego em Tempo Real
- Gráfico de KB/s com **histórico de até 2 horas** (deque de 7.200 amostras a 1 Hz)
- **Duas curvas sobrepostas**: bruta (volatilidade real) e EMA suavizada (tendência)
- **Crosshair interativo** com tooltip de valor exato ao mover o mouse
- **Navegação temporal**: botões ⏮ / ◀30s / ◀10s / ⏸ Pausar / 10s▶ / 30s▶ / ▶▶ Ao Vivo
- Controle de suavização EMA com slider (α de 0,05 a 0,50); recomputa histórico ao ajustar
- Cards com total de pacotes, dados transmitidos, dispositivos ativos e velocidade atual
- Tabela de protocolos detectados com contagem e volume de dados
- Top dispositivos por tráfego (enviado, recebido e total)

### Aba Modo Análise (Eventos ao Vivo + Insights)
- Lista lateral de eventos capturados com filtragem por protocolo e texto livre
- Guard de chave nos filtros: reconstrói a lista apenas quando há mudança real (evita freeze ao trocar de aba)
- Cap de 120 widgets no QListWidget com remoção O(1) do mais antigo (sem recriar a lista)
- **Lazy loading**: filtros reaplicados apenas ao tornar a aba visível
- Aba Insights com **domínios mais acessados** (DNS real) e **classificação de uso da rede**
- Diff incremental nos insights: não recria widgets quando os dados não mudaram
- Barra de resumo da sessão com contadores de eventos, consultas DNS, volume trafegado e alertas

### Servidor HTTP Embutido para Demonstrações
- Servidor multi-threaded (`ThreadingMixIn`) com páginas de login, cadastro e formulário
- **Modo Vulnerável**: senha em texto puro, sem limites — demonstra como credenciais aparecem capturadas
- **Modo Seguro**: hash PBKDF2+salt, rate limiting por IP (janela deslizante de 1s), bloqueio temporário e CAPTCHA após 3 falhas
- Cadastro de usuários em runtime em ambos os modos
- Proteção contra DoS com controle de req/s por IP, bloqueio automático e desbloqueio manual
- Monitoramento de requisições em tempo real com tabela e log de alertas didáticos
- Silenciamento de BrokenPipeError/ConnectionResetError esperados em testes de carga

### Identificação de Fabricantes (OUI)
- Base OUI embutida com centenas de fabricantes mapeados manualmente
- Integração com a biblioteca `manuf` para cobertura ampliada
- **Atualização online** da base via base do Wireshark com um clique (Menu Monitoramento → Atualizar Base de Fabricantes)
- Apelidos personalizados por dispositivo persistidos em JSON local

---

## Arquitetura do Sistema

O NetLab é organizado em **três camadas de performance** para garantir que a interface gráfica jamais trave:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERFACE (UI Thread)                        │
│  QTimer 250ms → _consumir_fila() → enfileirar() + coletar()        │
│  QTimer 1000ms → _atualizar_ui_por_segundo() → painéis visuais     │
│  QTimer 2000ms → _descarregar_eventos_ui() → backpressure (máx 8)  │
│  QThreadPool (max 4) → Motor Pedagógico → pyqtSignal → UI          │
│  Lazy loading: filtros reaplicados só ao abrir a aba Modo Análise   │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ deque(maxlen=5.000)  ← sem bloqueio
┌───────────────────────────▼─────────────────────────────────────────┐
│                   CAMADA 2 — ThreadAnalisador                       │
│  Thread daemon · lotes de 200 pacotes · SLEEP_VAZIO = 5ms          │
│  _parsear_pacote() → classificação + DPI HTTP + estatísticas        │
│  Resultados → fila_saida deque(maxlen=5.000)                        │
└───────────────────────────┬─────────────────────────────────────────┘
                            │ deque(maxlen=20.000)
┌───────────────────────────▼─────────────────────────────────────────┐
│               CAMADA 1 — _CapturadorPacotesThread                   │
│  AsyncSniffer (Scapy) · filtro "ip or arp" · daemon                │
│  Rate limit: 800 pkt/s máx · reinicialização automática em falha   │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐    ┌──────────────────────────────────────────┐
│  netlab_core_lib.c   │    │  http_parser.c                           │
│  Buffer circular C   │    │  Parser HTTP minimalista (ctypes)        │
│  Métricas de KB/s    │    │  Hot-path 10× mais rápido que Python     │
│  Fallback Python puro│    │  Fallback Python transparente            │
└──────────────────────┘    └──────────────────────────────────────────┘
```

### Decisões de Design

| Decisão | Motivo |
|---|---|
| `deque(maxlen=N)` em todas as filas | Zero OOM mesmo em picos — descarte automático do mais antigo |
| `QThreadPool` (máx 4) para DPI | Elimina vazamento de threads por reuso de workers |
| Backpressure (máx 8 ev/ciclo) | Impede que redes movimentadas travem a UI thread |
| Guard de chave nos filtros | Evita recriação de 100+ widgets ao trocar de aba |
| Cap de 120 itens no QListWidget | takeItem(0) é O(1) — sem recriar a lista inteira |
| Parser HTTP em C (ctypes) | Parsing de regex em Python é gargalo em capturas de alto volume |
| EMA α=0,20 no gráfico KB/s | Suaviza spikes sem atrasar a leitura visual da velocidade real |
| Cooldown por evento (3–5s) | Evita flood de eventos redundantes na UI em redes ativas |
| Debounce 800ms no layout de topologia | `_recalcular_layout()` é O(n²) — não executar a cada pacote |
| Importação da tabela ARP do OS | Mostra dispositivos reais sem depender apenas de varredura ativa |

---

## Tecnologias Utilizadas

| Tecnologia | Versão | Função |
|---|---|---|
| **Python** | 3.11 | Linguagem principal |
| **PyQt6** | 6.x | Interface gráfica (janelas, painéis, widgets) |
| **Scapy** | 2.x | Captura e decodificação de pacotes de rede |
| **PyQtGraph** | latest | Gráfico de tráfego em tempo real (alto desempenho) |
| **manuf** | latest | Base OUI de fabricantes do Wireshark |
| **ReportLab** | latest | Geração de relatórios PDF |
| **Npcap** | 1.87+ | Driver de captura de pacotes para Windows |
| **GCC / MSVC** | — | Compilação dos módulos C nativos |
| **PyInstaller** | latest | Empacotamento do executável `.exe` |

---

## Requisitos do Sistema

### Hardware (Mínimo)
| Componente | Especificação |
|---|---|
| Processador | Intel Core i3 ou equivalente (≥ 1,5 GHz) |
| Memória RAM | 4 GB (recomendado: 8 GB) |
| Espaço em Disco | 500 MB disponíveis |
| Resolução | 1280 × 720 pixels |

### Software
- **Windows 10 (64 bits)** ou superior
- **Npcap 1.87+** com *WinPcap API-compatible mode* ativado
- **Microsoft Visual C++ Redistributable x64**

> ⚠️ **Obrigatório:** O NetLab deve ser executado com **privilégios de Administrador**. Sem isso, o driver Npcap não consegue capturar pacotes no nível de hardware.

---

## Instalação

### Opção 1 — Instalador Automático (Recomendado)

1. Baixe o arquivo `NetLab_Setup.exe`
2. Clique com o **botão direito** → **Executar como administrador**
3. Siga o assistente de instalação
4. Na tela do Npcap, certifique-se de marcar **"WinPcap API-compatible mode"**
5. Ao finalizar, marque **"Executar NetLab"** e clique em **Concluir**

### Opção 2 — A partir do Código-Fonte

**Pré-requisitos:** Python 3.11, Git, GCC (MinGW no Windows)

```bash
# 1. Clone o repositório
git clone https://github.com/Yurigonpav/netlab-educacional.git
cd netlab-educacional

# 2. Instale as dependências Python
pip install -r requirements.txt

# 3. (Opcional, mas recomendado) Compile os módulos C nativos
python compilar_http_parser.py
python setup_netlab.py build_gcc

# 4. Execute como Administrador
python main.py
```

**`requirements.txt`:**
```
PyQt6
scapy
pyqtgraph
cryptography
reportlab
manuf
```

### Opção 3 — Build do Executável

```bash
# Gera o executável na pasta dist\NetLab\
build_exe.bat
```

### Compilação dos Módulos C Nativos (Opcional)

Os módulos C melhoram a performance em capturas de alto volume. O software funciona sem eles (fallback Python puro ativado automaticamente).

```bash
# Windows (MinGW)
gcc -O2 -shared -o netlab_core_lib.dll netlab_core_lib.c
gcc -O2 -shared -o http_parser.dll http_parser.c

# Linux / macOS
gcc -O2 -shared -fPIC -o netlab_core_lib.so netlab_core_lib.c
gcc -O2 -shared -fPIC -o http_parser.so http_parser.c
```

---

## Como Usar

### 1. Iniciando a Captura

1. Abra o NetLab **como Administrador**
2. Na barra de ferramentas, selecione a **interface de rede** ativa (Wi-Fi ou Ethernet) — o NetLab detecta automaticamente a interface com tráfego
3. Clique em **"Iniciar Captura"** (botão verde)
4. Abra qualquer site no navegador — os pacotes aparecerão imediatamente

> 💡 **Não sabe qual interface selecionar?** Execute `python diagnostico.py` em um terminal como Administrador. Ele testa cada interface por 4 segundos e indica qual está recebendo tráfego.

### 2. Explorando os Painéis

| Aba | O que mostra |
|---|---|
| **Topologia da Rede** | Mapa gráfico interativo dos dispositivos detectados. Scroll para zoom, arrastar para mover, clicar para detalhes, duplo clique para definir apelido. |
| **Tráfego em Tempo Real** | Gráfico histórico de KB/s com navegação temporal, protocolos detectados e top dispositivos por volume. |
| **Modo Análise** | Eventos de rede com explicações didáticas em 3 níveis + aba Insights com domínios e classificação de uso. |
| **Servidor** | Servidor HTTP embutido para demonstrações de segurança em sala de aula. |

### 3. Modo Análise — Os 3 Níveis de Explicação

Para cada evento capturado (DNS, HTTP, HTTPS, ARP, TCP, etc.):

- **Simples** — *"O computador 192.168.0.5 está perguntando para a rede qual é o IP de google.com"*
- **Técnico** — detalhes do protocolo, portas, flags TCP, TTL, vulnerabilidades detectadas, headers HTTP
- **Pacote Bruto** — conteúdo exato transmitido, hexdump + ASCII, campos de formulário destacados, alertas de segurança

### 4. Demonstração de Segurança com o Servidor Embutido

```
1. Vá para a aba "Servidor"
2. Clique em "Iniciar Servidor" (porta padrão: 8080)
3. Acesse http://<seu-IP>:8080/login de outro dispositivo na mesma rede
4. Modo VULNERÁVEL: faça login — observe as credenciais em texto puro no Modo Análise
5. Modo SEGURO: ative o modo seguro e refaça — as proteções entram em ação
```

### 5. Identificação de Fabricantes

- Dispositivos descobertos exibem o fabricante no painel de detalhes da topologia
- Para atualizar a base OUI: **Menu Monitoramento → Atualizar Base de Fabricantes**
- Duplo clique em qualquer nó da topologia permite definir um apelido personalizado

---

## Estrutura do Projeto

```
netlab-educacional/
│
├── main.py                      # Ponto de entrada — inicializa Qt, tema e janela principal
├── analisador_pacotes.py        # Processamento de pacotes (3 camadas async)
├── motor_pedagogico.py          # Geração de explicações didáticas por protocolo
├── netlab_core.py               # Wrapper ctypes para netlab_core_lib
├── painel_servidor.py           # Servidor HTTP embutido para demonstrações
├── diagnostico.py               # Ferramenta de diagnóstico de interfaces de rede
│
├── netlab_core_lib.c            # Buffer circular C — métricas de KB/s (O(1))
├── http_parser.c                # Parser HTTP em C — hot-path DPI
├── compilar_http_parser.py      # Script de compilação do http_parser.c
├── setup_netlab.py              # Script de compilação do netlab_core_lib.c
│
├── interface/
│   ├── __init__.py
│   ├── janela_principal.py      # Janela principal, timers, controle de captura
│   ├── painel_topologia.py      # Visualizador de topologia interativo (PyQt6)
│   ├── painel_trafego.py        # Gráfico histórico KB/s, navegação temporal, EMA
│   ├── painel_eventos.py        # Modo Análise — eventos, filtros, Insights
│   └── painel_login.py          # Laboratório de login vulnerável (educacional)
│
├── utils/
│   ├── constantes.py            # Portas, classificações, constantes globais
│   ├── rede.py                  # Helpers de rede (IP local, validação, formatação)
│   ├── identificador.py         # GerenciadorDispositivos, OUI, aliases, fabricantes
│   └── gerenciador_subredes.py  # GerenciadorSubRedes, classificação de IPs por segmento
│
├── recursos/
│   └── estilos/
│       └── tema_escuro.qss      # Folha de estilos Qt (tema dark personalizado)
│
├── requirements.txt             # Dependências Python
├── build_exe.bat                # Script de build do executável (PyInstaller)
└── .gitattributes
```

---

## Detalhes Técnicos

### netlab_core_lib.c — Buffer Circular de Alta Performance

Módulo C com buffer circular de 8.192 posições (potência de 2, mascaramento com `& (N-1)`) para cálculo eficiente de KB/s em janela deslizante. Todas as operações são O(1) amortizado, sem alocação dinâmica. Compilado como DLL/SO e carregado via ctypes; se não encontrado, o fallback Python puro (`_FallbackCore`) é ativado silenciosamente.

```
Índices de protocolo (sincronizados entre C e Python)
0=TCP  1=UDP  2=DNS  3=HTTP  4=HTTPS  5=ARP
6=ICMP 7=DHCP 8=TCP_SYN  9=OUTRO
```

### http_parser.c — Parser HTTP Minimalista

Exporta `parse_http_request()` que identifica o método HTTP, extrai o recurso (path + query) e busca credenciais no corpo POST. Sem dependências externas, sem alocação dinâmica. Resultado retornado em struct `HttpResult` lida diretamente pelo ctypes Python.

### Motor Pedagógico — Deep Packet Inspection

Para cada tipo de evento, o `MotorPedagogico` gera explicações ricas com os dados reais do pacote:

- Detecção de **indicadores de ataque** via regex: `union select`, `or 1=1`, `<script>`, `../`, `xp_cmdshell`
- Verificação de **headers de segurança ausentes**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Estimativa de **sistema operacional** pelo TTL (Windows=128, Linux=64, Embedded=32)
- Identificação de **fabricante** pelo OUI (3 primeiros bytes do MAC)
- **Hexdump** dos primeiros 2.048 bytes do payload com visualização ASCII
- **Hook educacional HTTP** fail-safe: analisa payloads mesmo sem credenciais explícitas e registra alertas internos

### Concorrência e Threading

```
UI Thread (Qt)
  ├── QTimer 250ms  → _consumir_fila()              ← coleta pacotes + eventos
  ├── QTimer 1000ms → _atualizar_ui_por_segundo()   ← redraw visual
  ├── QTimer 2000ms → _descarregar_eventos_ui()     ← backpressure (máx 8)
  ├── QTimer 30s    → _descoberta_periodica()       ← ARP sweep
  ├── QTimer 60s    → _popular_topologia_via_arp()  ← tabela ARP do OS
  └── QTimer 120s   → _atualizar_subredes_rotas()   ← rotas detectadas

QThreadPool (max 4 workers)
  └── _WorkerRunnable → motor.gerar_explicacao() → pyqtSignal → UI

ThreadAnalisador (daemon)
  └── consome deque(maxlen=20.000), produz deque(maxlen=5.000)

_CapturadorPacotesThread (daemon)
  └── AsyncSniffer (Scapy) · rate limit 800 pkt/s · restart automático

_DescobrirDispositivosThread (daemon)
  └── ARP sweep (múltiplas rodadas) + ICMP L2 paralelo
```

---

## Contexto Acadêmico

Este projeto foi desenvolvido como **Trabalho de Conclusão de Curso (TCC)** do **Curso Técnico em Informática** do **Instituto Federal Farroupilha (IFFar) — Campus Uruguaiana**.

**Objetivo acadêmico:** desenvolver uma ferramenta que torne o ensino de redes de computadores mais acessível e prático, permitindo que professores demonstrem em tempo real conceitos como protocolos de comunicação, topologia de rede, vulnerabilidades de segurança e mecanismos de proteção.

| | |
|---|---|
| **Aluno** | Yuri Gonçalves Pavão |
| **Instituição** | Instituto Federal Farroupilha — Campus Uruguaiana |
| **Curso** | Técnico em Informática |
| **Ano** | 2026 |
| **Instagram** | @yuri_g0n |
| **GitHub** | github.com/Yurigonpav |

---

## Limitações Conhecidas

| Limitação | Detalhes |
|---|---|
| **Permissões obrigatórias** | Requer execução como Administrador no Windows e Npcap instalado. Em ambientes com GPO restritiva, pode ser necessária autorização do TI. |
| **HTTPS — conteúdo cifrado** | O NetLab detecta conexões HTTPS e extrai o hostname via SNI, mas **não decifra o conteúdo**. Isso é comportamento esperado — o TLS garante confidencialidade. |
| **Isolamento de clientes Wi-Fi** | Redes com *client isolation* (comum em Wi-Fi escolar/corporativo) impedem descoberta ARP entre dispositivos. Apenas tráfego do próprio computador monitorado será visível. |
| **Switches gerenciados** | Em redes com switches gerenciados sem port mirroring, somente o tráfego da porta do computador é capturado. |
| **Alto volume de pacotes** | Em redes muito movimentadas, o rate limit de 800 pkt/s e o backpressure de 8 eventos/ciclo descartam excedentes por design (proteção contra OOM e freeze da UI). |
| **Plataforma primária** | Projetado e testado para Windows 10/11 (64 bits). Compatibilidade com Linux foi explorada mas não é o foco principal. |

---

## Licença

Este software é distribuído para **uso acadêmico e educacional**.

Desenvolvido como TCC no Instituto Federal Farroupilha — Campus Uruguaiana.  
Contribuições e sugestões de professores e alunos são bem-vindas.

---

<div align="center">

**NetLab Educacional V4.0** · Abril de 2026

*Desenvolvido por Yuri Gonçalves Pavão*  
*Este projeto contou com o apoio de LLMs (Large Language Models) para auxílio no desenvolvimento, revisão de código e otimização de funcionalidades, sempre sob supervisão e validação do autor.*

*Instituto Federal Farroupilha — Campus Uruguaiana*

</div>
