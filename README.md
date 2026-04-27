# NetLab Educacional

<div align="center">

Aplicação desktop para captura e análise de tráfego de rede com foco didático, desenvolvida como trabalho de conclusão de curso (TCC) no Curso Técnico em Informática.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-Desktop-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Captura-FF6B35?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)

</div>

---

## O que é o NetLab Educacional

O NetLab Educacional é uma aplicação desktop para Windows que captura pacotes de rede em tempo real e os apresenta de forma visual e explicada, com linguagem acessível a estudantes de redes de computadores e segurança da informação.

O projeto combina quatro frentes principais:

- **Captura e classificação de pacotes** com Scapy e Npcap
- **Visualização da topologia** da rede local em mapa interativo
- **Painel de tráfego** com histórico, gráfico EMA e estatísticas por protocolo
- **Modo Análise** com explicações pedagógicas estruturadas por evento
- **Servidor HTTP didático** com vulnerabilidades reais para demonstrações em laboratório

> [!WARNING]
> O NetLab requer **Npcap** instalado e deve ser executado com **privilégios de administrador** para capturar pacotes.

---

## Funcionalidades verificadas no código

### Captura de pacotes — `interface/janela_principal.py`, `analisador_pacotes.py`

- Captura em tempo real via `AsyncSniffer` do Scapy em modo promíscuo
- Classificação automática de pacotes: `DNS`, `DHCP`, `HTTP`, `HTTPS`, `TCP_SYN`, `TCP_FIN`, `TCP_RST`, `ICMP`, `ARP`
- Rate limit de 800 pacotes por segundo para proteger a UI de sobrecarga
- Parser HTTP em C via `ctypes` (`http_parser.dll`/`.so`) com fallback automático para Python puro
- Fila de entrada com `deque(maxlen=20_000)` e thread dedicada de análise (`ThreadAnalisador`)
- Detecção automática de interface ativa, IP local e CIDR da rede

### Motor pedagógico — `motor_pedagogico.py`

- Geração de explicações em linguagem acessível para cada tipo de evento capturado
- Cobertura de protocolos: DNS, HTTP, HTTPS, TCP (SYN/FIN/RST), ICMP, ARP, DHCP, SSH, FTP, SMB, RDP
- Deep Packet Inspection (DPI) em pacotes HTTP: extração de headers, corpo, campos de formulário e credenciais expostas
- Detecção de campos sensíveis (senha, token, CPF, email, etc.) via regex com word-boundary
- Identificação de fabricante por OUI nos primeiros 3 bytes do MAC
- Estimativa de sistema operacional pelo valor TTL
- Dump hexadecimal do pacote bruto (primeiros 2048 bytes)
- Alertas de segurança internos com registro dos últimos 200 eventos HTTP suspeitos

### Modo Análise — `interface/painel_eventos.py`

- Lista ao vivo de eventos com filtros por protocolo e busca textual
- Estrutura pedagógica de **6 seções** por evento:
  1. Análise — o que aconteceu e por quê
  2. Leitura Técnica — como o protocolo funciona
  3. Superfície de Risco — vulnerabilidades quando aplicável
  4. Evidência Observada — campos reais do pacote
  5. Interpretação Operacional — o que significa na prática
  6. Ação Sugerida — o que fazer e por quê
- Cap de 120 widgets visíveis no `QListWidget` para evitar freeze de interface
- Buffer de até 300 eventos com `deque(maxlen=300)`
- Aba **Insights** com domínios mais acessados e classificação de uso da rede
- Contadores por tipo de evento na sessão atual

### Topologia da rede — `interface/painel_topologia.py`

- Mapa interativo com zoom (scroll), pan (arrastar) e seleção de nós
- IPs externos agrupados automaticamente em nó "Internet"
- Tamanho dos nós proporcional ao volume de pacotes observados
- Destaque de conexões ao selecionar um dispositivo
- Distinção entre dispositivos **CONFIRMADO** (ARP) e **OBSERVADO** (sniffer)
- Painel de detalhes com IP, MAC, fabricante, portas, tipo e apelido personalizado
- Apelido por duplo clique, persistido em `dados/aliases.json`
- Limite de 50 nós locais simultâneos com remoção automática dos mais antigos e menos confiáveis
- Exibição opcional de sub-redes descobertas e inferidas via tabela de rotas

### Painel de Tráfego — `interface/painel_trafego.py`

- Gráfico de KB/s com duas curvas sobrepostas:
  - Curva bruta (voltilidade real)
  - Curva EMA com fator α ajustável (suavização exponencial)
- Histórico de até 7.200 amostras (≈ 2 horas a 1 amostra/s)
- Navegação temporal: recuar, avançar, pausar e retornar ao vivo
- Crosshair com tooltip de valor exato
- Cards com total de pacotes, volume trafegado e dispositivos ativos
- Tabelas de protocolos detectados e top dispositivos por tráfego

### Descoberta de dispositivos — `interface/janela_principal.py`

- Varredura ARP ativa via `srp` do Scapy (lotes configuráveis)
- Varredura ICMP complementar com resolução de MAC prévia
- Importação da tabela ARP do sistema operacional (`arp -a` / `ip neigh`)
- Atualização periódica automática (intervalo ajustado conforme tipo de interface)
- Parâmetros automáticos mais conservadores para interfaces Wi-Fi
- Detecção de sub-redes via tabela de rotas do sistema (`route print -4` / `ip route`)

### Identificação de fabricantes — `utils/identificador.py`

- Singleton `GerenciadorDispositivos` com lookup via biblioteca `manuf` (base OUI do Wireshark)
- Cache RAM de até 10.000 entradas para lookups repetidos em O(1)
- Atualização automática da base OUI em thread daemon se desatualizada (> 30 dias)
- Atualização manual via menu "Atualizar Base de Fabricantes"
- Apelidos persistidos em `dados/aliases.json` com escrita atômica

### Servidor HTTP didático — `painel_servidor.py`

- Servidor HTTP multi-thread em memória iniciado pela interface gráfica
- Banco SQLite **totalmente em memória** (`:memory:`), recriado a cada sessão e descartado ao parar
- Porta configurável pela interface (padrão 8080)
- Vulnerabilidades intencionais para demonstração em laboratório:
  - SQL Injection por concatenação direta em `/login` e `/produtos`
  - XSS refletido em `/busca` e `/perfil`
  - XSS armazenado em `/comentarios`
  - IDOR em `/pedidos` (sem verificação de autorização)
  - Exposição de credenciais em `/usuarios` e `/api/usuarios` (sem autenticação)
  - Tokens de sessão sequenciais e previsíveis
- Tabela de requisições em tempo real com payload resumido
- Log de alertas didáticos categorizados (INFO / AVISO / CRÍTICO)
- Contadores de requisições por segundo, total de dados e clientes únicos

### Módulos nativos opcionais em C — `http_parser.c`, `netlab_core_lib.c`

- `http_parser.dll/.so`: parser HTTP de alta performance via `ctypes`; fallback automático para Python se ausente
- `netlab_core_lib.dll/.so`: buffer circular e métricas de taxa (bytes/s) com janela deslizante; implementação Python equivalente sempre disponível

---

## Estrutura do projeto

```text
NetLab/
├── main.py                        # Ponto de entrada — inicializa Qt e abre a janela
├── analisador_pacotes.py          # Classificação de pacotes e estatísticas
├── motor_pedagogico.py            # Geração de explicações didáticas por evento
├── painel_servidor.py             # Servidor HTTP didático com vulnerabilidades
├── netlab_core.py                 # Wrapper ctypes para netlab_core_lib
├── diagnostico.py                 # Script standalone para testar interfaces
├── http_parser.c                  # Parser HTTP em C (compilado como .dll/.so)
├── netlab_core_lib.c              # Buffer circular e métricas em C
├── compilar_http_parser.py        # Wrapper de compilação do http_parser
├── setup_netlab.py                # Wrapper de compilação do netlab_core_lib
├── requirements.txt
│
├── interface/
│   ├── janela_principal.py        # Janela Qt, timers, sniffer e descoberta de rede
│   ├── painel_eventos.py          # Modo Análise com estrutura pedagógica de 6 seções
│   ├── painel_topologia.py        # Mapa interativo da rede local
│   └── painel_trafego.py          # Gráfico EMA, histórico e tabelas de tráfego
│
├── utils/
│   ├── compilar_c.py              # Compilação unificada dos módulos C
│   ├── constantes.py              # Cores, classificações e portas conhecidas
│   ├── gerenciador_subredes.py    # Descoberta e classificação de sub-redes
│   ├── identificador.py           # Identificação de fabricantes por OUI (manuf)
│   └── rede.py                    # Utilitários: IP local, classificação RFC 1918
│
├── recursos/
│   └── estilos/
│       └── tema_escuro.qss        # Folha de estilos Qt (tema escuro)
│
└── dados/
    └── aliases.json               # Apelidos de dispositivos (criado em tempo de execução)
```

---

## Pré-requisitos

| Requisito | Versão | Observação |
|---|---|---|
| Windows | 10 ou 11 | Único SO suportado atualmente |
| Python | 3.11+ | Testado com 3.11 e 3.12 |
| Npcap | Mais recente | Necessário para captura de pacotes |
| Privilégio | Administrador | Obrigatório para sniffing |
| GCC (opcional) | Qualquer | Só para compilar os módulos C |

---

## Instalação

### 1. Instalar o Npcap

Baixe em [https://npcap.com](https://npcap.com) e marque a opção **"WinPcap API-compatible mode"** durante a instalação.

### 2. Criar ambiente virtual e instalar dependências

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Conteúdo do `requirements.txt`:**

```
PyQt6
scapy
pyqtgraph
cryptography
manuf
```

### 3. Compilar os módulos nativos em C (opcional)

A compilação melhora a performance do parser HTTP, mas não é obrigatória. O sistema usa fallback em Python puro se as bibliotecas não estiverem disponíveis.

```powershell
python utils\compilar_c.py
```

Requer `gcc` (MinGW/MSYS2) ou `cl` (MSVC) no PATH.

### 4. Executar a aplicação

```powershell
# Execute sempre como administrador
python main.py
```

---

## Como usar

### Monitoramento de rede

1. Execute o NetLab **como administrador**
2. Selecione a interface de rede no menu suspenso da barra superior
3. Clique em **Iniciar Captura**
4. Abra um navegador e acesse sites para gerar tráfego real
5. Navegue pelas abas:
   - **Topologia da Rede** — mapa visual dos dispositivos detectados
   - **Tráfego em Tempo Real** — gráfico e estatísticas por protocolo
   - **Modo Análise** — eventos com explicações pedagógicas
6. Clique em qualquer evento na lista lateral para ver a análise completa nas três abas de conteúdo

### Diagnóstico de interface

Se a captura não estiver funcionando:

```powershell
# Execute como administrador
python diagnostico.py
```

O script testa cada interface disponível por 4 segundos e indica quais capturam tráfego real.

### Laboratório HTTP

1. Abra a aba **Servidor**
2. Ajuste a porta se necessário (padrão: 8080)
3. Clique em **Iniciar Servidor**
4. Acesse `http://<IP-local>:8080/` de qualquer dispositivo na mesma rede
5. Observe as requisições e alertas em tempo real no painel

> [!CAUTION]
> O servidor é intencionalmente inseguro. Use **apenas em ambientes controlados de laboratório**. Nunca exponha este servidor à internet ou a redes públicas.

---

## Limitações conhecidas

- **Sistema operacional:** o projeto foi desenvolvido e testado exclusivamente no Windows. Existe código de compatibilidade com Linux, mas não foi validado em produção.
- **Captura em Wi-Fi:** no Windows, o modo promíscuo em adaptadores sem fio frequentemente não captura tráfego de outros dispositivos da rede — apenas o tráfego do próprio computador e broadcasts.
- **HTTPS:** a inspeção é limitada aos metadados visíveis (endereços IP, porta e SNI). O conteúdo cifrado pelo TLS não é acessível.
- **Detecção de fabricante:** depende da biblioteca `manuf` e de acesso à internet para atualizar a base OUI. Em uso offline com base desatualizada, muitos MACs retornam "Desconhecido".
- **Escopo do sniffer:** captura apenas tráfego IP e ARP que passa pela interface selecionada. Tráfego entre outros dispositivos da rede pode não ser visível dependendo da topologia (switch vs. hub, presença de VLAN, etc.).
- **Sem testes automatizados:** o repositório não possui suíte de testes publicada.

---

## Contexto acadêmico

Este projeto foi desenvolvido como Trabalho de Conclusão de Curso (TCC) do **Curso Técnico em Informática**.

O objetivo principal é **traduzir o que acontece na rede para uma leitura visual e pedagógica**, tornando conceitos de protocolos, tráfego e segurança acessíveis a estudantes sem experiência prévia em análise de rede.

O NetLab não se propõe a substituir ferramentas profissionais como Wireshark ou Zeek. Seu valor está na **camada educacional** que envolve cada evento capturado: explicação, contexto de risco e ação sugerida, gerados automaticamente a partir do tráfego real do aluno.

---

**Autor:** Yuri Gonçalves Pavão  
**Instagram:** [@yuri_g0n](https://instagram.com/yuri_g0n)  
**GitHub:** [github.com/Yurigonpav](https://github.com/Yurigonpav)
