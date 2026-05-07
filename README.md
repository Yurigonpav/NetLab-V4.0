<div align="center">

<h1>
  <br>
  NetLab Educacional
  <br>
</h1>

<h4>Plataforma educacional de análise de tráfego de rede com explicações didáticas automatizadas</h4>

<br>

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.x-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![Scapy](https://img.shields.io/badge/Scapy-2.x-FF6B35?style=for-the-badge)](https://scapy.net)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com/windows)
[![License](https://img.shields.io/badge/Licença-MIT-green?style=for-the-badge)](LICENSE)
[![TCC](https://img.shields.io/badge/TCC-IFFar%20Uruguaiana-orange?style=for-the-badge)](https://iffarroupilha.edu.br)

<br>

> Trabalho de Conclusão de Curso — Curso Técnico em Informática  
> Instituto Federal Farroupilha (IFFar) · Campus Uruguaiana

<br>

</div>

---

## Sobre o Projeto

O **NetLab Educacional** é uma aplicação desktop de análise de rede voltada ao ensino de redes de computadores e segurança da informação. Inspirado no Wireshark, porém com foco pedagógico, o NetLab captura pacotes em tempo real, interpreta os protocolos detectados e gera explicações acessíveis sobre o que acontece na rede — linha a linha, evento a evento.

Desenvolvido como TCC do Curso Técnico em Informática no **Instituto Federal Farroupilha (IFFar) Campus Uruguaiana**, o projeto combina captura real de tráfego com um motor de análise que traduz dados técnicos em linguagem compreensível, tornando conceitos de redes tangíveis para estudantes em sala de aula.

---

## Funcionalidades

### Topologia da Rede
- Mapa interativo de dispositivos locais e conexões com a Internet
- Zoom via scroll, pan via arrastar, clique para detalhes completos do dispositivo
- Duplo-clique para definir apelido personalizado a qualquer host
- Identificação automática de fabricante pelo OUI do endereço MAC (base Wireshark, atualização em segundo plano)
- Classificação de dispositivos: gateway, computador, celular, impressora, equipamento de rede
- Tamanho dos nós dinâmico proporcional ao volume de tráfego
- Detecção e visualização de sub-redes com múltiplos níveis de confiança (total, parcial, inferida)
- Descoberta ativa por ARP sweep e ICMP paralelo (L2), com suporte a múltiplas rodadas

### Tráfego em Tempo Real
- Gráfico de banda com **duas curvas sobrepostas**: sinal bruto e EMA suavizado
- Histórico de até 2 horas de amostras (buffer circular `deque(maxlen=7200)`)
- Navegação temporal: retroceder e avançar no histórico sem perder dados ao vivo
- Suavização ajustável via slider (α de 0,05 a 0,50) com recompilação instantânea do histórico
- Crosshair interativo com tooltip do valor exato no ponto apontado
- Tabelas em tempo real: top protocolos por pacotes/bytes e top dispositivos por tráfego
- Cards de resumo: total de pacotes, dados transmitidos, dispositivos ativos

### Modo Análise (Pedagogia)
- Cada pacote capturado gera um **evento explicado** em três abas:
  - **Análise** — o que aconteceu, em linguagem acessível, com contexto de segurança
  - **Evidências** — campos técnicos reais: IPs, MACs, portas, headers HTTP, campos de formulário
  - **Na Prática** — significado operacional, comandos de diagnóstico e vetores de ataque
- Três níveis de alerta: `INFO`, `AVISO`, `CRÍTICO`
- Detecção de **campos sensíveis em texto puro** (senhas, tokens, CPF, cookies) em requisições HTTP
- Detecção de padrões de **SQL Injection** e **XSS** no tráfego capturado
- Deep Packet Inspection (DPI) em requisições HTTP: parse completo de método, headers, formulários
- Filtros por protocolo (badges clicáveis) e busca por IP, domínio ou protocolo
- Navegação histórica de até 1.500 eventos por sessão

### Servidor de Laboratório
- Servidor HTTP educacional com **vulnerabilidades reais e intencionais** para demonstração em sala
- Banco SQLite totalmente em memória — descartado ao encerrar, sem persistência em disco
- Vulnerabilidades implementadas:
  - SQL Injection por concatenação direta em `/login` e `/produtos`
  - XSS refletido em `/busca` e `/perfil`
  - XSS armazenado em `/comentarios`
  - IDOR em `/pedidos` (sem verificação de autorização)
  - Tokens de sessão sequenciais e previsíveis
  - Exposição de senhas em texto puro em `/usuarios` e `/api/usuarios`
  - CSRF em todos os formulários (sem proteção)
  - Força bruta sem limite de tentativas no login
- Painel Qt com tabela de requisições em tempo real, alertas por tipo de ataque e métricas de carga
- Acessível de qualquer dispositivo na mesma rede Wi-Fi durante a aula

### Diagnóstico do Sistema
- Verificação de privilégios de administrador
- Detecção de versão do Npcap e do Scapy
- Teste de ping ao gateway com latência real e percentual de perda
- Resolução DNS com tempo de resposta
- Sinal Wi-Fi (RSSI em %) via `netsh`
- Estatísticas da interface (drops e erros) via `psutil`
- Pontuação de saúde do sistema com barra de progresso colorida
- Exportação do relatório completo para `.txt`

---

## Arquitetura

```
NetLab Educacional
│
├── main.py                         # Ponto de entrada, tema visual
│
├── analisador_pacotes.py           # Pipeline de DPI com thread dedicada e filas limitadas
├── motor_pedagogico.py             # Gerador de explicações didáticas por protocolo
├── netlab_core.py                  # Buffer circular de métricas (Python puro, thread-safe)
│
├── interface/
│   ├── janela_principal.py         # Orquestração: captura, UI, descoberta, timers
│   ├── painel_topologia.py         # Mapa interativo de rede (QPainter, animação)
│   ├── painel_trafego.py           # Gráfico EMA + tabelas (PyQtGraph)
│   └── painel_eventos.py           # Modo Análise: lista + detalhe pedagógico
│
├── painel_servidor.py              # Servidor HTTP vulnerável + painel Qt
│
├── utils/
│   ├── gerenciador_subredes.py     # Descoberta e classificação de sub-redes
│   ├── identificador.py            # OUI/fabricante via manuf (Wireshark), apelidos JSON
│   ├── rede.py                     # Utilitários: IP local, CIDR, validação, formatação
│   └── constantes.py               # Cores, protocolos, portas conhecidas
│
├── recursos/
│   └── estilos/
│       └── tema_escuro.qss         # Folha de estilo Qt (tema escuro naval)
│
└── diagnostico.py                  # Script autônomo de diagnóstico de interfaces
```

### Fluxo de dados

```
Npcap (driver)
    │
    ▼
_CapturadorPacotesThread     ← AsyncSniffer (Scapy), thread daemon
    │  fila_pacotes_global
    ▼
AnalisadorPacotes            ← ThreadAnalisador, lotes de 200 pacotes
    │  fila_saida (deque)
    ▼
JanelaPrincipal._consumir_fila()   ← QTimer 400ms
    ├─► PainelTopologia             (registro de hosts e conexões)
    ├─► fila_eventos_ui             (cooldown por protocolo)
    └─► _snapshot_atual             (métricas agregadas)

fila_eventos_ui
    │  QTimer 2s
    ▼
_WorkerRunnable (QThreadPool)
    │  MotorPedagogico.gerar_explicacao()
    ▼
PainelEventos.adicionar_evento()
```

---

## Pré-requisitos

| Requisito | Versão mínima | Observação |
|-----------|--------------|------------|
| Windows | 10 ou 11 | Único SO suportado na versão atual |
| Python | 3.11+ | Recomendado 3.12 |
| [Npcap](https://npcap.com) | 1.70+ | Instalar com **"WinPcap API-compatible mode"** marcado |
| Privilégios | Administrador | Necessário para captura de pacotes |

---

## Instalação

### Opção 1 — Instalação manual

```powershell
# Clone o repositório
git clone https://github.com/Yurigonpav/netlab-educacional.git
cd netlab-educacional

# Crie e ative o ambiente virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Instale as dependências
pip install -r requirements.txt
```

### Opção 2 — Instalador automático

Execute o `INSTALAR.bat` com clique duplo. O script:
1. Solicita elevação para Administrador automaticamente
2. Verifica e instala o Python se necessário
3. Cria o ambiente virtual e instala todas as dependências
4. Cria um atalho na área de trabalho

### Executar

```powershell
# Sempre como Administrador
python main.py
```

Ou pelo atalho criado pelo instalador.

---

## Dependências

```text
PyQt6          # Interface gráfica
scapy          # Captura e análise de pacotes
pyqtgraph      # Gráficos de tráfego em tempo real
cryptography   # Certificados SSL para o servidor de laboratório
manuf          # Identificação de fabricantes via OUI (base Wireshark)
```

Instale com:

```bash
pip install -r requirements.txt
```

---

## Diagnóstico de Interfaces

Se nenhum pacote for capturado, execute o script de diagnóstico **como Administrador**:

```powershell
python diagnostico.py
```

O script testa cada interface disponível por 4 segundos e exibe quais capturam tráfego real. Copie o nome exato da interface ativa (incluindo `\Device\NPF_...`) e selecione-a no combo da janela principal.

**Problemas comuns:**

| Sintoma | Causa provável | Solução |
|---------|---------------|---------|
| Nenhuma interface captura | Npcap não instalado corretamente | Reinstalar com "WinPcap API-compatible mode" |
| Erro de permissão | Sem privilégios de Administrador | Executar como Administrador |
| `ImportError: scapy` | Dependência ausente | `pip install scapy` no venv |
| Gráfico sem dados | Interface errada selecionada | Usar `diagnostico.py` para identificar a correta |

---

## Servidor de Laboratório

O servidor HTTP vulnerável serve como ambiente controlado para demonstração de ataques web em sala de aula.

**Para usar:**
1. Acesse a aba **Servidor** no NetLab
2. Ajuste a porta (padrão 8080) e clique em **Iniciar Servidor**
3. Acesse `http://<IP-local>:<porta>/` de qualquer dispositivo na mesma rede

**Rotas disponíveis:**

| Rota | Descrição | Vulnerabilidade |
|------|-----------|----------------|
| `/` | Página inicial | — |
| `/login` | Formulário de autenticação | SQL Injection, Força bruta |
| `/register` | Cadastro de usuário | SQL Injection |
| `/produtos` | Catálogo com busca por ID | SQL Injection (parâmetro `?id=`) |
| `/busca` | Busca de produtos | XSS Refletido |
| `/perfil` | Exibição de perfil | XSS Refletido |
| `/comentarios` | Mural de comentários | XSS Armazenado, CSRF |
| `/pedidos` | Detalhes de pedido | IDOR (parâmetro `?id=`) |
| `/usuarios` | Lista de usuários | Divulgação sem autenticação |
| `/api/usuarios` | API JSON de usuários | Divulgação de senhas em texto puro |

> **Aviso:** este servidor implementa vulnerabilidades **reais** intencionalmente para fins didáticos. Não exponha na Internet. Todos os dados são descartados ao parar o servidor — nada é persistido em disco.

**Usuários pré-cadastrados:**

| Usuário | Senha | Papel |
|---------|-------|-------|
| admin | 123456 | admin |
| alice | alice123 | user |
| bob | bob456 | user |
| carlos | senha123 | user |

---

## Capturas de Tela

> *As capturas abaixo mostram o NetLab em operação em uma rede local doméstica.*

| Aba | Descrição |
|-----|-----------|
| **Topologia** | Mapa de dispositivos com nós, conexões e sub-redes detectadas |
| **Tráfego** | Gráfico EMA em tempo real com curva bruta sobreposta |
| **Modo Análise** | Evento HTTP com campos sensíveis destacados em vermelho |
| **Servidor** | Tabela de requisições e log de alertas de vulnerabilidades |

---

## Protocolos Suportados

| Protocolo | Análise pedagógica | Detecção de risco |
|-----------|-------------------|------------------|
| HTTP | ✅ Completa (DPI, headers, formulários) | ✅ Campos sensíveis, SQLi, XSS, cookies |
| HTTPS | ✅ TLS/SNI extraído | ℹ️ Conteúdo cifrado (esperado) |
| DNS | ✅ Domínio resolvido | ⚠️ Consultas em texto puro |
| ARP | ✅ Request/Reply com MAC | ⚠️ Sem autenticação (risco de spoofing) |
| TCP SYN | ✅ Handshake, TTL, OS estimado | ⚠️ SYN flood |
| ICMP | ✅ Echo, TTL, traceroute | ℹ️ |
| DHCP | ✅ Ciclo DORA completo | ⚠️ Rogue DHCP |
| SSH | ✅ Handshake cifrado | ℹ️ Seguro |
| FTP | ✅ Canal de controle | 🔴 Credenciais em texto puro |
| SMB | ✅ Negociação de protocolo | ⚠️ SMBv1, relay |
| RDP | ✅ Handshake TLS | ⚠️ Exposição na internet |

---

## Estrutura de Arquivos

```
netlab-educacional/
├── main.py
├── analisador_pacotes.py
├── motor_pedagogico.py
├── netlab_core.py
├── painel_servidor.py
├── diagnostico.py
├── requirements.txt
├── .gitignore
├── interface/
│   ├── __init__.py
│   ├── janela_principal.py
│   ├── painel_topologia.py
│   ├── painel_trafego.py
│   └── painel_eventos.py
├── utils/
│   ├── __init__.py
│   ├── gerenciador_subredes.py
│   ├── identificador.py
│   ├── rede.py
│   └── constantes.py
└── recursos/
    └── estilos/
        └── tema_escuro.qss
```

---

## Decisões Técnicas

**Por que Python puro no núcleo de métricas?**  
O `netlab_core.py` implementa um buffer circular de tamanho fixo em Python sem dependências nativas, garantindo portabilidade e evitando erros de compilação em ambientes escolares com instalações diversas.

**Por que thread dedicada no analisador?**  
O `ThreadAnalisador` desacopla o parsing de pacotes do loop Qt, processando lotes de 200 eventos por iteração e dormindo 5ms quando a fila está vazia — evitando starvation na UI mesmo com tráfego intenso.

**Por que deque com maxlen em todos os buffers?**  
Filas ilimitadas causam crescimento descontrolado de memória durante sessões longas. Todos os buffers críticos têm capacidade máxima definida (`deque(maxlen=N)`) com descarte automático do mais antigo.

**Por que SQLite em memória no servidor de laboratório?**  
Zero risco de persistência acidental de dados sensíveis de alunos. O banco existe apenas enquanto o servidor está ativo e é descartado completamente ao parar — sem arquivos, sem rastros.

---

## Limitações Conhecidas

- **Modo promíscuo no Wi-Fi (Windows):** drivers Wi-Fi no Windows bloqueiam captura de frames de terceiros em modo promíscuo. Para demonstração em sala com múltiplos alunos, use o **Hotspot do Windows** e conecte os dispositivos nele — o adaptador capta todo o tráfego do hotspot.
- **Requer Npcap:** o stack de captura depende do Npcap; o WinPcap nativo não é suportado nas versões recentes do Windows.
- **Somente IPv4:** o analisador cobre exclusivamente tráfego IPv4; IPv6 é ignorado na versão atual.
- **Windows apenas (primário):** o código tem compatibilidade parcial com Linux (rotas, interfaces), mas a UI e o instalador foram projetados para Windows 10/11.

---

## Licença

Distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## Autor

**Yuri Gonçalves Pavão**

Curso Técnico em Informática — Instituto Federal Farroupilha (IFFar) · Campus Uruguaiana

- GitHub: [@Yurigonpav](https://github.com/Yurigonpav)
- Instagram: [@yuri_g0n](https://instagram.com/yuri_g0n)

---

<div align="center">

Desenvolvido com propósito educacional. Use com responsabilidade.

</div>