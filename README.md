# NetLab Educacional

<div align="center">

Monitor de redes desktop com foco didático, visualização de topologia e análise pedagógica de tráfego em tempo real.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-Desktop-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Captura%20de%20Pacotes-FF6B35?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)

</div>

## Sobre o projeto

O **NetLab Educacional** é uma aplicação desktop desenvolvida para apoiar o ensino de redes de computadores com tráfego real, visualizações gráficas e explicações automáticas voltadas para contexto didático.

Hoje o projeto combina quatro frentes principais:

- captura de pacotes em tempo real com Scapy/Npcap;
- visualização da topologia da rede local;
- painel de tráfego com histórico e estatísticas;
- modo de análise com explicações pedagógicas e insights de uso da rede.

O sistema também inclui uma aba com **servidor HTTP propositalmente vulnerável** para demonstrações controladas de SQL Injection, XSS, IDOR, exposição de dados e outros cenários de segurança em laboratório.

> [!WARNING]
> O projeto é focado em **Windows** e depende de **Npcap** para captura de pacotes. Para capturar tráfego corretamente, o NetLab deve ser executado com privilégios de administrador.

## O que o NetLab faz hoje

### Captura e classificação de pacotes

- Captura tráfego de rede em tempo real usando `AsyncSniffer` do Scapy.
- Classifica eventos como `DNS`, `DHCP`, `HTTP`, `HTTPS`, `TCP_SYN`, `ICMP` e `ARP`.
- Aplica rate limit na captura para evitar sobrecarga da interface.
- Detecta automaticamente interface ativa, IP local e CIDR da rede quando possível.
- Usa parser HTTP em C via `ctypes` quando disponível, com fallback automático para Python.

### Modo Análise

- Exibe eventos ao vivo com filtros por protocolo e busca textual.
- Organiza a leitura pedagógica em três abas:
  - **Análise**
  - **Risco e Dados**
  - **Evidências**
- Estrutura o conteúdo do evento em seções como análise, leitura técnica, superfície de risco, evidência observada, interpretação operacional e ação sugerida.
- Mantém contadores por tipo de evento na sessão.
- Gera insights com:
  - domínios mais acessados;
  - classificação de uso da rede;
  - resumo de volume e alertas da sessão.

### Topologia da rede

- Desenha a rede local em um mapa interativo com zoom, pan, hover e seleção de nós.
- Agrupa IPs externos em um nó único chamado **Internet**.
- Destaca conexões entre dispositivos observados durante a captura.
- Marca dispositivos como **CONFIRMADO** ou **OBSERVADO** conforme a origem da descoberta.
- Permite definir apelidos manualmente com duplo clique no dispositivo.
- Exibe fabricante por OUI, hostname, tipo inferido, portas e volume aproximado.
- Suporta exibição opcional de sub-redes descobertas e inferidas pela tabela de rotas.

### Descoberta e enriquecimento de dispositivos

- Executa varredura ARP inicial e descoberta periódica.
- Complementa descoberta com ICMP em hosts elegíveis.
- Importa entradas da tabela ARP do sistema para enriquecer a topologia.
- Atualiza a base de fabricantes pela base `manuf` do Wireshark em segundo plano.
- Persiste apelidos de dispositivos localmente em arquivo JSON.

### Painel de tráfego

- Mantém histórico de até **2 horas** de amostras.
- Mostra gráfico de KB/s com:
  - curva bruta;
  - curva suavizada por EMA;
  - crosshair com tooltip;
  - navegação temporal e retorno ao modo ao vivo.
- Exibe cards com total de pacotes, volume trafegado e dispositivos ativos.
- Lista protocolos detectados com contagem e volume de dados.
- Mostra top dispositivos por tráfego enviado, recebido e total.

### Servidor HTTP didático

Na aba **Servidor**, o projeto inicia um servidor HTTP local multi-thread para demonstrações de segurança em sala de aula.

Recursos ativos do painel:

- escolha de porta diretamente pela interface;
- exibição do endereço local para acesso por outros dispositivos da rede;
- contadores de requisições, dados trafegados, clientes e carga por segundo;
- tabela com requisições recentes;
- log de alertas didáticos em tempo real.

Rotas e cenários de demonstração presentes no servidor:

- login vulnerável a SQL Injection;
- catálogo de produtos;
- busca vulnerável a XSS refletido;
- comentários vulneráveis a XSS armazenado;
- pedidos vulneráveis a IDOR;
- listagem de usuários com exposição de credenciais;
- perfil vulnerável a XSS refletido;
- endpoints JSON com divulgação de dados.

O banco usado pelo servidor é um **SQLite em memória**, recriado a cada inicialização e descartado ao parar o laboratório.

> [!CAUTION]
> O servidor embutido é intencionalmente inseguro. Use apenas em ambiente controlado de laboratório e nunca exponha esse recurso para internet pública.

## Arquitetura resumida

O fluxo principal do monitoramento é dividido em camadas para manter a UI responsiva:

1. uma thread de captura recebe pacotes da interface de rede;
2. um analisador dedicado classifica os pacotes e atualiza estatísticas;
3. a interface Qt consome os resultados por timers e atualiza os painéis.

O projeto também possui módulos nativos opcionais para acelerar partes específicas, mas a aplicação continua funcionando com fallback em Python quando a compilação não estiver disponível.

## Tecnologias usadas

- `Python`
- `PyQt6`
- `Scapy`
- `PyQtGraph`
- `manuf`
- `Npcap` no Windows
- `SQLite` em memória no servidor didático

## Requisitos

Antes de executar o projeto, garanta:

- Windows 10 ou Windows 11;
- Python 3.11 ou superior;
- `Npcap` instalado;
- permissão de administrador para a captura;
- dependências Python instaladas via `requirements.txt`.

Compilador C é opcional. Ele só é necessário se você quiser recompilar os módulos nativos manualmente.

## Instalação

### 1. Criar ambiente virtual

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Instalar dependências

```powershell
pip install -r requirements.txt
```

### 3. Compilar módulos nativos (opcional)

```powershell
python utils\compilar_c.py
```

Se a compilação não acontecer, o NetLab continua funcionando com fallback em Python.

### 4. Executar a aplicação

```powershell
python main.py
```

## Como usar

### Monitoramento de rede

1. Execute o programa como administrador.
2. Selecione uma interface de rede válida na barra superior.
3. Clique em **Iniciar Captura**.
4. Acompanhe a rede pelas abas:
   - **Topologia da Rede**
   - **Tráfego em Tempo Real**
   - **Modo Análise**
5. Use o botão **Diagnóstico** se precisar validar interface, CIDR ou estado da captura.

### Laboratório HTTP

1. Abra a aba **Servidor**.
2. Ajuste a porta se necessário.
3. Clique em **Iniciar Servidor**.
4. Acesse o endereço mostrado no painel em um navegador da mesma rede.
5. Observe requisições e alertas na própria interface do NetLab.

## Ferramentas auxiliares

- `diagnostico.py`: testa interfaces de rede e ajuda a descobrir qual adaptador realmente está capturando tráfego.
- `compilar_http_parser.py` e `setup_netlab.py`: wrappers de compatibilidade para compilação manual.
- `utils/compilar_c.py`: forma recomendada para recompilar os módulos C opcionais.

## Estrutura do projeto

```text
NetLab-V4.0/
├── main.py
├── analisador_pacotes.py
├── motor_pedagogico.py
├── painel_servidor.py
├── diagnostico.py
├── interface/
│   ├── janela_principal.py
│   ├── painel_eventos.py
│   ├── painel_topologia.py
│   └── painel_trafego.py
├── utils/
│   ├── compilar_c.py
│   ├── constantes.py
│   ├── gerenciador_subredes.py
│   ├── identificador.py
│   └── rede.py
├── recursos/
│   └── estilos/
├── dados/
├── http_parser.c
└── requirements.txt
```

## Limitações e observações

- A captura foi pensada para o ambiente Windows com Npcap.
- Em redes Wi-Fi, o modo promíscuo pode não revelar todo o tráfego da rede.
- O projeto consegue inspecionar o conteúdo de **HTTP em texto puro**, mas em **HTTPS** a visibilidade fica restrita a metadados observáveis.
- Alguns arquivos do repositório são artefatos de apoio ou compatibilidade e não representam necessariamente fluxos ativos da interface principal.
- O projeto não possui suíte automatizada de testes publicada neste repositório.

## Contexto acadêmico

Este projeto foi desenvolvido como parte de um trabalho acadêmico com foco em ensino de redes de computadores e demonstrações práticas de protocolos, tráfego e segurança.

Se a sua intenção é usar o NetLab em aula, o valor do projeto hoje está menos em "substituir ferramentas profissionais" e mais em **traduzir o que está acontecendo na rede para uma leitura visual e pedagógica**.

## Licença

No estado atual do repositório, **não há um arquivo `LICENSE` publicado**. Até que uma licença explícita seja adicionada, trate o projeto como material acadêmico/educacional.
