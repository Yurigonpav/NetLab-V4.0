# NetLab Educacional v4.0

<div align="center">

Aplicação desktop para captura e análise de tráfego de rede com foco didático.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyQt6](https://img.shields.io/badge/PyQt6-Desktop-41CD52?style=for-the-badge&logo=qt&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Captura-FF6B35?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)

</div>

---

## O que é o NetLab Educacional

O NetLab Educacional é uma ferramenta pedagógica para estudantes de redes e segurança. Ele traduz o tráfego real de rede em explicações visuais e textuais acessíveis.

### Funcionalidades v4.0 (Refatoradas)

- **Captura e Classificação**: Motor em Python puro otimizado para Windows 11.
- **Modo Análise Unificado**: Explicação pedagógica em 6 seções em um único painel scrollável.
- **Performance**: Redução drástica de objetos Qt e buffers inteligentes para evitar travamentos.
- **Topologia**: Mapa interativo de dispositivos locais e conexões com a Internet.
- **Tráfego**: Gráficos EMA e estatísticas de protocolos em tempo real.
- **Laboratório Inseguro**: Servidor HTTP didático com vulnerabilidades (SQLi, XSS, IDOR).

---

## Pré-requisitos

- **Windows 10/11**
- **Python 3.11+**
- **Npcap** (com "WinPcap API-compatible mode")
- **Privilégios de Administrador**

---

## Instalação

1. **Instale o Npcap** de [https://npcap.com](https://npcap.com).
2. **Clone o repositório** e entre na pasta.
3. **Crie o ambiente virtual**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
4. **Execute**:
   ```powershell
   python main.py
   ```

---

## Estrutura do Projeto

- `main.py`: Entrada do programa.
- `analisador_pacotes.py`: Lógica de classificação de pacotes.
- `netlab_core.py`: Núcleo de métricas e contadores.
- `motor_pedagogico.py`: Geração de explicações didáticas.
- `interface/`: Todos os painéis da interface PyQt6.
- `utils/`: Utilitários de rede e identificação.

---

**Autor:** Yuri Gonçalves Pavão  
**GitHub:** [github.com/Yurigonpav](https://github.com/Yurigonpav)
