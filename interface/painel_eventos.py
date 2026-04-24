# interface/painel_eventos.py
# Painel do Modo Análise — Estrutura Pedagógica de 6 Seções + Otimizações v3.2
#
# NOVA ESTRUTURA PEDAGÓGICA:
#   O motor pedagógico atua como analista de redes + professor experiente.
#   Cada evento é estruturado em até 6 seções:
#     1. Análise              — O que aconteceu + Por que + Conclusão
#     2. Leitura Técnica      — Como o protocolo funciona internamente
#     3. Superfície de Risco  — Vulnerabilidades (quando aplicável)
#     4. Evidência Observada  — Campos do evento + interpretação
#     5. Interpretação Oper.  — O que significa na prática
#     6. Ação Sugerida        — O que fazer + justificativa (quando aplicável)
#
# ABAS DE EXIBIÇÃO:
#   Aba 0 "Análise"      → Seções 1 + 2 (análise + protocolo)
#   Aba 1 "Risco & Dados" → Seções 3 + 4 (risco + evidência)
#   Aba 2 "Evidências"    → Seções 4 + 5 + 6 (raw + operacional + ação)
#
# OTIMIZAÇÕES v3.2 (freeze fix — mantidas da v3.1):
#   - QScrollArea wrapper removido — QListWidget usa scroll nativo
#   - Cap de 120 itens no QListWidget com takeItem(0) O(1)
#   - _reaplicar_filtros tem guard de chave para evitar reconstrução redundante
#   - _todos_eventos é deque(maxlen=300): O(1) nas duas pontas
#   - atualizar_insights() diff incremental
#   - _renderizar_insights() com guard de chave
#   - Lazy loading: filtros reaplicados só ao abrir a aba

from collections import defaultdict, deque
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton, QTextEdit,
    QSplitter, QTabWidget, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QGridLayout, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QFont, QColor
from utils.constantes import CLASSIFICACAO_USO
from utils.rede import formatar_bytes, corrigir_mojibake


# ─────────────────────────────────────────────────────────────
# Constantes visuais
# ─────────────────────────────────────────────────────────────

ESTILOS_NIVEL = {
    "INFO":    {"borda": "#3498DB", "fundo": "#0d1a2a", "badge": "#1a4a6b"},
    "AVISO":   {"borda": "#E67E22", "fundo": "#1f1200", "badge": "#5a3000"},
    "CRITICO": {"borda": "#E74C3C", "fundo": "#200a0a", "badge": "#5a0000"},
}

# Abas de nível: (ícone, rótulo, tooltip)
ROTULOS_NIVEL = [
    ("", "Análise",        "Análise do evento + leitura técnica do protocolo"),
    ("", "Risco e Dados",  "Superfície de risco + evidência observada com interpretação"),
    ("", "Evidências",     "Dump bruto do pacote + interpretação operacional + ação sugerida"),
]

# Cabeçalhos das seções pedagógicas — embutidos na renderização
SECOES_PEDAGOGICAS = {
    "analise": {
        "titulo":   "1. Análise",
        "subtitulo": "O que aconteceu · Por que aconteceu · Conclusão",
        "cor":      "#3498DB",
        "icone":    "",
    },
    "tecnica": {
        "titulo":   "2. Leitura Técnica",
        "subtitulo": "Como o protocolo funciona · Conceitos aplicados ao caso",
        "cor":      "#2ECC71",
        "icone":    "",
    },
    "risco": {
        "titulo":   "3. Superfície de Risco",
        "subtitulo": "O que pode dar errado · Como a vulnerabilidade ocorre",
        "cor":      "#E74C3C",
        "icone":    "",
    },
    "evidencia": {
        "titulo":   "4. Evidência Observada",
        "subtitulo": "Campos do evento · Significado de cada campo",
        "cor":      "#F39C12",
        "icone":    "",
    },
    "operacional": {
        "titulo":   "5. Interpretação Operacional",
        "subtitulo": "O que significa na prática · Quando vira problema",
        "cor":      "#9B59B6",
        "icone":    "",
    },
    "acao": {
        "titulo":   "6. Ação Sugerida",
        "subtitulo": "O que fazer · Por que · O que monitorar",
        "cor":      "#1ABC9C",
        "icone":    "",
    },
}

# Domínios conhecidos → nome amigável
DOMINIOS_CONHECIDOS = {
    "google.com": "Google",           "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static",   "youtube.com": "YouTube",
    "youtu.be": "YouTube",            "googlevideo.com": "YouTube Vídeo",
    "facebook.com": "Facebook",       "instagram.com": "Instagram",
    "fbcdn.net": "Facebook CDN",      "whatsapp.com": "WhatsApp",
    "whatsapp.net": "WhatsApp",       "twitter.com": "Twitter/X",
    "twimg.com": "Twitter CDN",       "x.com": "X (Twitter)",
    "netflix.com": "Netflix",         "nflxvideo.net": "Netflix Vídeo",
    "amazon.com": "Amazon",           "amazonaws.com": "Amazon AWS",
    "microsoft.com": "Microsoft",     "office.com": "Microsoft Office",
    "live.com": "Microsoft Live",     "outlook.com": "Outlook",
    "windows.com": "Windows Update",  "windowsupdate.com": "Windows Update",
    "apple.com": "Apple",             "icloud.com": "iCloud",
    "spotify.com": "Spotify",         "twitch.tv": "Twitch",
    "tiktok.com": "TikTok",           "reddit.com": "Reddit",
    "wikipedia.org": "Wikipedia",     "github.com": "GitHub",
    "steamcontent.com": "Steam",      "steampowered.com": "Steam",
    "discord.com": "Discord",         "discordapp.com": "Discord CDN",
    "cloudflare.com": "Cloudflare",   "akamai.net": "Akamai CDN",
    "akamaized.net": "Akamai CDN",    "globo.com": "Globo",
    "uol.com.br": "UOL",              "terra.com.br": "Terra",
    "zoom.us": "Zoom",                "slack.com": "Slack",
    "dropbox.com": "Dropbox",         "drive.google.com": "Google Drive",
}

# Limite máximo de widgets reais no QListWidget — evita freeze na troca de aba
_LIMITE_LISTA_WIDGETS = 120


# ─────────────────────────────────────────────────────────────
# Cartão de evento (lista lateral)
# ─────────────────────────────────────────────────────────────

class CartaoEvento(QFrame):
    """Cartão compacto para a lista lateral de eventos capturados."""

    def __init__(self, dados: dict, parent=None):
        super().__init__(parent)
        nivel  = dados.get("nivel", "INFO")
        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {estilo['fundo']};
                border-left: 4px solid {estilo['borda']};
                border-radius: 3px;
                margin: 1px 2px;
            }}
            QFrame:hover {{ background-color: #1a2540; }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(2)

        # Cabeçalho: ícone+título + timestamp
        cabecalho = QHBoxLayout()
        icone_titulo = QLabel(
            f"{dados.get('icone', '')} {dados.get('titulo', 'Evento')}".strip()
        )
        icone_titulo.setStyleSheet(
            f"color:{estilo['borda']};font-weight:bold;"
            f"font-size:10px;border:none;"
        )
        icone_titulo.setWordWrap(False)

        hora = QLabel(dados.get("timestamp", ""))
        hora.setStyleSheet("color:#7f8c8d;font-size:9px;border:none;")

        cabecalho.addWidget(icone_titulo, 1)
        cabecalho.addWidget(hora)
        layout.addLayout(cabecalho)

        # IPs envolvidos
        ip_src = dados.get("ip_envolvido", "")
        ip_dst = dados.get("ip_destino", "")
        ip_texto = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_texto += f" → {ip_dst}"

        lbl_ip = QLabel(ip_texto)
        lbl_ip.setStyleSheet(
            "color:#95a5a6;font-size:9px;font-family:Consolas;border:none;"
        )
        layout.addWidget(lbl_ip)

        # Badge de alerta
        if dados.get("alerta_seguranca"):
            badge = QLabel("⚠ Risco de segurança")
            badge.setStyleSheet(
                f"color:#E74C3C;font-size:8px;font-weight:bold;"
                f"background:{estilo['badge']};border-radius:2px;"
                f"padding:1px 4px;border:none;"
            )
            layout.addWidget(badge)


# ─────────────────────────────────────────────────────────────
# Barra de contadores por tipo de evento
# ─────────────────────────────────────────────────────────────

class PainelContadores(QWidget):
    """Barra horizontal com contadores por tipo de evento."""

    TIPOS_MONITORADOS = [
        ("DNS",     "#3498DB"),
        ("HTTP",    "#E74C3C"),
        ("HTTPS",   "#2ECC71"),
        ("TCP_SYN", "#9B59B6"),
        ("ICMP",    "#1ABC9C"),
        ("ARP",     "#E67E22"),
        ("DHCP",    "#16A085"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._contadores: dict = defaultdict(int)
        self._labels:     dict = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(8)

        titulo = QLabel("Eventos nesta sessão:")
        titulo.setStyleSheet("color:#7f8c8d;font-size:9px;")
        layout.addWidget(titulo)

        for tipo, cor in self.TIPOS_MONITORADOS:
            lbl = QLabel(f"{tipo}: 0")
            lbl.setStyleSheet(
                f"color:{cor};font-size:9px;font-family:Consolas;"
                f"background:#0d1a2a;border:1px solid {cor}33;"
                f"border-radius:3px;padding:1px 6px;"
            )
            self._labels[tipo] = lbl
            layout.addWidget(lbl)

        layout.addStretch()

    def incrementar(self, tipo: str):
        self._contadores[tipo] += 1
        if tipo in self._labels:
            self._labels[tipo].setText(f"{tipo}: {self._contadores[tipo]}")

    def resetar(self):
        self._contadores.clear()
        for tipo, _ in self.TIPOS_MONITORADOS:
            if tipo in self._labels:
                self._labels[tipo].setText(f"{tipo}: 0")

    def obter_contagens(self) -> dict:
        """Retorna cópia dos contadores para uso nos insights."""
        return dict(self._contadores)


# ─────────────────────────────────────────────────────────────
# Painel principal de Eventos
# ─────────────────────────────────────────────────────────────

class PainelEventos(QWidget):
    """
    Painel completo do Modo Análise com estrutura gpedaógica de 6 seções.

    ESTRUTURA PEDAGÓGICA (professor-analista):
    ─────────────────────────────────────────
    O painel exibe cada evento com até 6 seções estruturadas:
      1. Análise              → O que/por que aconteceu + conclusão
      2. Leitura Técnica      → Protocolo interno + conceitos aplicados
      3. Superfície de Risco  → Vulnerabilidades + como ocorrem (se aplicável)
      4. Evidência Observada  → Campos reais + interpretação de cada campo
      5. Interpretação Oper.  → Significado prático + quando vira problema
      6. Ação Sugerida        → O que fazer + justificativa (se aplicável)

    OTIMIZAÇÕES v3.2
    ─────────────────
    • QListWidget direto, sem QScrollArea wrapper
    • Cap de _LIMITE_LISTA_WIDGETS (120) com takeItem(0) O(1)
    • _reaplicar_filtros com guard de chave
    • _todos_eventos deque(maxlen=300)
    • atualizar_insights() diff incremental
    • Lazy loading ao abrir a aba
    """

    LIMITE_EVENTOS = 300

    def __init__(self, parent=None):
        super().__init__(parent)
        self._todos_eventos:     deque = deque(maxlen=self.LIMITE_EVENTOS)
        self._eventos_filtrados: list  = []
        self._evento_atual:      dict  = {}
        self._nivel_atual:       int   = 0
        self._filtro_protocolo:  str   = "Todos"
        self._filtro_texto:      str   = ""
        self._contagem_sessao:   dict  = defaultdict(lambda: defaultdict(int))

        # Atributos para insights e alertas
        self._alertas_seguranca:  list  = []
        self._volume_bytes_total: int   = 0
        self._ultimo_top_dns:     list  = []
        self._ultimo_historias:   list  = []
        self._ultima_chave_dns:   str   = ''
        self._chave_render_anterior: str = ''

        # Guard para _reaplicar_filtros
        self._ultima_chave_filtro = None

        self._montar_layout()

    # ──────────────────────────────────────────────
    # Montagem da interface
    # ──────────────────────────────────────────────

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 4)
        layout.setSpacing(4)

        # Cabeçalho
        cab = QHBoxLayout()
        fonte_titulo = QFont("Arial", 12)
        fonte_titulo.setBold(True)
        titulo = QLabel("Modo Análise — Eventos de Rede em Tempo Real")
        titulo.setFont(fonte_titulo)
        cab.addWidget(titulo)
        cab.addStretch()
        layout.addLayout(cab)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#2c3e50;")
        layout.addWidget(sep)

        layout.addLayout(self._criar_barra_filtros())

        self.painel_contadores = PainelContadores()
        layout.addWidget(self.painel_contadores)

        self.abas = QTabWidget()
        layout.addWidget(self.abas)

        self.abas.addTab(self._criar_aba_eventos(),  "Eventos ao Vivo")
        self.abas.addTab(self._criar_aba_insights(), "Insights")

        self.lbl_rodape = QLabel("Nenhum evento registrado.")
        self.lbl_rodape.setStyleSheet("color:#7f8c8d;font-size:10px;padding:2px;")
        layout.addWidget(self.lbl_rodape)

        self._trocar_nivel(0)
        self._exibir_boas_vindas()

    # ──────────────────────────────────────────────
    # Aba de Eventos ao Vivo
    # ──────────────────────────────────────────────

    def _criar_barra_filtros(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)

        lbl = QLabel("Filtrar:")
        lbl.setStyleSheet("color:#7f8c8d;font-size:10px;")
        row.addWidget(lbl)

        self.combo_protocolo = QComboBox()
        self.combo_protocolo.setMaximumWidth(140)
        self.combo_protocolo.addItems([
            "Todos", "DNS", "HTTP", "HTTPS", "TCP_SYN",
            "ICMP", "ARP", "DHCP", "NOVO_DISPOSITIVO",
        ])
        self.combo_protocolo.currentTextChanged.connect(self._ao_mudar_filtro_protocolo)
        row.addWidget(self.combo_protocolo)

        self.campo_busca = QLineEdit()
        self.campo_busca.setPlaceholderText("Buscar por IP, domínio ou palavra-chave")
        self.campo_busca.setMaximumWidth(280)
        self.campo_busca.textChanged.connect(self._ao_mudar_filtro_texto)
        row.addWidget(self.campo_busca)

        row.addStretch()
        return row

    def _criar_aba_eventos(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # ── Lista lateral de eventos ──────────────
        w_lista = QWidget()
        l_lista = QVBoxLayout(w_lista)
        l_lista.setContentsMargins(0, 0, 4, 0)
        l_lista.setSpacing(2)

        fonte_label = QFont("Arial", 10)
        fonte_label.setBold(True)
        lbl_lista = QLabel("Eventos Capturados")
        lbl_lista.setStyleSheet("color:#7f8c8d;padding-bottom:4px;")
        lbl_lista.setFont(fonte_label)
        l_lista.addWidget(lbl_lista)

        # QListWidget direto, sem QScrollArea wrapper (anti-freeze)
        self.lista_eventos = QListWidget()
        self.lista_eventos.setSpacing(2)
        self.lista_eventos.setWordWrap(True)
        self.lista_eventos.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        l_lista.addWidget(self.lista_eventos)

        splitter.addWidget(w_lista)

        # ── Painel de explicação pedagógica ───────
        w_expl = QWidget()
        l_expl = QVBoxLayout(w_expl)
        l_expl.setContentsMargins(4, 0, 0, 0)
        l_expl.setSpacing(4)

        lbl_expl = QLabel("Análise")
        lbl_expl.setStyleSheet("font-weight:bold;font-size:11px;color:#bdc3c7;")
        l_expl.addWidget(lbl_expl)

        # Botões de nível — 3 abas pedagógicas
        row_niveis = QHBoxLayout()
        self.botoes_nivel = []
        for icone, rotulo, dica in ROTULOS_NIVEL:
            btn = QPushButton(f"{icone} {rotulo}")
            btn.setCheckable(True)
            btn.setMaximumHeight(28)
            btn.setToolTip(dica)
            btn.setStyleSheet("""
                QPushButton {
                    background: #12162a;
                    color: #7f8c8d;
                    border: 1px solid #1e2d40;
                    border-radius: 4px;
                    padding: 4px 10px;
                    font-size: 10px;
                }
                QPushButton:checked {
                    background: #1e3a5f;
                    color: #ecf0f1;
                    border: 1px solid #3498DB;
                }
                QPushButton:hover { background: #1a2540; color: #ecf0f1; }
            """)
            idx = len(self.botoes_nivel)
            btn.clicked.connect(lambda _, n=idx: self._trocar_nivel(n))
            self.botoes_nivel.append(btn)
            row_niveis.addWidget(btn)
        row_niveis.addStretch()
        l_expl.addLayout(row_niveis)

        self.texto_explicacao = QTextEdit()
        self.texto_explicacao.setReadOnly(True)
        self.texto_explicacao.setStyleSheet("""
            QTextEdit {
                background-color: #0f1423;
                color: #ecf0f1;
                border: 1px solid #1e2d40;
                border-radius: 6px;
                padding: 14px;
                font-size: 11px;
            }
        """)
        l_expl.addWidget(self.texto_explicacao)

        splitter.addWidget(w_expl)
        splitter.setSizes([400, 580])
        return widget

    # ──────────────────────────────────────────────
    # Aba Insights — dados reais
    # ──────────────────────────────────────────────

    def _criar_aba_insights(self) -> QWidget:
        widget = QWidget()
        layout_externo = QVBoxLayout(widget)
        layout_externo.setContentsMargins(0, 0, 0, 0)
        layout_externo.setSpacing(0)

        self._barra_resumo = self._criar_barra_resumo()
        layout_externo.addWidget(self._barra_resumo)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self._container_insights = QWidget()
        self._layout_insights    = QVBoxLayout(self._container_insights)
        self._layout_insights.setContentsMargins(8, 6, 8, 8)
        self._layout_insights.setSpacing(10)
        self._layout_insights.addStretch()

        scroll.setWidget(self._container_insights)
        layout_externo.addWidget(scroll)

        return widget

    def _criar_barra_resumo(self) -> QFrame:
        """Faixa de métricas rápidas no topo da aba Insights."""
        frame = QFrame()
        frame.setFixedHeight(44)
        frame.setStyleSheet(
            "QFrame { background:#0a0f1a; border-bottom:1px solid #1e2d40; }"
            "QLabel { border:none; background:transparent; }"
        )
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(0)

        def _metrica(rotulo: str, cor: str) -> QLabel:
            lbl = QLabel(rotulo)
            lbl.setStyleSheet(
                f"color:{cor};font-size:10px;font-family:Consolas;"
                "padding: 0 14px 0 0;border:none;background:transparent;"
            )
            return lbl

        lbl_label = QLabel("Sessão atual:  ")
        lbl_label.setStyleSheet(
            "color:#566573;font-size:10px;border:none;background:transparent;"
        )

        self._lbl_resumo_eventos  = _metrica("0 eventos",        "#3498DB")
        self._lbl_resumo_dns      = _metrica("0 consultas DNS",  "#2ECC71")
        self._lbl_resumo_volume   = _metrica("0 B trafegados",   "#9B59B6")
        self._lbl_resumo_alertas  = _metrica("0 alertas",        "#566573")
        self._lbl_resumo_insights = _metrica("Aguardando dados de captura...", "#7f8c8d")
        self._lbl_total_insights  = _metrica("", "#7f8c8d")

        layout.addWidget(lbl_label)
        layout.addWidget(self._lbl_resumo_eventos)
        layout.addWidget(self._lbl_resumo_dns)
        layout.addWidget(self._lbl_resumo_volume)
        layout.addWidget(self._lbl_resumo_alertas)
        layout.addWidget(self._lbl_resumo_insights)
        layout.addWidget(self._lbl_total_insights)
        layout.addStretch()

        return frame

    # ──────────────────────────────────────────────
    # Renderização da explicação pedagógica (6 seções)
    # ──────────────────────────────────────────────

    @staticmethod
    def _html_cabecalho_secao(chave: str) -> str:
        """Gera o cabeçalho HTML de uma seção pedagógica."""
        info = SECOES_PEDAGOGICAS.get(chave, {})
        cor    = info.get("cor",      "#3498DB")
        icone  = info.get("icone",    "•")
        titulo = info.get("titulo",   chave)
        sub    = info.get("subtitulo", "")
        return (
            f"<div style='margin:14px 0 6px 0;border-left:3px solid {cor};"
            f"padding:4px 10px;background:rgba(0,0,0,0.18);border-radius:0 4px 4px 0;'>"
            f"<span style='color:{cor};font-weight:bold;font-size:11px;'>"
            f"{icone} {titulo}</span>"
            f"<span style='color:#566573;font-size:9px;margin-left:8px;'>"
            f"{sub}</span>"
            f"</div>"
        )

    @staticmethod
    def _html_conteudo_secao(conteudo: str, cor_borda: str = "#1e2d40") -> str:
        """Envolve o conteúdo de uma seção em um bloco visual."""
        if not conteudo or not conteudo.strip():
            return ""
        return (
            f"<div style='background:#080d1a;border:1px solid {cor_borda};"
            f"border-radius:5px;padding:10px 14px;margin:4px 0 10px 0;"
            f"font-size:11px;line-height:1.7;color:#ecf0f1;'>"
            f"{conteudo}"
            f"</div>"
        )

    def _renderizar_nivel_0(self, e: dict) -> str:
        """
        Nível 0 — Análise: Seções 1 (análise) + 2 (leitura técnica).
        O conteúdo vem de nivel1 (análise) e nivel2 (técnica).
        """
        conteudo_analise = e.get("nivel1", "")
        conteudo_tecnica = e.get("nivel2", "")

        html = ""

        # Seção 1: Análise
        if conteudo_analise:
            html += self._html_cabecalho_secao("analise")
            html += self._html_conteudo_secao(conteudo_analise, "#1e3a5f")

        # Seção 2: Leitura Técnica
        if conteudo_tecnica:
            html += self._html_cabecalho_secao("tecnica")
            html += self._html_conteudo_secao(conteudo_tecnica, "#1a3a1a")

        if not html:
            html = "<i style='color:#7f8c8d;'>Análise não disponível para este evento.</i>"

        return html

    def _renderizar_nivel_1(self, e: dict) -> str:
        """
        Nível 1 — Risco & Dados: Seções 3 (risco) + 4 (evidência).
        Risco vem do alerta_seguranca + nivel2; evidência de nivel3.
        """
        alerta    = e.get("alerta_seguranca", "")
        nivel2    = e.get("nivel2", "")
        evidencia = e.get("nivel3", "")

        html = ""

        # Seção 3: Superfície de Risco
        # Apresentada apenas quando há alerta real de segurança
        if alerta:
            html += self._html_cabecalho_secao("risco")
            bloco_risco = (
                f"<div style='background:#200a0a;border:1px solid #E74C3C;"
                f"border-radius:5px;padding:10px 14px;margin:4px 0 10px 0;'>"
                f"<b style='color:#E74C3C;'>⚠ Risco identificado:</b><br>"
                f"<span style='color:#ecf0f1;font-size:11px;line-height:1.7;'>"
                f"{alerta}</span>"
                f"</div>"
            )
            # Se houver conteúdo técnico complementar sobre o risco, inclui
            if nivel2 and "risco" in nivel2.lower() or "vulnerab" in nivel2.lower():
                bloco_risco += self._html_conteudo_secao(nivel2, "#5a0000")
            html += bloco_risco
        else:
            html += self._html_cabecalho_secao("risco")
            html += (
                "<div style='background:#0a1a0a;border:1px solid #2a4a2a;"
                "border-radius:5px;padding:8px 14px;margin:4px 0 10px 0;"
                "color:#2ECC71;font-size:10px;'>"
                " Nenhuma superfície de risco crítica identificada neste evento."
                "</div>"
            )

        # Seção 4: Evidência Observada
        if evidencia:
            html += self._html_cabecalho_secao("evidencia")
            html += self._html_conteudo_secao(evidencia, "#3a2a00")
        else:
            # Monta evidência básica a partir dos campos do evento
            html += self._html_cabecalho_secao("evidencia")
            html += self._html_conteudo_secao(
                self._gerar_evidencia_basica(e), "#1a2a3a"
            )

        if not html:
            html = "<i style='color:#7f8c8d;'>Dados de risco não disponíveis.</i>"

        return html

    def _renderizar_nivel_2(self, e: dict) -> str:
        """
        Nível 2 — Evidências: Seções 4 (raw) + 5 (operacional) + 6 (ação).
        Conteúdo principal vem de nivel4 (pacote bruto + interpretação).
        """
        nivel4 = e.get("nivel4", "")
        tipo   = e.get("tipo",   "")

        html = ""

        # Seção 4: Evidência Observada (raw / dump)
        html += self._html_cabecalho_secao("evidencia")
        if nivel4:
            html += (
                "<div style='background:#000;border:1px solid #1e2d40;"
                "border-radius:5px;padding:10px 14px;margin:4px 0 10px 0;'>"
                f"{nivel4}"
                "</div>"
            )
        else:
            html += (
                "<div style='background:#0a0f1a;border:1px solid #1e2d40;"
                "border-radius:5px;padding:10px 14px;margin:4px 0 10px 0;"
                "color:#7f8c8d;font-size:10px;text-align:center;'>"
                "Dump bruto disponível apenas para eventos HTTP.<br>"
                "Acesse um site HTTP (porta 80) para visualizar o pacote completo."
                "</div>"
            )

        # Seção 5: Interpretação Operacional
        html += self._html_cabecalho_secao("operacional")
        html += self._html_conteudo_secao(
            self._gerar_interpretacao_operacional(e), "#2a1a4a"
        )

        # Seção 6: Ação Sugerida (somente quando há contexto relevante)
        acao = self._gerar_acao_sugerida(e)
        if acao:
            html += self._html_cabecalho_secao("acao")
            html += self._html_conteudo_secao(acao, "#0a2a2a")

        return html

    @staticmethod
    def _gerar_evidencia_basica(e: dict) -> str:
        """Gera HTML de evidência básica a partir dos campos do evento."""
        tipo       = e.get("tipo",           "—")
        ip_orig    = e.get("ip_envolvido",   "") or e.get("ip_origem", "—")
        ip_dest    = e.get("ip_destino",     "—")
        protocolo  = e.get("protocolo",      tipo)
        tamanho    = e.get("tamanho",        0)
        porta_dest = e.get("porta_destino",  "—")
        dominio    = e.get("dominio",        "")
        ttl        = e.get("ttl",            "")
        contador   = e.get("contador",       1)
        ts         = e.get("timestamp",      "")

        def campo(nome, valor, cor="#ecf0f1"):
            if not valor or valor == "—" or valor == 0:
                return ""
            return (
                f"<tr>"
                f"<td style='padding:3px 12px 3px 0;color:#7f8c8d;white-space:nowrap;"
                f"font-size:10px;'>{nome}</td>"
                f"<td style='padding:3px 0;color:{cor};font-family:Consolas;"
                f"font-size:10px;'>{valor}</td>"
                f"</tr>"
            )

        linhas = (
            campo("Tipo",           tipo,            "#F39C12") +
            campo("Timestamp",      ts,              "#7f8c8d") +
            campo("IP Origem",      ip_orig,         "#3498DB") +
            campo("IP Destino",     ip_dest,         "#3498DB") +
            campo("Protocolo",      protocolo,       "#2ECC71") +
            campo("Porta Destino",  str(porta_dest), "#ecf0f1") +
            campo("Domínio",        dominio,         "#2ECC71") +
            campo("Tamanho",        f"{tamanho} bytes" if tamanho else "", "#ecf0f1") +
            campo("TTL",            str(ttl) if ttl else "", "#9B59B6") +
            campo("Ocorrências",    str(contador),   "#ecf0f1")
        )

        if not linhas:
            return "<i style='color:#566573;'>Campos não disponíveis.</i>"

        return (
            "<table style='border-collapse:collapse;width:100%;'>"
            + linhas +
            "</table>"
        )

    @staticmethod
    def _gerar_interpretacao_operacional(e: dict) -> str:
        """
        Gera interpretação operacional baseada no tipo de evento.
        Ensina: o que significa na prática + quando vira problema.
        """
        tipo   = e.get("tipo", "")
        alerta = e.get("alerta_seguranca", "")

        mapa = {
            "DNS": (
                "<b>Significado prático:</b> Toda navegação web começa com uma "
                "consulta DNS — o dispositivo precisa resolver o nome antes de "
                "abrir qualquer conexão TCP. Volume alto de DNS para domínios "
                "desconhecidos pode indicar C2 (command and control) ou exfiltração "
                "via DNS tunneling.<br><br>"
                "<b>Quando vira problema:</b> DNS sem DNSSEC permite ataques de "
                "cache poisoning. DNS sobre UDP (porta 53) é legível por qualquer "
                "nó na rede — revela quais serviços o dispositivo acessa."
            ),
            "HTTP": (
                "<b>Significado prático:</b> Tráfego HTTP em texto puro é "
                "imediatamente legível por qualquer capturador na mesma rede. "
                "Credenciais, cookies de sessão e dados de formulário trafegam "
                "sem proteção alguma.<br><br>"
                "<b>Quando vira problema:</b> Em redes Wi-Fi abertas ou com ARP "
                "spoofing ativo, qualquer participante pode interceptar e modificar "
                "o conteúdo em trânsito (MITM). O único controle efetivo é migrar "
                "para HTTPS com HSTS habilitado."
            ),
            "HTTPS": (
                "<b>Significado prático:</b> O TLS garante confidencialidade, "
                "integridade e autenticidade da comunicação. Mesmo capturando todos "
                "os pacotes, o conteúdo permanece ilegível sem a chave de sessão.<br><br>"
                "<b>Quando vira problema:</b> Certificados autoassinados ou expirados "
                "permitem ataques de SSL stripping. O SNI (Server Name Indication) "
                "ainda revela o hostname — visível mesmo em conexões HTTPS."
            ),
            "ARP": (
                "<b>Significado prático:</b> O ARP opera sem autenticação — qualquer "
                "dispositivo pode responder a um ARP request, verdadeiro ou não. "
                "Isso é normal em redes locais, mas cria um vetor de ataque direto.<br><br>"
                "<b>Quando vira problema:</b> ARP spoofing (gratuitous ARP) permite "
                "redirecionar o tráfego de qualquer host para o atacante "
                "transparentemente. Ferramentas como arpspoof fazem isso em segundos."
            ),
            "TCP_SYN": (
                "<b>Significado prático:</b> O three-way handshake TCP estabelece "
                "estado em ambos os lados antes de qualquer dado trafegar. "
                "SYNs isolados (sem SYN-ACK de resposta) indicam porta fechada, "
                "firewall ou host inexistente.<br><br>"
                "<b>Quando vira problema:</b> Flood de SYNs sem ACK (SYN flood) "
                "esgota a tabela de conexões half-open do servidor. "
                "Port scanning gera SYNs sequenciais em várias portas."
            ),
            "ICMP": (
                "<b>Significado prático:</b> ICMP é a camada de diagnóstico do IP — "
                "usado para ping, traceroute e notificação de erros de roteamento. "
                "Não carrega dados de aplicação.<br><br>"
                "<b>Quando vira problema:</b> ICMP pode ser usado para tunneling "
                "(dados ocultos no payload do Echo Request). "
                "Volume incomum de ICMP pode indicar varredura ou flood."
            ),
            "DHCP": (
                "<b>Significado prático:</b> O DHCP distribui configuração de rede "
                "automaticamente. Um único servidor DHCP responde a todos os clientes "
                "da rede sem autenticação mútua.<br><br>"
                "<b>Quando vira problema:</b> Rogue DHCP server pode distribuir "
                "gateway e DNS falsos, redirecionando todo o tráfego da vítima. "
                "Detectável monitorando DISCOVERs sem OFFER legítimo."
            ),
        }

        texto_base = mapa.get(tipo, (
            "<b>Significado prático:</b> Evento de rede capturado e classificado "
            "pelo analisador. Verifique os campos de evidência para mais detalhes."
        ))

        # Adiciona aviso de alerta se presente
        if alerta:
            texto_base += (
                f"<br><br><div style='background:#1a0a0a;border-left:3px solid #E74C3C;"
                f"padding:6px 10px;border-radius:3px;color:#ffb3b3;font-size:10px;'>"
                f"<b>⚠ Alerta ativo:</b> {alerta}</div>"
            )

        return texto_base

    @staticmethod
    def _gerar_acao_sugerida(e: dict) -> str:
        """
        Gera ação sugerida apenas quando há contexto de risco real.
        Sempre com justificativa técnica.
        """
        tipo   = e.get("tipo", "")
        alerta = e.get("alerta_seguranca", "")

        # Só gera ação quando há risco identificado ou protocolo inseguro
        acoes = {
            "HTTP": (
                "<b>O que fazer:</b><br>"
                "• Migre para HTTPS com certificado válido (Let's Encrypt é gratuito)<br>"
                "• Habilite HSTS (<code>Strict-Transport-Security</code>) para forçar "
                "HTTPS em acessos futuros<br>"
                "• Monitore requisições HTTP na porta 80 — qualquer login via HTTP "
                "é uma credencial exposta<br><br>"
                "<b>Por que isso resolve:</b> O TLS cifra o payload completo "
                "(headers + corpo + cookies) antes de sair do socket, tornando "
                "a interceptação inútil sem a chave de sessão."
            ),
            "ARP": (
                "<b>O que fazer:</b><br>"
                "• Execute <code>arp -a</code> periodicamente e compare com o mapa "
                "esperado da rede<br>"
                "• Em ambientes críticos, use ARP dinâmico com DAI (Dynamic ARP "
                "Inspection) em switches gerenciados<br>"
                "• Monitore entradas duplicadas na tabela ARP "
                "(mesmo IP, MACs diferentes)<br><br>"
                "<b>Por que isso resolve:</b> DAI valida cada ARP reply contra a "
                "tabela DHCP snooping, descartando respostas não autorizadas."
            ),
            "DHCP": (
                "<b>O que fazer:</b><br>"
                "• Habilite DHCP snooping no switch para limitar quais portas "
                "podem originar respostas DHCP<br>"
                "• Monitore o syslog do servidor DHCP para concessões inesperadas<br>"
                "• Use 802.1X para autenticar dispositivos antes de conceder "
                "acesso à rede<br><br>"
                "<b>Por que isso resolve:</b> DHCP snooping cria uma tabela de "
                "portas confiáveis; ofertas de portas não confiáveis são descartadas "
                "silenciosamente pelo switch."
            ),
        }

        # Retorna ação se o tipo tiver contexto de risco OU se há alerta ativo
        if tipo in acoes:
            return acoes[tipo]

        if alerta:
            return (
                "<b>O que fazer:</b><br>"
                f"• Investigue o alerta: <i>{alerta[:120]}</i><br>"
                "• Correlacione com outros eventos do mesmo IP no histórico<br>"
                "• Considere isolar o dispositivo origem se o comportamento persistir<br><br>"
                "<b>O que monitorar:</b> frequência do evento, variação de IP/MAC "
                "de origem, horário dos picos."
            )

        return ""  # Sem ação para eventos normais sem risco

    # ──────────────────────────────────────────────
    # Renderização dos Insights (diff incremental)
    # ──────────────────────────────────────────────

    def _renderizar_insights(self):
        total_ev  = len(self._todos_eventos)
        top_dns   = getattr(self, '_ultimo_top_dns', [])
        total_dns = sum(d.get('acessos', 0) for d in top_dns)

        self._lbl_resumo_eventos.setText(f"{total_ev:,} eventos")
        self._lbl_resumo_dns.setText(f"{total_dns:,} consultas DNS")
        self._lbl_resumo_insights.setText(f"{total_ev} eventos · {total_dns} consultas DNS")
        self._lbl_total_insights.setText(f"{total_ev:,} eventos analisados")

        chave_render = f"{total_ev}:{total_dns}:{len(top_dns)}"
        if chave_render == self._chave_render_anterior:
            return
        self._chave_render_anterior = chave_render

        self._limpar_layout_insights()
        if total_ev == 0:
            self._exibir_mensagem_insights_vazio()
            return

        self._layout_insights.addWidget(self._card_dominios(top_dns))
        self._layout_insights.addWidget(self._card_tipo_uso())
        self._layout_insights.addStretch()

    def _limpar_layout_insights(self):
        while self._layout_insights.count() > 0:
            item = self._layout_insights.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _exibir_mensagem_insights_vazio(self):
        lbl = QLabel(
            "Os insights aparecerão aqui durante a captura.\n\n"
            "Inicie a captura e navegue pela internet para\n"
            "ver os dados de tráfego em tempo real."
        )
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("color:#4a5a6b;font-size:12px;padding:50px;")
        self._layout_insights.addWidget(lbl)
        self._layout_insights.addStretch()
        self._lbl_resumo_insights.setText("Aguardando dados de captura...")
        self._lbl_total_insights.setText("")

    def _atualizar_barra_resumo(self, eventos: int, consultas_dns: int,
                                volume_bytes: int, alertas: int):
        self._lbl_resumo_eventos.setText(f"{eventos:,} eventos")
        self._lbl_resumo_dns.setText(f"{consultas_dns:,} consultas DNS")
        self._lbl_resumo_volume.setText(f"{formatar_bytes(volume_bytes)} trafegados")
        cor_alerta = "#E74C3C" if alertas > 0 else "#566573"
        self._lbl_resumo_alertas.setStyleSheet(
            f"color:{cor_alerta};font-size:10px;font-family:Consolas;padding:0 14px 0 0;"
        )
        self._lbl_resumo_alertas.setText(
            f"{' ' if alertas > 0 else ''}{alertas} alerta(s)"
        )
        self._lbl_resumo_insights.setText(
            f"{eventos} eventos · {consultas_dns} consultas DNS"
        )

    # ──────────────────────────────────────────────
    # Card — Tipo de Uso
    # ──────────────────────────────────────────────

    def _card_tipo_uso(self) -> QFrame:
        frame = self._criar_frame_card("#1a2a1f", "#2a4030")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        cab = QHBoxLayout()
        titulo = QLabel("Classificação de Uso da Rede")
        titulo.setStyleSheet("color:#F39C12;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        layout.addLayout(cab)

        contagens     = self.painel_contadores.obter_contagens()
        total_eventos = sum(contagens.values()) or 1

        if not contagens:
            layout.addWidget(self._lbl_vazio("Nenhum evento classificado ainda."))
            return frame

        categorias: dict = defaultdict(int)
        for tipo, qtd in contagens.items():
            cat, _ = CLASSIFICACAO_USO.get(tipo, ("Outro", "#7f8c8d"))
            categorias[cat] += qtd

        sorted_cats = sorted(categorias.items(), key=lambda x: x[1], reverse=True)
        max_qtd     = sorted_cats[0][1] if sorted_cats else 1

        grid = QGridLayout()
        grid.setSpacing(6)

        for idx, (cat, qtd) in enumerate(sorted_cats[:8]):
            tipo_orig = next(
                (t for t, (c, _) in CLASSIFICACAO_USO.items() if c == cat), ""
            )
            _, cor = CLASSIFICACAO_USO.get(tipo_orig, ("", "#7f8c8d"))
            pct    = (qtd / total_eventos) * 100

            lbl_cat = QLabel(cat)
            lbl_cat.setStyleSheet(f"color:{cor};font-size:9px;font-weight:bold;")

            barra = QProgressBar()
            barra.setRange(0, max(max_qtd, 1))
            barra.setValue(qtd)
            barra.setFixedHeight(10)
            barra.setTextVisible(False)
            barra.setStyleSheet(f"""
                QProgressBar {{ background:#0d1520; border-radius:3px; }}
                QProgressBar::chunk {{ background:{cor}; border-radius:3px; }}
            """)

            lbl_pct = QLabel(f"{pct:.0f}%")
            lbl_pct.setFixedWidth(36)
            lbl_pct.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_pct.setStyleSheet(f"color:{cor};font-size:9px;font-family:Consolas;")

            grid.addWidget(lbl_cat,  idx, 0)
            grid.addWidget(barra,    idx, 1)
            grid.addWidget(lbl_pct,  idx, 2)

        layout.addLayout(grid)
        return frame

    # ──────────────────────────────────────────────
    # Card — Domínios
    # ──────────────────────────────────────────────

    def _card_dominios(self, dominios: list) -> QFrame:
        frame = self._criar_frame_card("#1a3a5f", "#2a5a70")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        cab = QHBoxLayout()
        titulo = QLabel(" Domínios Mais Acessados")
        titulo.setStyleSheet("color:#2ECC71;font-weight:bold;font-size:11px;")
        cab.addWidget(titulo)
        cab.addStretch()
        total_acessos = sum(d.get("acessos", 0) for d in dominios)
        cab.addWidget(self._lbl_info(
            f"{len(dominios)} domínio(s) · {total_acessos} acessos"
        ))
        layout.addLayout(cab)

        sub = QLabel("Baseado em consultas DNS reais capturadas")
        sub.setStyleSheet("color:#4a6a8a;font-size:9px;")
        layout.addWidget(sub)

        if not dominios:
            layout.addWidget(self._lbl_vazio("Nenhum domínio acessado ainda."))
            return frame

        max_acessos = max((d.get("acessos", 1) for d in dominios[:15]), default=1)

        for i, dom in enumerate(dominios[:15]):
            dominio = dom.get("dominio", "?")
            acessos = dom.get("acessos", 0)

            nome = dominio
            for sufixo, apelido in DOMINIOS_CONHECIDOS.items():
                if dominio == sufixo or dominio.endswith("." + sufixo):
                    nome = apelido
                    break

            row = QHBoxLayout()
            row.setSpacing(6)

            lbl_num = QLabel(f"{i + 1}.")
            lbl_num.setFixedWidth(20)
            lbl_num.setStyleSheet("color:#566573;font-size:9px;")

            lbl_dom = QLabel(dominio)
            lbl_dom.setFixedWidth(180)
            lbl_dom.setToolTip(nome)
            lbl_dom.setStyleSheet("color:#ecf0f1;font-size:9px;font-family:Consolas;")

            barra = QProgressBar()
            barra.setRange(0, max(max_acessos, 1))
            barra.setValue(acessos)
            barra.setFixedHeight(12)
            barra.setTextVisible(False)
            barra.setStyleSheet("""
                QProgressBar { background:#0d1520; border-radius:3px; }
                QProgressBar::chunk { background:#2ECC71; border-radius:3px; }
            """)

            lbl_cnt = QLabel(f"{acessos}x")
            lbl_cnt.setFixedWidth(36)
            lbl_cnt.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lbl_cnt.setStyleSheet("color:#2ECC71;font-size:9px;font-family:Consolas;")

            row.addWidget(lbl_num)
            row.addWidget(lbl_dom)
            row.addWidget(barra, 1)
            row.addWidget(lbl_cnt)
            layout.addLayout(row)

        return frame

    # ──────────────────────────────────────────────
    # Auxiliares visuais
    # ──────────────────────────────────────────────

    @staticmethod
    def _criar_frame_card(cor_fundo: str, cor_borda: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {cor_fundo};
                border: 1px solid {cor_borda};
                border-radius: 8px;
            }}
        """)
        return frame

    @staticmethod
    def _lbl_info(texto: str) -> QLabel:
        lbl = QLabel(texto)
        lbl.setStyleSheet("color:#566573;font-size:9px;font-family:Consolas;")
        return lbl

    @staticmethod
    def _lbl_vazio(texto: str) -> QLabel:
        lbl = QLabel(texto)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("color:#4a5a6b;font-size:10px;padding:20px;")
        return lbl

    @staticmethod
    def _criar_tabela(colunas: list, n_linhas: int) -> QTableWidget:
        t = QTableWidget(n_linhas, len(colunas))
        t.setHorizontalHeaderLabels(colunas)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setStyleSheet("""
            QTableWidget {
                background:#0a0f1a; color:#ecf0f1;
                gridline-color:#1e2d40; border:none;
                alternate-background-color:#0d1520;
                font-size:9px; font-family:Consolas;
            }
            QHeaderView::section {
                background:#0d1520; color:#7f8c8d;
                border:none; padding:4px; font-size:9px;
            }
        """)
        t.horizontalHeader().setStretchLastSection(True)
        return t

    # ──────────────────────────────────────────────
    # API pública
    # ──────────────────────────────────────────────

    def atualizar_insights(self, top_dns: list, historias: list):
        self._ultimo_top_dns   = top_dns
        self._ultimo_historias = historias

        chave = f"{len(top_dns)}:{sum(d.get('acessos', 0) for d in top_dns)}"
        if chave == getattr(self, '_ultima_chave_dns', ''):
            return
        self._ultima_chave_dns = chave

        self._renderizar_insights()

    def atualizar_insights_correlacionados(self, insights: list, estatisticas: dict,
                                            top_dominios: list, narrativas: list):
        """Compatibilidade com MotorCorrelacao externo."""
        self.atualizar_insights([], [])

    def adicionar_evento(self, dados: dict):
        """Recebe um evento do motor pedagógico e exibe na interface."""
        sessao = dados.get("sessao_id", "sessao_default")
        tipo   = dados.get("tipo", "")
        self._contagem_sessao[sessao][tipo] += 1
        dados["contador_sessao"] = self._contagem_sessao[sessao][tipo]

        # Corrige encoding em todos os campos de texto
        for campo in ("titulo", "nivel1", "nivel2", "nivel3", "nivel4",
                      "alerta_seguranca", "fluxo_visual"):
            if campo in dados:
                dados[campo] = corrigir_mojibake(dados[campo])

        self._todos_eventos.append(dados)
        self.painel_contadores.incrementar(tipo)

        # Coleta alertas de segurança (cap. 50)
        alerta = dados.get("alerta_seguranca", "")
        if alerta and len(self._alertas_seguranca) < 50:
            ts    = dados.get("timestamp", "")
            ip    = dados.get("ip_envolvido", "")
            texto = f"[{ts}] {ip} — {alerta[:100]}"
            if texto not in self._alertas_seguranca:
                self._alertas_seguranca.append(texto)

        if self._passa_filtro(dados):
            self._adicionar_cartao(dados)
            self._eventos_filtrados.append(dados)

        self._evento_atual = dados
        self._renderizar_explicacao()
        self._atualizar_rodape()

    def limpar(self):
        """Limpa todos os eventos e reinicia a interface."""
        self._todos_eventos.clear()
        self._eventos_filtrados.clear()
        self._evento_atual = {}
        self._contagem_sessao.clear()
        self.painel_contadores.resetar()

        self.lista_eventos.clear()

        self._limpar_layout_insights()
        self._exibir_mensagem_insights_vazio()

        self._lbl_resumo_insights.setText("Aguardando dados de captura...")
        self._lbl_total_insights.setText("")

        self.lbl_rodape.setText("Nenhum evento registrado.")
        self._exibir_boas_vindas()

        self._ultimo_top_dns      = []
        self._ultimo_historias    = []
        self._ultima_chave_dns          = ""
        self._chave_render_anterior     = ""
        self._ultima_chave_filtro       = None

    # ──────────────────────────────────────────────
    # Filtros
    # ──────────────────────────────────────────────

    @pyqtSlot(str)
    def _ao_mudar_filtro_protocolo(self, valor: str):
        self._filtro_protocolo = valor
        self._reaplicar_filtros()

    @pyqtSlot(str)
    def _ao_mudar_filtro_texto(self, texto: str):
        self._filtro_texto = texto.lower().strip()
        self._reaplicar_filtros()

    def _passa_filtro(self, dados: dict) -> bool:
        if (self._filtro_protocolo and
                self._filtro_protocolo != "Todos" and
                dados.get("tipo", "").upper() != self._filtro_protocolo.upper()):
            return False
        if self._filtro_texto:
            campos = " ".join([
                dados.get("ip_envolvido", ""),
                dados.get("ip_destino",   ""),
                dados.get("titulo",       ""),
                dados.get("nivel1",       ""),
                dados.get("tipo",         ""),
            ]).lower()
            if self._filtro_texto not in campos:
                return False
        return True

    def _reaplicar_filtros(self):
        """
        Reconstrói a lista filtrada.
        Guard de chave — evita reconstrução redundante se nada mudou.
        Exibe apenas os últimos _LIMITE_LISTA_WIDGETS eventos (anti-freeze).
        """
        chave = (
            len(self._todos_eventos),
            self._filtro_protocolo,
            self._filtro_texto,
        )
        if chave == self._ultima_chave_filtro:
            return
        self._ultima_chave_filtro = chave

        self.lista_eventos.clear()

        self._eventos_filtrados = [
            e for e in self._todos_eventos if self._passa_filtro(e)
        ]

        # Renderiza apenas os mais recentes para não criar centenas de widgets
        for evento in self._eventos_filtrados[-_LIMITE_LISTA_WIDGETS:]:
            self._adicionar_cartao(evento)

        self._atualizar_rodape()

        if self._eventos_filtrados:
            self._evento_atual = self._eventos_filtrados[-1]
            self._renderizar_explicacao()
        else:
            self._evento_atual = {}
            self._exibir_boas_vindas()

    def _atualizar_rodape(self):
        total    = len(self._todos_eventos)
        visiveis = len(self._eventos_filtrados)
        self.lbl_rodape.setText(
            f"{visiveis} exibido(s) de {total} total (filtro ativo)."
        )

    # ──────────────────────────────────────────────
    # Cartões e renderização de explicações
    # ──────────────────────────────────────────────

    def _adicionar_cartao(self, dados: dict):
        """
        Adiciona um cartão ao QListWidget.
        Cap de _LIMITE_LISTA_WIDGETS: remove o mais antigo (índice 0)
        com takeItem() — O(1), sem recriar a lista.
        """
        item   = QListWidgetItem()
        widget = CartaoEvento(dados)
        item.setSizeHint(widget.sizeHint())
        self.lista_eventos.addItem(item)
        self.lista_eventos.setItemWidget(item, widget)

        # Remove o mais antigo se ultrapassar o limite (anti-freeze)
        while self.lista_eventos.count() > _LIMITE_LISTA_WIDGETS:
            self.lista_eventos.takeItem(0)

        self.lista_eventos.scrollToBottom()

        dados_ref = dados
        widget.mousePressEvent = lambda _: self._ao_clicar_cartao(dados_ref)

    def _ao_clicar_cartao(self, dados: dict):
        self._evento_atual = dados
        self._renderizar_explicacao()

    def _trocar_nivel(self, nivel: int):
        self._nivel_atual = nivel
        for i, btn in enumerate(self.botoes_nivel):
            btn.setChecked(i == nivel)
        if self._evento_atual:
            self._renderizar_explicacao()

    def _renderizar_explicacao(self):
        """
        Renderiza a explicação pedagógica estruturada do evento atual.
        Cada nível exibe um subconjunto das 6 seções:
          Nível 0 "Análise"       → seções 1 + 2
          Nível 1 "Risco & Dados" → seções 3 + 4
          Nível 2 "Evidências"    → seções 4 + 5 + 6
        """
        if not self._evento_atual or not self._evento_atual.get("titulo"):
            return

        e      = self._evento_atual
        titulo = e.get("titulo", "Evento")
        nivel  = e.get("nivel", "INFO")
        hora   = e.get("timestamp", "")
        ip_src = e.get("ip_envolvido", "")
        ip_dst = e.get("ip_destino", "")
        cont   = e.get("contador", 1)
        cont_s = e.get("contador_sessao", cont)
        fluxo  = e.get("fluxo_visual", "")
        alerta = e.get("alerta_seguranca", "")

        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])
        cor    = estilo["borda"]

        icone_nivel, rotulo_nivel, _ = ROTULOS_NIVEL[self._nivel_atual]

        # Gera o conteúdo das seções para o nível selecionado
        if self._nivel_atual == 0:
            corpo_secoes = self._renderizar_nivel_0(e)
        elif self._nivel_atual == 1:
            corpo_secoes = self._renderizar_nivel_1(e)
        else:
            corpo_secoes = self._renderizar_nivel_2(e)

        ip_linha = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_linha += f" → {ip_dst}"

        # Bloco de fluxo visual
        bloco_fluxo = ""
        if fluxo:
            bloco_fluxo = (
                f"<div style='font-family:Consolas;font-size:10px;"
                f"background:#0d1520;padding:7px 14px;"
                f"border-radius:5px;color:#ecf0f1;margin:8px 0;"
                f"border-left:3px solid {cor};'>"
                f"{fluxo}</div>"
            )

        # Bloco de alerta de segurança (visível em todos os níveis)
        bloco_alerta = ""
        if alerta and self._nivel_atual == 0:
            bloco_alerta = (
                f"<div style='background:#1a0a00;border:1px solid #E74C3C;"
                f"border-radius:5px;padding:8px 14px;margin:8px 0;'>"
                f"<b style='color:#E74C3C;'>⚠ ALERTA DE SEGURANÇA:</b><br>"
                f"<span style='color:#ffb3b3;font-size:10px;'>{alerta}</span>"
                f"</div>"
            )

        html = f"""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;">

          <!-- Cabeçalho do evento -->
          <h3 style="color:{cor};margin:0 0 4px 0;">{titulo}</h3>
          <p style="color:#7f8c8d;font-size:10px;margin:0 0 8px 0;">
             {hora}
            &nbsp;·&nbsp;
            <code style="color:#3498DB;">{ip_linha}</code>
            &nbsp;·&nbsp; Ocorrências: <b>{cont}</b>
            &nbsp;·&nbsp; Sessão: <b>{cont_s}</b>
            &nbsp;·&nbsp;
            <span style="color:{cor};font-size:9px;">{icone_nivel} {rotulo_nivel}</span>
          </p>

          {bloco_fluxo}
          {bloco_alerta}

          <!-- Seções pedagógicas do nível selecionado -->
          {corpo_secoes}

        </div>
        """

        self.texto_explicacao.setHtml(html)

    def _exibir_boas_vindas(self):
        self.texto_explicacao.setHtml("""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.8;color:#ecf0f1;padding:4px;">

          <h3 style="color:#3498DB;margin:0 0 12px 0;">
             Modo Análise — Análise em Tempo Real
          </h3>

          <p style="color:#9fb2c8;">
            Este painel funciona como um <b>analista de redes experiente</b>
            que comenta cada evento à medida que ele ocorre — combinando
            interpretação técnica com ensino aplicado.
          </p>

          <p style="color:#9fb2c8;">
            <b>Como usar:</b><br>
            1. Clique em <b>Iniciar Captura</b> na barra superior<br>
            2. Acesse sites no navegador para gerar tráfego real<br>
            3. Clique em qualquer evento da lista para ver a análise<br>
            4. Use as três abas para navegar pelas 6 seções pedagógicas
          </p>

          <div style="background:#0d1a2a;border:1px solid #1e3a5f;
                      border-radius:6px;padding:12px 16px;margin:10px 0;">
            <b style="color:#3498DB;font-size:10px;">
               Aba "Análise" — Seções 1 e 2
            </b><br>
            <span style="color:#7f8c8d;font-size:10px;">
              O que aconteceu · Por que aconteceu · Como o protocolo funciona
            </span>
          </div>

          <div style="background:#1f1200;border:1px solid #3a2000;
                      border-radius:6px;padding:12px 16px;margin:6px 0;">
            <b style="color:#E67E22;font-size:10px;">
              ⚠ Aba "Risco &amp; Dados" — Seções 3 e 4
            </b><br>
            <span style="color:#7f8c8d;font-size:10px;">
              Superfície de risco · Como a vulnerabilidade ocorre ·
              Evidência observada com interpretação de campos
            </span>
          </div>

          <div style="background:#0a0a1a;border:1px solid #1e1e40;
                      border-radius:6px;padding:12px 16px;margin:6px 0;">
            <b style="color:#9B59B6;font-size:10px;">
               Aba "Evidências" — Seções 4, 5 e 6
            </b><br>
            <span style="color:#7f8c8d;font-size:10px;">
              Dump bruto do pacote · Interpretação operacional ·
              Ação sugerida com justificativa técnica
            </span>
          </div>

          <p style="color:#566573;font-size:10px;margin-top:10px;">
            Acesse a aba <b>Insights</b> para ver os domínios acessados
            e a classificação de uso da rede em tempo real.
          </p>

        </div>
        """)