# interface/painel_eventos.py
# Painel do Modo Análise — v7.0  (redesign visual minimalista)
#
# MUDANÇAS v7.0:
#   - Visual completamente refeito: minimalista, compacto e sem poluição visual
#   - Topbar comprimida (84 px → 68 px) — badges e busca em faixa única quando possível
#   - _ItemWidget reduzido de 68 → 56 px com layout mais denso e limpo
#   - Cabeçalho de detalhe compactado; padding e espaçamentos revistos
#   - Barra de abas 40 → 32 px; rodapé 28 → 24 px
#   - Scrollbar ultra-fina (4 px) com transição suave
#   - resizeEvent adapta padding e texto do rodapé de forma responsiva
#   - API pública idêntica à v6.1 (adicionar_evento, limpar, atualizar_stats)

from collections import defaultdict, deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton,
    QSplitter, QLineEdit, QListWidget, QListWidgetItem,
    QTextBrowser, QSizePolicy,
)
from PyQt6.QtCore import Qt, QSize, QTimer
from PyQt6.QtGui import QColor

from utils.rede import corrigir_mojibake

# ══════════════════════════════════════════════════════════════
# TOKENS DE DESIGN — paleta do NetLab Educacional (v7.0)
# ══════════════════════════════════════════════════════════════

_BG        = "#090d18"
_BG2       = "#0d1120"
_SURFACE   = "#0f1422"
_SURFACE2  = "#131828"
_CARD      = "#0b0f1e"
_BORDA     = "#182038"
_BORDA2    = "#1f2e4a"
_SEL       = "#152f4e"
_ACCENT    = "#3a9ecf"
_ACCENT2   = "#57b2e2"
_TEXTO     = "#d8e4f0"
_TEXTO2    = "#a6bccb"
_MUTED     = "#5f7489"
_DIM       = "#354e63"
_LINHA     = "#111a2b"

_CRITICO   = "#de4f4f"
_AVISO     = "#cf832a"
_INFO      = "#3a9ecf"
_OK        = "#38b578"

# Cores e rótulos por protocolo
_PROTO_COR = {
    "HTTPS":            "#38b578",
    "HTTP":             "#de4f4f",
    "DNS":              "#3a9ecf",
    "ARP":              "#cf832a",
    "ICMP":             "#28b8a8",
    "TCP_SYN":          "#8b69c0",
    "DHCP":             "#1c9c85",
    "SSH":              "#2e6eae",
    "FTP":              "#c44a86",
    "SMB":              "#7a5f42",
    "RDP":              "#d05c28",
    "NOVO_DISPOSITIVO": "#cfa528",
}

_PROTO_LABEL = {
    "HTTPS": "HTTPS", "HTTP": "HTTP",  "DNS": "DNS",
    "ARP":   "ARP",   "ICMP": "ICMP",  "TCP_SYN": "SYN",
    "DHCP":  "DHCP",  "SSH":  "SSH",   "FTP": "FTP",
    "SMB":   "SMB",   "RDP":  "RDP",   "NOVO_DISPOSITIVO": "NOVO",
}

_NIVEL_COR = {
    "CRITICO": _CRITICO,
    "AVISO":   _AVISO,
    "INFO":    _INFO,
}


def _cor(tipo: str) -> str:
    """Retorna a cor associada ao protocolo; fallback para _MUTED."""
    return _PROTO_COR.get(tipo, _MUTED)


def _lbl(tipo: str) -> str:
    """Retorna o rótulo curto do protocolo."""
    return _PROTO_LABEL.get(tipo, tipo[:4] if tipo else "PKT")


def _rgb(hex_c: str) -> tuple[int, int, int]:
    """Converte cor hexadecimal para componentes RGB."""
    c = QColor(hex_c)
    return c.red(), c.green(), c.blue()


# ── Estilo da scrollbar — ultra-fina, discreta ─────────────────
_SCROLL_SS = f"""
    QScrollBar:vertical {{
        background: transparent;
        width: 4px;
        border-radius: 2px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {_BORDA2};
        border-radius: 2px;
        min-height: 20px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {_ACCENT};
    }}
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar::add-page:vertical,
    QScrollBar::sub-page:vertical {{ background: none; }}
"""


# ══════════════════════════════════════════════════════════════
# BADGE DE FILTRO DE PROTOCOLO
# ══════════════════════════════════════════════════════════════

class _Badge(QPushButton):
    """Botão de filtro por protocolo com contagem integrada."""

    def __init__(self, proto: str, parent=None):
        super().__init__(parent)
        self.proto  = proto
        self._count = 0
        self._ativo = (proto == "Todos")
        self.setCheckable(True)
        self.setChecked(self._ativo)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(20)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._sync()
        if proto != "Todos":
            self.hide()

    def set_count(self, n: int):
        self._count = n
        self._sync()
        if self.proto != "Todos":
            self.setVisible(n > 0)

    def set_ativo(self, ativo: bool):
        self._ativo = ativo
        self.setChecked(ativo)
        self._sync()

    def _sync(self):
        label     = _lbl(self.proto) if self.proto != "Todos" else "Todos"
        count_txt = f" {self._count}" if self._count > 0 else ""
        self.setText(f"{label}{count_txt}")

        cor = _cor(self.proto) if self.proto != "Todos" else _ACCENT
        r, g, b = _rgb(cor)

        if self._ativo:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: rgba({r},{g},{b}, 18);
                    color: {cor};
                    border: 1px solid rgba({r},{g},{b}, 70);
                    border-radius: 4px;
                    padding: 1px 10px;
                    font-size: 9px;
                    font-weight: bold;
                    font-family: Consolas, monospace;
                    letter-spacing: 0.4px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {_MUTED};
                    border: 1px solid {_BORDA};
                    border-radius: 4px;
                    padding: 1px 10px;
                    font-size: 9px;
                    font-family: Consolas, monospace;
                    letter-spacing: 0.4px;
                }}
                QPushButton:hover {{
                    color: {_TEXTO2};
                    background: rgba(255,255,255, 4);
                    border-color: {_BORDA2};
                }}
            """)


# ══════════════════════════════════════════════════════════════
# ITEM DA LISTA DE EVENTOS
# ══════════════════════════════════════════════════════════════

class _ItemWidget(QWidget):
    """Widget visual de um evento na lista lateral."""

    HEIGHT = 56  # Reduzido de 68 → 56 px

    def __init__(self, evento: dict, parent=None):
        super().__init__(parent)
        self.evento = evento
        self.setFixedHeight(self.HEIGHT)

        tipo      = evento.get("tipo", "")
        cor       = _cor(tipo)
        r, g, b   = _rgb(cor)
        nivel     = evento.get("nivel", "INFO")
        cor_nivel = _NIVEL_COR.get(nivel, _MUTED)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Faixa colorida lateral (indicador de protocolo)
        faixa = QFrame()
        faixa.setFixedWidth(3)
        faixa.setStyleSheet(f"background: {cor}; border: none;")
        root.addWidget(faixa)

        # Corpo principal do item
        corpo = QWidget()
        corpo.setStyleSheet("background: transparent;")
        cl = QVBoxLayout(corpo)
        cl.setContentsMargins(10, 7, 8, 7)
        cl.setSpacing(3)

        # ── Linha 1: badge de protocolo + IPs ──────────────────
        r1 = QHBoxLayout()
        r1.setSpacing(5)
        r1.setContentsMargins(0, 0, 0, 0)

        badge = QLabel(_lbl(tipo))
        badge.setFixedHeight(15)
        badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(f"""
            background: rgba({r},{g},{b}, 18);
            color: {cor};
            border: 1px solid rgba({r},{g},{b}, 55);
            border-radius: 3px;
            padding: 0 6px;
            font-family: Consolas, monospace;
            font-size: 8px;
            font-weight: bold;
            letter-spacing: 0.4px;
        """)

        # Omite "origem >" quando ip_origem não está disponível (patch v6.1)
        ip_orig = (evento.get("ip_origem") or "").strip()
        ip_dest = (evento.get("ip_destino") or "").strip()

        lbl_dest = QLabel(ip_dest or "—")
        lbl_dest.setStyleSheet(
            f"color: {_ACCENT2}; font-family: Consolas; font-size: 10px; "
            "background: transparent;"
        )

        # Indicador de criticidade
        if nivel in ("CRITICO", "AVISO"):
            dot = QLabel("●")
            dot.setStyleSheet(
                f"color: {cor_nivel}; font-size: 8px; background: transparent;"
            )
            r1.addWidget(dot)

        r1.addWidget(badge)

        if ip_orig and ip_orig != "—":
            lbl_orig = QLabel(ip_orig)
            lbl_orig.setStyleSheet(
                f"color: {_TEXTO}; font-family: Consolas; font-size: 10px; "
                "font-weight: bold; background: transparent;"
            )
            lbl_seta = QLabel("›")
            lbl_seta.setStyleSheet(
                f"color: {_DIM}; font-size: 10px; background: transparent;"
            )
            lbl_seta.setFixedWidth(10)
            r1.addWidget(lbl_orig)
            r1.addWidget(lbl_seta)

        r1.addWidget(lbl_dest)
        r1.addStretch()
        cl.addLayout(r1)

        # ── Linha 2: sub-informação (domínio, caminho, porta…) ─
        sub = (
            evento.get("dominio")
            or evento.get("http_caminho")
            or evento.get("mac_origem")
            or (f":{evento.get('porta_destino')}" if evento.get("porta_destino") else "")
            or ""
        )
        if sub:
            ls = QLabel(str(sub)[:48])
            ls.setStyleSheet(
                f"color: {_MUTED}; font-size: 9px; "
                "font-family: Consolas; background: transparent;"
            )
            cl.addWidget(ls)
        else:
            cl.addStretch()

        root.addWidget(corpo, 1)

        # Timestamp alinhado à direita
        lbl_ts = QLabel(evento.get("timestamp", ""))
        lbl_ts.setFixedWidth(46)
        lbl_ts.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight)
        lbl_ts.setStyleSheet(
            f"color: {_DIM}; font-family: Consolas; font-size: 8px; "
            f"padding-right: 10px; background: transparent;"
        )
        root.addWidget(lbl_ts)


# ══════════════════════════════════════════════════════════════
# SEPARADOR DE SEÇÃO
# ══════════════════════════════════════════════════════════════

class _SecaoHeader(QWidget):
    """Cabeçalho compacto de seção com linha divisória."""

    def __init__(self, titulo: str, cor: str = _MUTED, parent=None):
        super().__init__(parent)
        self.setFixedHeight(24)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        lbl = QLabel(titulo)
        lbl.setStyleSheet(f"""
            color: {cor};
            font-size: 8px;
            font-weight: bold;
            font-family: 'Segoe UI', Arial, sans-serif;
            letter-spacing: 1.8px;
            background: transparent;
        """)
        lbl.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        lay.addWidget(lbl)

        linha = QFrame()
        linha.setFrameShape(QFrame.Shape.HLine)
        linha.setStyleSheet(f"background: {_BORDA}; border: none; max-height: 1px;")
        lay.addWidget(linha, 1)


# ══════════════════════════════════════════════════════════════
# GRID DE METADADOS
# ══════════════════════════════════════════════════════════════

# Valores considerados "sem informação" — linhas com esses valores são omitidas
_META_SKIP = frozenset({
    "—", "", "none", "0 bytes", "0",
    "não extraído neste pacote", "não extraído",
})


class _MetaGrid(QFrame):
    """Grade de metadados chave/valor com filtragem de valores vazios."""

    def __init__(self, campos: list, parent=None):
        """campos: lista de (rotulo, valor, cor_valor_opcional)"""
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background: {_CARD};
                border: 1px solid {_BORDA};
                border-radius: 6px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Filtra linhas sem valor (patch v6.1)
        campos = [
            c for c in campos
            if str(c[1]).strip().lower() not in _META_SKIP
        ]

        for i, campo in enumerate(campos):
            rot   = campo[0]
            val   = campo[1]
            cor_v = campo[2] if len(campo) > 2 else _TEXTO

            linha = QFrame()
            borda_b = f"border-bottom: 1px solid {_LINHA};" if i < len(campos) - 1 else ""
            linha.setStyleSheet(f"QFrame {{ {borda_b} background: transparent; }}")
            ll = QHBoxLayout(linha)
            ll.setContentsMargins(14, 7, 14, 7)
            ll.setSpacing(10)

            lr = QLabel(rot)
            lr.setFixedWidth(110)
            lr.setStyleSheet(
                f"color: {_MUTED}; font-size: 9px; background: transparent;"
            )

            lv = QLabel(str(val))
            lv.setStyleSheet(
                f"color: {cor_v}; font-family: Consolas; "
                f"font-size: 9px; background: transparent;"
            )
            lv.setWordWrap(True)

            ll.addWidget(lr)
            ll.addWidget(lv, 1)
            lay.addWidget(linha)


# ══════════════════════════════════════════════════════════════
# PAINEL PRINCIPAL — PainelEventos
# ══════════════════════════════════════════════════════════════

class PainelEventos(QWidget):
    """
    Painel do Modo Análise do NetLab Educacional.

    API pública:
      adicionar_evento(e: dict)          — insere novo evento
      limpar()                           — reseta o painel
      atualizar_stats(pacotes, rede, dados) — atualiza rodapé
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self._todos_eventos = deque(maxlen=1500)  # Armazena eventos completos para filtragem
        self._evento_atual  = None
        self._filtro_proto  = "Todos"
        self._filtro_texto  = ""
        self._aba_ativa     = "analise"
        self._badges        = {}
        self._contadores    = defaultdict(int)
        self._item_map      = []
        self._stats_cache   = {"pacotes": 0, "rede": "—", "dados": "0 B"}

        # Timer de debounce para a busca (evita filtrar a cada tecla)
        self._timer_busca = QTimer(self)
        self._timer_busca.setSingleShot(True)
        self._timer_busca.setInterval(100)
        self._timer_busca.timeout.connect(self._filtrar)

        self._montar_layout()

        # Exibe a tela de boas-vindas no estado inicial
        QTimer.singleShot(0, self._renderizar_boas_vindas)

    # ─────────────────────────────────────────────────────────
    # MONTAGEM DO LAYOUT PRINCIPAL
    # ─────────────────────────────────────────────────────────

    def _montar_layout(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._mk_topbar())

        # Divisor horizontal: lista (esq) | detalhe (dir)
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(1)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {_BORDA}; }}"
        )
        self._splitter.addWidget(self._mk_painel_lista())
        self._splitter.addWidget(self._mk_painel_detalhe())
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 3)

        root.addWidget(self._splitter, 1)
        root.addWidget(self._mk_rodape())

    # ─────────────────────────────────────────────────────────
    # TOPBAR (compacta — 2 faixas de 34 + 34 = 68 px total)
    # ─────────────────────────────────────────────────────────

    def _mk_topbar(self) -> QWidget:
        container = QFrame()
        container.setStyleSheet("QFrame { background: transparent; }")
        v = QVBoxLayout(container)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # ── Faixa 1: título + contador + busca ─────────────────
        linha1 = QFrame()
        linha1.setFixedHeight(40)
        linha1.setStyleSheet(
            f"QFrame {{ background: {_SURFACE}; "
            f"border-bottom: 1px solid {_BORDA}; }}"
        )
        l1 = QHBoxLayout(linha1)
        l1.setContentsMargins(16, 0, 14, 0)
        l1.setSpacing(10)

        lbl_titulo = QLabel("MODO ANÁLISE")
        lbl_titulo.setStyleSheet(f"""
            color: {_TEXTO2};
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 2px;
            font-family: 'Segoe UI', Arial, sans-serif;
        """)
        l1.addWidget(lbl_titulo)

        l1.addStretch()

        # Campo de busca com largura responsiva
        self._campo_busca = QLineEdit()
        self._campo_busca.setPlaceholderText("Buscar IP, domínio, protocolo…")
        self._campo_busca.setMinimumWidth(180)
        self._campo_busca.setMaximumWidth(300)
        self._campo_busca.setFixedHeight(26)
        self._campo_busca.setStyleSheet(f"""
            QLineEdit {{
                background: {_CARD};
                border: 1px solid {_BORDA};
                border-radius: 5px;
                color: {_TEXTO};
                padding: 0 10px;
                font-size: 10px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
            QLineEdit:focus {{
                border-color: {_ACCENT};
                background: {_BG2};
            }}
            QLineEdit::placeholder {{ color: {_DIM}; }}
        """)
        self._campo_busca.textChanged.connect(self._ao_busca_mudou)
        l1.addWidget(self._campo_busca)

        # Botão para limpar a busca
        self._btn_limpar_busca = QPushButton("✕")
        self._btn_limpar_busca.setFixedSize(20, 20)
        self._btn_limpar_busca.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_limpar_busca.setVisible(False)
        self._btn_limpar_busca.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {_MUTED};
                border: none;
                border-radius: 10px;
                font-size: 9px;
            }}
            QPushButton:hover {{
                background: {_BORDA};
                color: {_TEXTO};
            }}
        """)
        self._btn_limpar_busca.clicked.connect(self._campo_busca.clear)
        l1.addWidget(self._btn_limpar_busca)

        v.addWidget(linha1)

        # ── Faixa 2: badges de protocolo + contador de filtro ──
        linha2 = QFrame()
        linha2.setFixedHeight(28)
        linha2.setStyleSheet(
            f"QFrame {{ background: {_SURFACE2}; "
            f"border-bottom: 1px solid {_BORDA}; }}"
        )
        l2 = QHBoxLayout(linha2)
        l2.setContentsMargins(16, 0, 14, 0)
        l2.setSpacing(4)

        protos = [
            "Todos", "HTTPS", "HTTP", "DNS", "ARP",
            "ICMP", "TCP_SYN", "DHCP", "SSH", "FTP", "SMB", "RDP",
        ]
        for proto in protos:
            b = _Badge(proto)
            b.clicked.connect(lambda _, p=proto: self._ao_badge(p))
            self._badges[proto] = b
            l2.addWidget(b)

        l2.addStretch()

        self._lbl_contagem = QLabel("0 / 0")
        self._lbl_contagem.setStyleSheet(
            f"color: {_DIM}; font-family: Consolas; font-size: 9px;"
        )
        l2.addWidget(self._lbl_contagem)

        v.addWidget(linha2)
        return container

    # ─────────────────────────────────────────────────────────
    # PAINEL ESQUERDO: lista de eventos
    # ─────────────────────────────────────────────────────────

    def _mk_painel_lista(self) -> QWidget:
        frame = QFrame()
        frame.setMinimumWidth(220)
        frame.setMaximumWidth(340)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_BG2};
                border-right: 1px solid {_BORDA};
            }}
        """)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self._lista = QListWidget()
        self._lista.setStyleSheet(f"""
            QListWidget {{
                background: {_BG2};
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                border-bottom: 1px solid {_BORDA};
                padding: 0;
                background: transparent;
            }}
            QListWidget::item:selected {{
                background: {_SEL};
            }}
            QListWidget::item:hover:!selected {{
                background: rgba(255,255,255, 3);
            }}
            {_SCROLL_SS}
        """)
        self._lista.setUniformItemSizes(True)
        self._lista.itemSelectionChanged.connect(self._ao_selecionar)
        lay.addWidget(self._lista)
        return frame

    # ─────────────────────────────────────────────────────────
    # PAINEL DIREITO: detalhe do evento
    # ─────────────────────────────────────────────────────────

    def _mk_painel_detalhe(self) -> QWidget:
        frame = QFrame()
        frame.setStyleSheet(f"QFrame {{ background: {_BG}; }}")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        lay.addWidget(self._mk_header_detalhe())
        lay.addWidget(self._mk_barra_abas())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            f"QScrollArea {{ border: none; background: {_BG}; }}{_SCROLL_SS}"
        )

        self._conteudo = QWidget()
        self._conteudo.setStyleSheet(f"background: {_BG};")
        self._lay_c = QVBoxLayout(self._conteudo)
        self._lay_c.setContentsMargins(20, 16, 20, 20)
        self._lay_c.setSpacing(12)
        self._lay_c.addStretch()

        scroll.setWidget(self._conteudo)
        lay.addWidget(scroll, 1)
        return frame

    def _renderizar_boas_vindas(self):
        """Tela inicial exibida antes de qualquer evento ser selecionado."""
        while self._lay_c.count() > 1:
            it = self._lay_c.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

        # Reset cabeçalho
        self._det_badge.setText("—")
        self._det_badge.setStyleSheet(f"""
            color: {_MUTED}; border: 1px solid {_BORDA}; border-radius: 3px;
            padding: 1px 10px; font-family: Consolas, monospace;
            font-size: 9px; font-weight: bold;
        """)
        self._det_titulo.setText("Modo Análise")
        self._det_ts.setText("")
        self._det_resumo.setText("Selecione um evento na lista para ver a análise detalhada")
        self._lbl_status.setText("Aguardando seleção")

        css = f"""
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11px;
                color: {_TEXTO};
                line-height: 1.75;
                margin: 0; padding: 0;
                background: {_BG};
            }}
            b {{ color: {_ACCENT2}; font-weight: 600; }}
            code {{
                font-family: Consolas, monospace; font-size: 10px;
                background: rgba(58,158,207,0.10); color: {_ACCENT2};
                padding: 1px 4px; border-radius: 3px;
            }}
            .bloco {{
                border: 1px solid {_BORDA2};
                border-radius: 8px;
                padding: 14px 16px;
                margin: 0 0 12px 0;
                background: rgba(255,255,255,0.02);
            }}
            .titulo-bloco {{
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 1.4px;
                text-transform: uppercase;
                color: {_MUTED};
                margin-bottom: 10px;
            }}
            .aba {{
                display: inline-block;
                border: 1px solid {_BORDA2};
                border-radius: 4px;
                padding: 3px 10px;
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 0.6px;
                margin-right: 6px;
                color: {_TEXTO2};
            }}
            .proto {{
                display: inline-block;
                border-radius: 4px;
                padding: 2px 8px;
                font-family: Consolas, monospace;
                font-size: 9px;
                font-weight: bold;
                margin: 2px 3px 2px 0;
            }}
            .linha {{
                display: flex;
                align-items: flex-start;
                gap: 10px;
                margin: 6px 0;
                font-size: 11px;
            }}
            .dot {{
                min-width: 6px; height: 6px;
                border-radius: 50%;
                margin-top: 5px;
            }}
        """

        html = f"""
        <style>{css}</style>
        <body>
        <div style="padding: 4px 0 20px 0;">

          <div style="
            margin-bottom: 20px;
            padding: 18px 20px;
            border: 1px solid rgba(58,158,207,0.22);
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(58,158,207,0.07), rgba(58,158,207,0.02));
          ">
            <div style="font-size:13px; font-weight:600; color:{_TEXTO}; margin-bottom:6px;">
              Como usar o Modo Análise
            </div>
            <div style="color:{_TEXTO2}; font-size:11px; line-height:1.7;">
              Cada pacote capturado gera um <b>evento</b> na lista à esquerda.
              Clique em qualquer evento para ver uma explicação detalhada sobre
              o que aconteceu, como o protocolo funciona e o que significa
              do ponto de vista de segurança.
            </div>
          </div>

          <div class="bloco">
            <div class="titulo-bloco">As três abas de análise</div>
            <div class="linha">
              <span class="aba" style="border-color:rgba(58,158,207,0.5); color:{_ACCENT};">ANÁLISE</span>
              <span style="color:{_TEXTO2};">O que aconteceu e por quê — explicação em linguagem acessível, com contexto de segurança quando relevante.</span>
            </div>
            <div class="linha">
              <span class="aba">EVIDÊNCIAS</span>
              <span style="color:{_TEXTO2};">Campos técnicos do pacote capturado: IPs, portas, MAC, tamanho, headers HTTP e campos de formulário.</span>
            </div>
            <div class="linha">
              <span class="aba">NA PRÁTICA</span>
              <span style="color:{_TEXTO2};">Significado operacional do protocolo e o que fazer — comandos de diagnóstico, boas práticas e vetores de ataque.</span>
            </div>
          </div>

          <div class="bloco">
            <div class="titulo-bloco">Filtros por protocolo</div>
            <div style="margin-bottom: 8px; color:{_TEXTO2}; font-size:11px;">
              Use os badges no topo da lista para filtrar por tipo de tráfego:
            </div>
            <div>
              <span class="proto" style="background:rgba(56,181,120,0.15); color:#38b578; border:1px solid rgba(56,181,120,0.3);">HTTPS</span>
              <span class="proto" style="background:rgba(222,79,79,0.15); color:#de4f4f; border:1px solid rgba(222,79,79,0.3);">HTTP</span>
              <span class="proto" style="background:rgba(58,158,207,0.15); color:{_ACCENT}; border:1px solid rgba(58,158,207,0.3);">DNS</span>
              <span class="proto" style="background:rgba(207,131,42,0.15); color:#cf832a; border:1px solid rgba(207,131,42,0.3);">ARP</span>
              <span class="proto" style="background:rgba(40,184,168,0.15); color:#28b8a8; border:1px solid rgba(40,184,168,0.3);">ICMP</span>
              <span class="proto" style="background:rgba(139,105,192,0.15); color:#8b69c0; border:1px solid rgba(139,105,192,0.3);">SYN</span>
              <span class="proto" style="background:rgba(28,156,133,0.15); color:#1c9c85; border:1px solid rgba(28,156,133,0.3);">DHCP</span>
            </div>
          </div>

          <div class="bloco">
            <div class="titulo-bloco">Níveis de alerta</div>
            <div class="linha">
              <div class="dot" style="background:{_INFO};"></div>
              <span><b style="color:{_INFO};">INFO</b> — atividade normal de rede; conteúdo educativo sobre o protocolo.</span>
            </div>
            <div class="linha">
              <div class="dot" style="background:#cf832a;"></div>
              <span><b style="color:#cf832a;">AVISO</b> — protocolo intrinsecamente inseguro em uso (FTP, RDP, SMB) ou dado que merece atenção.</span>
            </div>
            <div class="linha">
              <div class="dot" style="background:{_CRITICO};"></div>
              <span><b style="color:{_CRITICO};">CRÍTICO</b> — evidência real de dado sensível exposto: credenciais, tokens ou padrão de ataque detectado.</span>
            </div>
          </div>

          <div style="
            padding: 12px 16px;
            border-radius: 8px;
            background: rgba(255,255,255,0.02);
            border: 1px dashed {_BORDA};
            color: {_MUTED};
            font-size: 10px;
            line-height: 1.6;
          ">
            Use a <b style="color:{_TEXTO2};">busca</b> no topo para filtrar por IP, domínio ou protocolo.
            Duplo clique em um evento HTTP abre o payload completo com hexdump.
            O histórico é preservado enquanto a captura estiver ativa.
          </div>

        </div>
        </body>
        """

        tb = QTextBrowser()
        tb.setOpenExternalLinks(False)
        tb.setHtml(html)
        tb.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        tb.setStyleSheet(f"""
            QTextBrowser {{
                background: {_BG};
                border: none;
                padding: 0;
                color: {_TEXTO};
            }}
            {_SCROLL_SS}
        """)
        self._lay_c.insertWidget(0, tb)

    def _mk_header_detalhe(self) -> QFrame:
        """Cabeçalho compacto do painel de detalhe."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_SURFACE};
                border-bottom: 1px solid {_BORDA};
            }}
        """)
        frame.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
        )

        lay = QVBoxLayout(frame)
        lay.setContentsMargins(20, 10, 20, 10)
        lay.setSpacing(4)

        r1 = QHBoxLayout()
        r1.setSpacing(10)
        r1.setContentsMargins(0, 0, 0, 0)

        # Badge do protocolo
        self._det_badge = QLabel("—")
        self._det_badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._det_badge.setFixedHeight(18)
        self._det_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._det_badge.setStyleSheet(f"""
            color: {_MUTED};
            border: 1px solid {_BORDA};
            border-radius: 3px;
            padding: 1px 10px;
            font-family: Consolas, monospace;
            font-size: 9px;
            font-weight: bold;
        """)

        self._det_titulo = QLabel("Selecione um evento na lista")
        self._det_titulo.setWordWrap(False)
        self._det_titulo.setStyleSheet(f"""
            font-size: 12px;
            font-weight: bold;
            color: {_TEXTO};
            font-family: Consolas, monospace;
            background: transparent;
        """)
        self._det_titulo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )

        self._det_ts = QLabel("")
        self._det_ts.setStyleSheet(
            f"color: {_MUTED}; font-family: Consolas; font-size: 9px; "
            "background: transparent;"
        )
        self._det_ts.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        r1.addWidget(self._det_badge)
        r1.addWidget(self._det_titulo, 1)
        r1.addWidget(self._det_ts)
        lay.addLayout(r1)

        self._det_resumo = QLabel("")
        self._det_resumo.setStyleSheet(
            f"color: {_MUTED}; font-family: Consolas; font-size: 9px; "
            "background: transparent;"
        )
        lay.addWidget(self._det_resumo)

        return frame

    def _mk_barra_abas(self) -> QFrame:
        """Barra de abas compacta: Análise / Evidências / Na Prática."""
        frame = QFrame()
        frame.setFixedHeight(32)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_SURFACE2};
                border-bottom: 1px solid {_BORDA};
            }}
        """)
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(2)

        self._btn_analise    = self._mk_btn_aba("ANÁLISE",    "analise",   True)
        self._btn_evidencias = self._mk_btn_aba("EVIDÊNCIAS", "evidencias")
        self._btn_pratica    = self._mk_btn_aba("NA PRÁTICA", "pratica")

        lay.addWidget(self._btn_analise)
        lay.addWidget(self._btn_evidencias)
        lay.addWidget(self._btn_pratica)
        lay.addStretch()
        return frame

    def _mk_btn_aba(self, texto: str, id_aba: str, ativo: bool = False) -> QPushButton:
        btn = QPushButton(texto)
        btn.setCheckable(True)
        btn.setChecked(ativo)
        btn.setFixedHeight(32)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._aplicar_estilo_aba(btn, ativo)
        btn.clicked.connect(lambda: self._trocar_aba(id_aba))
        return btn

    def _aplicar_estilo_aba(self, btn: QPushButton, ativo: bool):
        cor_txt = _TEXTO if ativo else _MUTED
        borda_b = _ACCENT if ativo else "transparent"
        bg      = "rgba(58, 158, 207, 0.07)" if ativo else "transparent"
        peso    = "600" if ativo else "normal"
        hover   = (
            f"QPushButton:hover {{ color: {_TEXTO2}; background: rgba(255,255,255,3); }}"
            if not ativo else ""
        )
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {cor_txt};
                border: none;
                border-bottom: 2px solid {borda_b};
                border-radius: 0;
                padding: 0 16px;
                font-size: 9px;
                font-weight: {peso};
                letter-spacing: 0.8px;
                font-family: 'Segoe UI', Arial, sans-serif;
                margin-bottom: -1px;
            }}
            {hover}
        """)

    # ─────────────────────────────────────────────────────────
    # RODAPÉ
    # ─────────────────────────────────────────────────────────

    def _mk_rodape(self) -> QFrame:
        frame = QFrame()
        frame.setFixedHeight(24)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_SURFACE};
                border-top: 1px solid {_BORDA};
            }}
        """)
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(0)

        self._lbl_status = QLabel("Aguardando captura")
        self._lbl_status.setStyleSheet(
            f"color: {_MUTED}; font-size: 9px;"
        )

        self._lbl_stats = QLabel("Rede: — | Pacotes: 0 | Dados: 0 B")
        self._lbl_stats.setMinimumWidth(0)
        self._lbl_stats.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )
        self._lbl_stats.setWordWrap(False)
        self._lbl_stats.setStyleSheet(
            f"color: {_DIM}; font-family: Consolas; font-size: 9px;"
        )

        lay.addWidget(self._lbl_status)
        lay.addStretch()
        lay.addWidget(self._lbl_stats)
        return frame

    # ─────────────────────────────────────────────────────────
    # FILTROS
    # ─────────────────────────────────────────────────────────

    def _ao_busca_mudou(self, texto: str):
        self._filtro_texto = texto.lower().strip()
        self._btn_limpar_busca.setVisible(bool(texto))
        self._timer_busca.start()

    def _ao_badge(self, proto: str):
        self._filtro_proto = proto
        for p, b in self._badges.items():
            b.set_ativo(p == proto)
        self._filtrar()

    def _passa(self, e: dict) -> bool:
        """Retorna True se o evento passa pelos filtros ativos."""
        if self._filtro_proto != "Todos" and e.get("tipo", "") != self._filtro_proto:
            return False
        if self._filtro_texto:
            campo = " ".join([
                e.get("ip_origem",  ""),
                e.get("ip_destino", ""),
                e.get("titulo",     ""),
                e.get("dominio",    ""),
                e.get("tipo",       ""),
            ]).lower()
            if self._filtro_texto not in campo:
                return False
        return True

    def _filtrar(self):
        visiveis = 0
        self._lista.setUpdatesEnabled(False)
        try:
            for evento, item, _ in self._item_map:
                visivel = self._passa(evento)
                item.setHidden(not visivel)
                if visivel:
                    visiveis += 1
        finally:
            self._lista.setUpdatesEnabled(True)

        total = len(self._todos_eventos)
        self._lbl_contagem.setText(f"{visiveis} / {total}")

    # ─────────────────────────────────────────────────────────
    # INSERÇÃO DE ITENS NA LISTA
    # ─────────────────────────────────────────────────────────

    def _inserir_item(self, evento: dict):
        widget = _ItemWidget(evento)
        item   = QListWidgetItem()
        item.setSizeHint(QSize(220, _ItemWidget.HEIGHT))
        self._lista.addItem(item)
        self._lista.setItemWidget(item, widget)
        self._item_map.append((evento, item, widget))
        if not self._passa(evento):
            item.setHidden(True)
        self._lista.scrollToBottom()

    def _ao_selecionar(self):
        items = self._lista.selectedItems()
        if not items:
            return
        row = self._lista.row(items[0])
        if 0 <= row < len(self._item_map):
            self._evento_atual = self._item_map[row][0]
            self._renderizar()

    # ─────────────────────────────────────────────────────────
    # RENDERIZAÇÃO DO DETALHE
    # ─────────────────────────────────────────────────────────

    def _trocar_aba(self, id_aba: str):
        self._aba_ativa = id_aba
        mapa = [
            (self._btn_analise,    "analise"),
            (self._btn_evidencias, "evidencias"),
            (self._btn_pratica,    "pratica"),
        ]
        for btn, tid in mapa:
            ativo = (tid == id_aba)
            btn.setChecked(ativo)
            self._aplicar_estilo_aba(btn, ativo)
        self._renderizar()

    def _renderizar(self):
        e = self._evento_atual
        if not e:
            return

        tipo    = e.get("tipo", "")
        cor     = _cor(tipo)
        nivel   = e.get("nivel", "INFO")
        r, g, b = _rgb(cor)

        # Atualiza badge de protocolo no cabeçalho
        self._det_badge.setText(_lbl(tipo))
        self._det_badge.setStyleSheet(f"""
            background: rgba({r},{g},{b}, 18);
            color: {cor};
            border: 1px solid rgba({r},{g},{b}, 55);
            border-radius: 3px;
            padding: 1px 10px;
            font-family: Consolas, monospace;
            font-size: 9px;
            font-weight: bold;
        """)

        titulo = (
            e.get("dominio")
            or e.get("titulo")
            or f"{e.get('ip_origem', '')} → {e.get('ip_destino', '')}"
        )
        if len(str(titulo)) > 72:
            titulo = str(titulo)[:70] + "…"
        self._det_titulo.setText(str(titulo))
        self._det_ts.setText(e.get("timestamp", ""))

        # Linha de resumo compacta
        partes = []
        if e.get("ip_origem"):
            partes.append(e["ip_origem"])
        if e.get("ip_destino"):
            partes.append(f"› {e['ip_destino']}")
        if e.get("tamanho"):
            partes.append(f"· {e['tamanho']} bytes")
        if nivel in ("CRITICO", "AVISO"):
            cor_n = _NIVEL_COR.get(nivel, _MUTED)
            partes.append(f'<span style="color:{cor_n};">● {nivel}</span>')

        self._det_resumo.setText("   ".join(partes) if partes else "")
        self._lbl_status.setText(
            f"{tipo}  —  {e.get('ip_origem', '')} › {e.get('ip_destino', '')}"
        )

        # Limpa o conteúdo anterior (mantém o stretch no final)
        while self._lay_c.count() > 1:
            it = self._lay_c.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

        if self._aba_ativa == "analise":
            self._aba_analise(e)
        elif self._aba_ativa == "evidencias":
            self._aba_evidencias(e)
        else:
            self._aba_pratica(e)

    # ─────────────────────────────────────────────────────────
    # HELPERS DE CONTEÚDO
    # ─────────────────────────────────────────────────────────

    _CSS_BASE = f"""
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 11px;
            color: {_TEXTO};
            line-height: 1.70;
            margin: 0;
            padding: 0;
            background: {_CARD};
        }}
        b {{ color: {_ACCENT2}; font-weight: 600; }}
        code {{
            font-family: Consolas, monospace;
            font-size: 10px;
            background: rgba(58,158,207,0.10);
            color: {_ACCENT2};
            padding: 1px 4px;
            border-radius: 3px;
        }}
        p {{ margin: 6px 0; }}
    """

    def _browser(
        self,
        html: str,
        min_h: int = 60,
        max_h: int = 500,
    ) -> QTextBrowser:
        """Cria um QTextBrowser estilizado para exibição de HTML formatado."""
        tb = QTextBrowser()
        tb.setOpenExternalLinks(False)
        tb.setHtml(html)
        tb.setMinimumHeight(min_h)
        tb.setMaximumHeight(max_h)
        tb.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        tb.setStyleSheet(f"""
            QTextBrowser {{
                background: {_CARD};
                border: 1px solid {_BORDA};
                border-radius: 6px;
                padding: 12px 14px;
                color: {_TEXTO};
                selection-background-color: {_SEL};
            }}
            {_SCROLL_SS}
        """)
        return tb

    def _inserir_secao(
        self,
        titulo: str,
        widget: QWidget,
        cor: str,
        pos: int,
    ):
        """Insere cabeçalho de seção + widget de conteúdo no layout de detalhe."""
        self._lay_c.insertWidget(pos * 2,     _SecaoHeader(titulo, cor))
        self._lay_c.insertWidget(pos * 2 + 1, widget)

    # ─────────────────────────────────────────────────────────
    # CONTEÚDO DAS ABAS
    # ─────────────────────────────────────────────────────────

    def _aba_analise(self, e: dict):
        pos = 0

        # ── O QUE ACONTECEU ─────────────────────────────────
        n1 = e.get("nivel1", "")
        n2 = e.get("nivel2", "")
        if n1 or n2:
            html_o = (
                f"<style>{self._CSS_BASE}</style><body>"
                f"{n1}"
                f"{'<p>' + n2 + '</p>' if n2 else ''}"
                "</body>"
            )
            self._inserir_secao(
                "O QUE ACONTECEU",
                self._browser(html_o, 60, 300),
                _MUTED,
                pos,
            )
            pos += 1

        # ── COMO FUNCIONA (gerado dinamicamente com dados reais) ──
        html_cf = self._gerar_html_como_funciona(e)
        self._inserir_secao(
            "COMO FUNCIONA",
            self._browser(html_cf, 80, 420),
            _MUTED,
            pos,
        )
        pos += 1

        # ── ALERTA DE SEGURANÇA (nível CRITICO ou AVISO) ─────
        alerta = e.get("alerta_seguranca", "")
        nivel  = e.get("nivel", "INFO")
        if alerta and nivel in ("CRITICO", "AVISO"):
            cor_al = _NIVEL_COR.get(nivel, _MUTED)
            r2, g2, b2 = _rgb(cor_al)

            def _bloco_alerta(txt: str, cor_a: str) -> QFrame:
                f = QFrame()
                f.setStyleSheet(f"""
                    QFrame {{
                        background: rgba({r2},{g2},{b2}, 10);
                        border: 1px solid rgba({r2},{g2},{b2}, 40);
                        border-radius: 6px;
                    }}
                """)
                ll = QHBoxLayout(f)
                ll.setContentsMargins(12, 10, 12, 10)
                lbl = QLabel(txt)
                lbl.setWordWrap(True)
                lbl.setStyleSheet(
                    f"color: {cor_a}; font-size: 10px; background: transparent;"
                )
                ll.addWidget(lbl)
                return f

            self._inserir_secao(
                f"ALERTA — {nivel}",
                _bloco_alerta(alerta, cor_al),
                cor_al,
                pos,
            )

    # ─────────────────────────────────────────────────────────
    # GERADOR DIDÁTICO DE "COMO FUNCIONA"
    # ─────────────────────────────────────────────────────────

    def _gerar_html_como_funciona(self, e: dict) -> str:
        """
        Gera HTML educativo e contextualizado para a seção 'Como Funciona',
        usando os dados reais do evento capturado (IPs, portas, domínio, tamanho).

        Cada protocolo tem sua própria explicação passo a passo, conectando
        o que foi capturado ao mecanismo técnico subjacente.
        """
        tipo   = e.get("tipo", "")
        orig   = e.get("ip_origem",  "?")
        dest   = e.get("ip_destino", "?")
        porta  = e.get("porta_destino", "")
        tam    = e.get("tamanho", 0) or 0
        dom    = e.get("dominio", "")
        mac    = e.get("mac_origem", "")
        tam_s  = f"{tam} bytes" if tam else "—"

        # Endereço destino formatado com porta quando disponível
        dest_porta = f"{dest}:{porta}" if porta else dest

        # ── Helpers de formatação HTML ──────────────────────

        def ip(val: str) -> str:
            """Formata um IP/hostname com destaque monoespaçado."""
            return f'<code>{val}</code>'

        def passo(numero: str, titulo_passo: str, corpo: str) -> str:
            """Renderiza um passo numerado do fluxo do protocolo."""
            return (
                f'<div style="display:flex;gap:10px;margin:6px 0;">'
                f'<span style="color:{_DIM};font-family:Consolas;font-size:10px;'
                f'min-width:18px;padding-top:1px;">{numero}</span>'
                f'<div><b style="color:{_TEXTO2}">{titulo_passo}</b>'
                f'<span style="color:{_TEXTO2}"> — </span>{corpo}</div>'
                f'</div>'
            )

        def linha_dados(rotulo: str, valor: str, cor_val: str = _ACCENT2) -> str:
            """Renderiza uma linha de dado capturado (chave: valor)."""
            return (
                f'<div style="margin:2px 0;">'
                f'<span style="color:{_MUTED}">{rotulo}:</span> '
                f'<code style="color:{cor_val}">{valor}</code>'
                f'</div>'
            )

        def caixa_captura(linhas: list[str]) -> str:
            """Renderiza uma caixa com os dados reais capturados pelo sniffer."""
            conteudo = "".join(linhas)
            return (
                f'<div style="background:rgba(0,0,0,0.25);border:1px solid {_BORDA2};'
                f'border-radius:5px;padding:8px 12px;margin:10px 0 4px;">'
                f'<div style="color:{_DIM};font-size:9px;letter-spacing:1px;'
                f'margin-bottom:6px;">CAPTURADO NESTE PACOTE</div>'
                f'{conteudo}'
                f'</div>'
            )

        def aviso(txt: str, cor_av: str = _AVISO) -> str:
            """Renderiza um aviso contextual."""
            return (
                f'<div style="border-left:2px solid {cor_av};padding:4px 0 4px 10px;'
                f'margin:10px 0 0;color:{_TEXTO2};">{txt}</div>'
            )

        def nao_ve(txt: str) -> str:
            """Indica o que o sniffer NÃO consegue ver."""
            return (
                f'<div style="margin-top:8px;color:{_DIM};font-size:10px;">'
                f'<span style="color:{_OK}">✓</span> {txt}</div>'
            )

        # ══════════════════════════════════════════════════════
        # CONTEÚDO POR PROTOCOLO
        # ══════════════════════════════════════════════════════

        conteudo = ""

        if tipo == "HTTPS":
            sni_info = (
                f' O SNI enviado no ClientHello identifica o serviço como {ip(dom)}.'
                if dom else
                ' Nenhum SNI capturado neste pacote (pode ser pacote de dados, não o handshake).'
            )
            conteudo = (
                passo("Passo 1", "TCP Handshake",
                      f'{ip(orig)} envia SYN para {ip(dest_porta)}. '
                      f'O servidor responde SYN-ACK e a conexão TCP é estabelecida.')
                + passo("Passo 2", "TLS ClientHello",
                        f'O cliente anuncia as cifras suportadas e envia o '
                        f'<b>SNI (Server Name Indication)</b> — único campo visível ao sniffer.'
                        + sni_info)
                + passo("Passo 3", "Troca de chaves ECDHE",
                        f'Cliente e servidor derivam uma chave de sessão efêmera. '
                        f'Com <b>Perfect Forward Secrecy</b>, nem a chave privada do servidor '
                        f'decripta sessões passadas.')
                + passo("Passo 4", "Dados cifrados",
                        f'URL, headers, cookies e corpo trafegam completamente opacos. '
                        f'O sniffer só enxerga IPs, porta e tamanho dos pacotes.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("SNI visível", dom or "não capturado neste pacote", _ACCENT2),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + nao_ve("URL, cookies, credenciais e corpo da resposta estão cifrados pelo TLS.")
            )

        elif tipo == "HTTP":
            conteudo = (
                passo("Passo 1", "Requisição em texto puro",
                      f'{ip(orig)} envia GET/POST para {ip(dest_porta)} sem nenhuma criptografia. '
                      f'Método, URL, headers e corpo são completamente legíveis na rede.')
                + passo("Passo 2", "Dados expostos",
                        f'Qualquer dispositivo na mesma rede que capture este tráfego consegue ler '
                        f'credenciais, cookies de sessão, formulários e o conteúdo das páginas.')
                + passo("Passo 3", "Resposta do servidor",
                        f'Status HTTP (200 OK, 404, etc.), headers de resposta e corpo '
                        f'também trafegam em texto puro de volta para {ip(orig)}.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                    linha_dados("Cifrado", "NÃO — tráfego legível", _CRITICO),
                ])
                + aviso(
                    '<b>Risco crítico:</b> credenciais e cookies transmitidos por HTTP '
                    'podem ser capturados por qualquer dispositivo na rede. '
                    'Migre para HTTPS + HSTS imediatamente.',
                    _CRITICO,
                )
            )

        elif tipo == "DNS":
            conteudo = (
                passo("Passo 1", "Consulta DNS (query)",
                      f'{ip(orig)} não sabe o IP de {ip(dom) if dom else "um domínio"}. '
                      f'Envia uma query UDP para o servidor DNS {ip(dest)} na porta 53.')
                + passo("Passo 2", "Resposta do servidor",
                        f'O servidor DNS responde com registros A (IPv4) ou AAAA (IPv6) '
                        f'e um <b>TTL</b> que indica por quanto tempo o resultado pode ser cacheado.')
                + passo("Passo 3", "Sem criptografia",
                        f'Sem DoH (DNS over HTTPS) or DoT (DNS over TLS), qualquer dispositivo '
                        f'na rede consegue ver todos os domínios que {ip(orig)} consulta — '
                        f'revelando intenção de navegação antes mesmo da conexão ser feita.')
                + caixa_captura([
                    linha_dados("Origem", orig),
                    linha_dados("Servidor DNS", dest),
                    linha_dados("Domínio consultado", dom or "não extraído neste pacote", _ACCENT2),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + aviso(
                    '<b>Privacidade:</b> consultas DNS em texto puro mapeiam '
                    'toda a navegação do usuário. Ative DoH ou DoT no roteador ou no sistema.'
                )
            )

        elif tipo == "ARP":
            conteudo = (
                passo("Passo 1", "Broadcast ARP",
                      f'{ip(orig)} precisa saber o MAC de um IP na rede local. '
                      f'Envia um broadcast <code>FF:FF:FF:FF:FF:FF</code> — '
                      f'todos os dispositivos da rede recebem essa pergunta.')
                + passo("Passo 2", "Resposta ARP",
                        f'O dono do IP alvo responde com seu MAC address. '
                        f'{ip(orig)} registra o par IP→MAC na sua <b>ARP table</b> '
                        f'e passa a enviar frames diretamente para ele.')
                + passo("Passo 3", "Sem autenticação",
                        f'O protocolo ARP não verifica a autenticidade das respostas. '
                        f'Qualquer dispositivo pode responder com um MAC falso (<b>ARP Spoofing</b>), '
                        f'desviando o tráfego de {ip(orig)} para um atacante.')
                + caixa_captura([
                    linha_dados("Origem", f"{orig}" + (f" ({mac})" if mac else "")),
                    linha_dados("Destino ARP", dest),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + aviso(
                    '<b>ARP Spoofing:</b> em redes sem Dynamic ARP Inspection (DAI), '
                    'um atacante pode envenenar a ARP table de todos os hosts e '
                    'interceptar tráfego sem que ninguém perceba.'
                )
            )

        elif tipo == "TCP_SYN":
            conteudo = (
                passo("Passo 1", "SYN enviado",
                      f'{ip(orig)} inicia o 3-way handshake enviando um pacote com flag '
                      f'<b>SYN</b> para {ip(dest_porta)}. '
                      f'Isso reserva uma entrada na tabela de conexões do servidor.')
                + passo("Passo 2", "Aguardando SYN-ACK",
                        f'O servidor deve responder com <b>SYN-ACK</b>, confirmando que '
                        f'aceita a conexão. A conexão ainda não está estabelecida neste momento.')
                + passo("Passo 3", "ACK completa o handshake",
                        f'{ip(orig)} responde com <b>ACK</b>. '
                        f'A conexão TCP está estabelecida e os dados podem fluir.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Flag", "SYN (início de conexão)", _AVISO),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + aviso(
                    '<b>SYN Flood:</b> um volume anormal de SYNs sem ACK de resposta '
                    'esgota a tabela de conexões do servidor, tornando-o inacessível. '
                    'Mitigação: SYN Cookies e rate limiting por IP.'
                )
            )

        elif tipo == "ICMP":
            conteudo = (
                passo("Passo 1", "Pacote ICMP capturado",
                      f'{ip(orig)} enviou um pacote ICMP para {ip(dest)}. '
                      f'ICMP é um protocolo de diagnóstico — não carrega dados de aplicação.')
                + passo("Passo 2", "Tipos possíveis",
                        f'<b>Echo Request/Reply</b> (ping): testa conectividade. '
                        f'<b>Time Exceeded</b>: TTL expirou em um roteador — '
                        f'base do <code>traceroute</code>. '
                        f'<b>Destination Unreachable</b>: destino inacessível.')
                + passo("Passo 3", "TTL e fingerprinting",
                        f'O valor de TTL do pacote revela o número de saltos percorridos '
                        f'e permite estimar o sistema operacional do remetente '
                        f'(Linux tipicamente parte de 64, Windows de 128).')
                + caixa_captura([
                    linha_dados("Origem", orig),
                    linha_dados("Destino", dest),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
            )

        elif tipo == "DHCP":
            conteudo = (
                passo("Passo 1", "DISCOVER",
                      f'O dispositivo sem IP envia um broadcast para '
                      f'{ip("255.255.255.255")}: "Há algum servidor DHCP na rede?"')
                + passo("Passo 2", "OFFER",
                        f'O servidor DHCP {ip(dest)} responde com uma oferta: '
                        f'IP sugerido, máscara de sub-rede, gateway padrão e servidor DNS.')
                + passo("Passo 3", "REQUEST",
                        f'O dispositivo aceita a oferta enviando REQUEST de volta '
                        f'ao servidor para confirmar o uso do IP proposto.')
                + passo("Passo 4", "ACK",
                        f'O servidor confirma com ACK. O dispositivo passa a usar '
                        f'o IP recebido pelo tempo do <b>lease</b> definido na concessão.')
                + caixa_captura([
                    linha_dados("Origem", orig),
                    linha_dados("Servidor DHCP", dest),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + aviso(
                    '<b>Rogue DHCP:</b> sem autenticação, qualquer dispositivo pode '
                    'atuar como servidor DHCP e distribuir gateway e DNS falsos, '
                    'redirecionando todo o tráfego da rede. '
                    'Ative DHCP Snooping no switch.'
                )
            )

        elif tipo == "SSH":
            conteudo = (
                passo("Passo 1", "TCP Handshake",
                      f'Conexão TCP estabelecida entre {ip(orig)} e {ip(dest_porta)}.')
                + passo("Passo 2", "Negociação SSH",
                        f'Cliente e servidor anunciam a versão do protocolo (ex: SSH-2.0) '
                        f'e negociam algoritmos de cifra, MAC e troca de chaves — '
                        f'visível ao sniffer apenas neste momento inicial.')
                + passo("Passo 3", "Autenticação cifrada",
                        f'Senha ou par de chaves (Ed25519 / RSA) são verificados '
                        f'dentro do canal já cifrado. O sniffer não vê as credenciais.')
                + passo("Passo 4", "Sessão opaca",
                        f'Todos os comandos, saídas e arquivos transferidos trafegam '
                        f'completamente cifrados durante toda a sessão.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                    linha_dados("Cifrado", "SIM — SSH/TLS", _OK),
                ])
                + nao_ve("Credenciais, comandos executados e saída do terminal estão cifrados.")
            )

        elif tipo == "FTP":
            conteudo = (
                passo("Passo 1", "Canal de controle (porta 21)",
                      f'{ip(orig)} conecta à porta 21 de {ip(dest)}. '
                      f'Todos os comandos — USER, PASS, LIST, RETR — '
                      f'trafegam em texto puro neste canal.')
                + passo("Passo 2", "Credenciais expostas",
                        f'O login (<code>USER nome_usuario</code> / <code>PASS senha</code>) '
                        f'é enviado literalmente em texto. '
                        f'Qualquer sniffer na rede captura as credenciais.')
                + passo("Passo 3", "Canal de dados",
                        f'Para transferir arquivos, o FTP abre uma segunda conexão '
                        f'(porta 20 em modo ativo, ou porta negociada em modo passivo). '
                        f'Os arquivos também trafegam sem criptografia.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                    linha_dados("Cifrado", "NÃO — credenciais em texto puro", _CRITICO),
                ])
                + aviso(
                    '<b>Alternativas seguras:</b> SFTP (porta 22, via SSH) '
                    'cifra comandos e arquivos. FTPS adiciona TLS ao FTP legado.',
                    _CRITICO,
                )
            )

        elif tipo == "SMB":
            conteudo = (
                passo("Passo 1", "Negociação de protocolo",
                      f'{ip(orig)} conecta a {ip(dest_porta)} e negocia a versão SMB '
                      f'(SMBv1, SMBv2 ou SMBv3). A versão negociada determina '
                      f'o nível de segurança da sessão.')
                + passo("Passo 2", "Autenticação NTLM/Kerberos",
                        f'Cliente e servidor realizam o desafio de autenticação. '
                        f'Sem SMB Signing, o hash NTLM pode ser capturado e usado '
                        f'em ataques de relay sem precisar decriptar a senha.')
                + passo("Passo 3", "Acesso ao compartilhamento",
                        f'Após autenticação, {ip(orig)} pode ler, escrever e executar '
                        f'arquivos no servidor conforme as permissões configuradas.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + aviso(
                    '<b>SMBv1:</b> vulnerável ao EternalBlue (WannaCry). '
                    'Desabilite imediatamente se ainda ativo. '
                    'Ative SMB Signing para prevenir ataques de relay.'
                )
            )

        elif tipo == "RDP":
            conteudo = (
                passo("Passo 1", "TCP Handshake",
                      f'{ip(orig)} inicia conexão TCP com {ip(dest_porta)} (porta padrão 3389).')
                + passo("Passo 2", "Negociação TLS",
                        f'RDP moderno usa TLS para cifrar a sessão. '
                        f'<b>Sem NLA:</b> a tela de login é renderizada remotamente antes '
                        f'da autenticação — expande a superfície de ataque. '
                        f'<b>Com NLA:</b> autenticação ocorre antes de qualquer renderização.')
                + passo("Passo 3", "Sessão de área de trabalho",
                        f'Teclado, mouse e tela são transmitidos pelo protocolo RDP '
                        f'dentro do canal TLS. A porta 3389 exposta na internet '
                        f'é alvo constante de bots de força bruta.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
                + aviso(
                    '<b>Exposição crítica:</b> RDP nunca deve estar exposto diretamente '
                    'na internet. Acesso somente via VPN + NLA ativado + MFA.'
                )
            )

        elif tipo == "NOVO_DISPOSITIVO":
            mac_info = (
                f'MAC detectado: {ip(mac)}. Os primeiros 3 bytes (OUI) identificam '
                f'o fabricante e podem indicar o tipo de dispositivo.'
                if mac else
                'MAC não capturado neste evento.'
            )
            conteudo = (
                passo("Passo 1", "Detecção de entrada",
                      f'Um dispositivo com IP {ip(orig)} foi identificado pela primeira vez '
                      f'na rede. A detecção ocorre via ARP, DHCP ou outros protocolos '
                      f'que revelam o endereço MAC do dispositivo.')
                + passo("Passo 2", "Identificação pelo OUI",
                        mac_info + ' Ferramentas como <code>arp-scan</code> ou bases '
                        'OUI públicas (IEEE) permitem identificar o fabricante em segundos.')
                + passo("Passo 3", "Risco em redes sem controle de acesso",
                        f'Em redes sem 802.1X, qualquer dispositivo com acesso físico '
                        f'ou acesso à rede Wi-Fi entra livremente e recebe IP via DHCP. '
                        f'Não há verificação de identidade ou autorização prévia.')
                + caixa_captura([
                    linha_dados("IP detectado", orig),
                    linha_dados("MAC", mac or "não disponível", _ACCENT2),
                ])
                + aviso(
                    '<b>Ação recomendada:</b> verifique se este dispositivo é autorizado. '
                    'Em ambientes corporativos, implante 802.1X para autenticação '
                    'por certificado antes de conceder acesso à rede.'
                )
            )

        else:
            # Protocolo genérico — exibe dados disponíveis de forma organizada
            conteudo = (
                passo("Passo 1", "Pacote capturado",
                      f'O sniffer capturou tráfego de {ip(orig)} para {ip(dest_porta)}. '
                      f'O protocolo <b>{tipo or "desconhecido"}</b> foi identificado '
                      f'com base nas portas e no conteúdo do pacote.')
                + passo("Passo 2", "Dados do fluxo",
                        f'Tamanho do payload capturado: <b>{tam_s}</b>. '
                        f'Analise a aba <b>Evidências</b> para ver os campos completos do pacote.')
                + caixa_captura([
                    linha_dados("Fluxo", f"{orig} → {dest_porta}"),
                    linha_dados("Tamanho", tam_s, _TEXTO2),
                ])
            )

        return f"<style>{self._CSS_BASE}</style><body>{conteudo}</body>"

    def _aba_evidencias(self, e: dict):
        pos  = 0
        tipo = e.get("tipo", "")

        cifrado = (
            "Sim — TLS" if tipo == "HTTPS"
            else ("Sim — SSH" if tipo == "SSH" else "Não")
        )
        cor_cifrado = _OK if cifrado.startswith("Sim") else _CRITICO

        tamanho = e.get("tamanho") or 0
        campos  = [
            ("IP Origem",     e.get("ip_origem")  or "—",                  _TEXTO),
            ("IP Destino",    e.get("ip_destino") or "—",                  _ACCENT2),
            ("Protocolo",     e.get("protocolo")  or e.get("tipo", "—"),   _cor(tipo)),
            ("Porta Destino", str(e.get("porta_destino") or "—"),           _TEXTO2),
            ("Tamanho",       f"{tamanho} bytes" if tamanho else "—",       _TEXTO2),
            ("Cifrado",       cifrado,                                       cor_cifrado),
        ]
        if e.get("dominio"):
            campos.insert(3, ("Domínio", e["dominio"], _ACCENT2))
        if e.get("mac_origem"):
            campos.append(("MAC Origem", e["mac_origem"], _TEXTO2))

        # _MetaGrid filtra automaticamente linhas com valor "—" (patch v6.1)
        self._inserir_secao("CAMPOS DO PACOTE", _MetaGrid(campos), _MUTED, pos)
        pos += 1

        n3 = e.get("nivel3", "")
        if n3:
            html3 = f"<style>{self._CSS_BASE}</style><body>{n3}</body>"
            self._inserir_secao(
                "DETALHES TÉCNICOS",
                self._browser(html3, 60, 500),
                _MUTED,
                pos,
            )

    def _aba_pratica(self, e: dict):
        pos = 0

        mapa = {
            "HTTPS":
                "Tráfego cifrado e seguro. O TLS protege URL, headers, cookies e corpo — "
                "ilegíveis para qualquer capturador na rede. Analise o <b>SNI</b> no "
                "ClientHello para identificar o serviço sem precisar decriptar.",
            "HTTP":
                "Tráfego em texto puro. URL, cabeçalhos e corpo visíveis para qualquer "
                "dispositivo na mesma rede. Solução imediata: migrar para <b>HTTPS</b> com "
                "certificado válido e ativar <b>HSTS</b> para impedir downgrade.",
            "DNS":
                "Consultas DNS revelam intenção de navegação antes da conexão. Sem "
                "<b>DoH</b> ou <b>DoT</b>, qualquer dispositivo na rede pode mapear todos "
                "os domínios acessados. Considere ativar DNS criptografado no roteador.",
            "ARP":
                "Protocolo sem autenticação — vulnerável a <b>ARP Spoofing</b>. Um atacante "
                "pode responder com MACs falsos e interceptar todo o tráfego local. Em redes "
                "corporativas, ative <b>Dynamic ARP Inspection (DAI)</b> no switch.",
            "ICMP":
                "Diagnóstico de conectividade. O <b>TTL</b> revela o número de saltos e "
                "permite estimar o sistema operacional do remetente. O <code>traceroute</code> "
                "usa ICMP Time Exceeded para mapear o caminho até o destino.",
            "TCP_SYN":
                "Início do <b>3-way handshake</b> TCP. Um flood de SYNs sem ACK é o "
                "ataque <b>SYN Flood</b>, que esgota a tabela de conexões do servidor. "
                "Mitigação: <b>SYN Cookies</b> e rate limiting por IP.",
            "DHCP":
                "Distribuição automática de IPs sem autenticação. Um <b>Rogue DHCP Server</b> "
                "pode distribuir gateway e DNS falsos, redirecionando todo o tráfego. "
                "Ative <b>DHCP Snooping</b> no switch para bloquear servidores não autorizados.",
            "SSH":
                "Acesso remoto completamente cifrado. Prefira autenticação por <b>par de "
                "chaves</b> (Ed25519 ou RSA 4096) em vez de senha. Desabilite login root "
                "direto e considere mover a porta 22 para reduzir ruído de bots.",
            "FTP":
                "Protocolo legado sem criptografia. Credenciais e conteúdo dos arquivos "
                "trafegam em texto puro. Substitua por <b>SFTP</b> (porta 22) ou "
                "<b>FTPS</b> (TLS explícito na porta 21 ou implícito na 990).",
            "SMB":
                "Compartilhamento de arquivos Windows/Samba. Desabilite <b>SMBv1</b> "
                "(vulnerável ao EternalBlue/WannaCry). Ative <b>SMB Signing</b> para "
                "prevenir relay attacks. Restrinja o acesso com firewall na porta 445.",
            "RDP":
                "Acesso remoto à área de trabalho Windows. Exponha somente via <b>VPN</b>. "
                "Ative <b>NLA</b> (Network Level Authentication) e <b>MFA</b>. "
                "Monitore eventos <code>4624</code> (logon) e <code>4625</code> (falha) "
                "no Event Viewer.",
            "NOVO_DISPOSITIVO":
                "Novo dispositivo detectado na rede local. Verifique o <b>OUI</b> do MAC "
                "para identificar o fabricante. Em ambientes corporativos, use <b>802.1X</b> "
                "para autenticar dispositivos antes de conceder acesso à rede.",
        }

        tipo  = e.get("tipo", "")
        texto = mapa.get(tipo, "Análise operacional baseada no fluxo detectado.")

        html_op = f"""
            <style>{self._CSS_BASE}</style>
            <body>
              <div style="border-left: 2px solid {_ACCENT};
                          padding: 0 0 0 12px; margin: 0;">
                {texto}
              </div>
            </body>
        """
        self._inserir_secao(
            "SIGNIFICADO OPERACIONAL",
            self._browser(html_op),
            _ACCENT,
            pos,
        )
        pos += 1

        n4 = e.get("nivel4", "")
        if n4:
            html_n4 = f"""
                <style>
                  body {{
                    font-family: Consolas, monospace;
                    font-size: 9px;
                    color: {_TEXTO2};
                    line-height: 1.55;
                    margin: 0; padding: 0;
                    background: #040810;
                  }}
                </style>
                <body>{n4}</body>
            """
            tb_n4 = self._browser(html_n4, 60, 260)
            tb_n4.setStyleSheet(
                tb_n4.styleSheet().replace(f"background: {_CARD}", "background: #040810", 1)
            )
            self._inserir_secao("PAYLOAD BRUTO", tb_n4, _DIM, pos)

    # ─────────────────────────────────────────────────────────
    # EVENTOS ADAPT. DE REDIMENSIONAMENTO
    # ─────────────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Ajusta margem lateral do conteúdo conforme largura disponível
        margem = max(12, min(24, self.width() // 55))
        self._lay_c.setContentsMargins(margem, 14, margem, 18)
        self._atualizar_rodape()

    def _atualizar_rodape(self):
        """Adapta o texto do rodapé para telas menores."""
        p = self._stats_cache.get("pacotes", 0)
        r = self._stats_cache.get("rede", "—")
        d = self._stats_cache.get("dados", "0 B")
        if self.width() < 860:
            self._lbl_stats.setText(f"Net: {r} | Pkt: {p:,} | {d}")
        else:
            self._lbl_stats.setText(f"Rede: {r}  |  Pacotes: {p:,}  |  Dados: {d}")

    # ─────────────────────────────────────────────────────────
    # API PÚBLICA
    # ─────────────────────────────────────────────────────────

    def adicionar_evento(self, e: dict):
        """Insere um novo evento no painel e atualiza contadores/filtros."""
        e["titulo"] = corrigir_mojibake(e.get("titulo", "Evento"))
        for k in ("nivel1", "nivel2", "nivel3", "nivel4", "alerta_seguranca"):
            if k in e:
                e[k] = corrigir_mojibake(e[k])

        self._todos_eventos.append(e)

        tipo = e.get("tipo", "OUTRO")
        self._contadores[tipo]    += 1
        self._contadores["Todos"] += 1

        for proto, badge in self._badges.items():
            badge.set_count(self._contadores[proto])

        self._inserir_item(e)

        visiveis = sum(1 for _, it, _ in self._item_map if not it.isHidden())
        total    = len(self._todos_eventos)
        self._lbl_contagem.setText(f"{visiveis} / {total}")

    def limpar(self):
        """Reseta completamente o painel, removendo todos os eventos."""
        self._todos_eventos.clear()
        self._item_map.clear()
        self._lista.clear()
        self._contadores.clear()
        self._evento_atual = None

        for b in self._badges.values():
            b.set_count(0)

        self._det_titulo.setText("Selecione um evento na lista")
        self._det_ts.setText("")
        self._det_resumo.setText("")
        self._det_badge.setText("—")
        self._det_badge.setStyleSheet(f"""
            color: {_MUTED};
            border: 1px solid {_BORDA};
            border-radius: 3px;
            padding: 1px 10px;
            font-family: Consolas, monospace;
            font-size: 9px;
            font-weight: bold;
        """)
        self._lbl_contagem.setText("0 / 0")
        self._lbl_status.setText("Aguardando captura")
        QTimer.singleShot(0, self._renderizar_boas_vindas)

        while self._lay_c.count() > 1:
            it = self._lay_c.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def atualizar_stats(self, pacotes: int, rede: str, dados: str):
        """Atualiza os dados exibidos no rodapé."""
        self._stats_cache = {"pacotes": pacotes, "rede": rede, "dados": dados}
        self._atualizar_rodape()

    def _reaplicar_filtros(self):
        self._filtrar()