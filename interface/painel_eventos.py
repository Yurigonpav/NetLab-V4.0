# interface/painel_eventos.py
# Painel do Modo Análise — v6.1
#
# PATCHES v6.1:
#   - _MetaGrid filtra automaticamente linhas com valor vazio, "—" ou "0 bytes"
#   - _ItemWidget omite o prefixo "— >" quando ip_origem não está disponível
#   - _aba_evidencias não exibe Tamanho quando 0 nem Porta quando ausente

from collections import defaultdict, deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton,
    QSplitter, QLineEdit, QListWidget, QListWidgetItem,
    QTextBrowser, QSizePolicy, QGraphicsOpacityEffect,
)
from PyQt6.QtCore import Qt, QSize, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QColor, QFont, QPainter, QPen, QLinearGradient

from utils.rede import corrigir_mojibake

# ══════════════════════════════════════════════════════════════
# TOKENS DE DESIGN — Sistema de cores do NetLab Educacional
# ══════════════════════════════════════════════════════════════

_BG       = "#0a0e1a"
_BG2      = "#0f1423"
_SURFACE  = "#111827"
_SURFACE2 = "#161d2e"
_CARD     = "#0d1220"
_BORDA    = "#1a2540"
_BORDA2   = "#243352"
_SEL      = "#1a3a5c"
_SEL2     = "#1e4571"
_ACCENT   = "#3d9fd3"
_ACCENT2  = "#5ab4e5"
_TEXTO    = "#dde6f0"
_TEXTO2   = "#aabdcc"
_MUTED    = "#6b7f94"
_DIM      = "#3d5166"
_LINHA    = "#131c2e"

_CRITICO  = "#e05252"
_AVISO    = "#d4872a"
_INFO     = "#3d9fd3"
_OK       = "#3dba7e"

_PROTO_COR = {
    "HTTPS":            "#3dba7e",
    "HTTP":             "#e05252",
    "DNS":              "#3d9fd3",
    "ARP":              "#d4872a",
    "ICMP":             "#2bbfb0",
    "TCP_SYN":          "#8e6dc4",
    "DHCP":             "#1d9e87",
    "SSH":              "#3070b0",
    "FTP":              "#c94f8a",
    "SMB":              "#7d6145",
    "RDP":              "#d4602a",
    "NOVO_DISPOSITIVO": "#d4a72a",
}

_PROTO_LABEL = {
    "HTTPS": "HTTPS", "HTTP": "HTTP", "DNS": "DNS",
    "ARP": "ARP", "ICMP": "ICMP", "TCP_SYN": "SYN",
    "DHCP": "DHCP", "SSH": "SSH", "FTP": "FTP",
    "SMB": "SMB", "RDP": "RDP", "NOVO_DISPOSITIVO": "NOVO",
}

_NIVEL_COR = {
    "CRITICO": _CRITICO,
    "AVISO":   _AVISO,
    "INFO":    _INFO,
}


def _cor(tipo):  return _PROTO_COR.get(tipo, _MUTED)
def _lbl(tipo):  return _PROTO_LABEL.get(tipo, (tipo[:4] if tipo else "PKT"))
def _rgb(hex_c):
    c = QColor(hex_c)
    return c.red(), c.green(), c.blue()


_SCROLL_SS = f"""
    QScrollBar:vertical {{
        background: {_BG}; width: 6px;
        border-radius: 3px; margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {_BORDA2}; border-radius: 3px; min-height: 24px;
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
    def __init__(self, proto: str, parent=None):
        super().__init__(parent)
        self.proto  = proto
        self._count = 0
        self._ativo = (proto == "Todos")
        self.setCheckable(True)
        self.setChecked(self._ativo)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(24)
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
        label = _lbl(self.proto) if self.proto != "Todos" else "Todos"
        count_txt = f" {self._count}" if self._count > 0 else ""
        self.setText(f"{label}{count_txt}")

        cor = _cor(self.proto) if self.proto != "Todos" else _ACCENT
        r, g, b = _rgb(cor)

        if self._ativo:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: rgba({r},{g},{b}, 22);
                    color: {cor};
                    border: 1px solid rgba({r},{g},{b}, 80);
                    border-radius: 5px;
                    padding: 2px 12px;
                    font-size: 10px;
                    font-weight: bold;
                    font-family: Consolas, monospace;
                    letter-spacing: 0.5px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {_MUTED};
                    border: 1px solid {_BORDA};
                    border-radius: 5px;
                    padding: 2px 12px;
                    font-size: 10px;
                    font-family: Consolas, monospace;
                    letter-spacing: 0.5px;
                }}
                QPushButton:hover {{
                    color: {_TEXTO2};
                    background: rgba(255,255,255, 5);
                    border-color: {_BORDA2};
                }}
            """)


# ══════════════════════════════════════════════════════════════
# ITEM DA LISTA DE EVENTOS
# PATCH v6.1: omite "— >" quando ip_origem não está disponível
# ══════════════════════════════════════════════════════════════

class _ItemWidget(QWidget):
    HEIGHT = 68

    def __init__(self, evento: dict, parent=None):
        super().__init__(parent)
        self.evento = evento
        self.setFixedHeight(self.HEIGHT)

        tipo = evento.get("tipo", "")
        cor  = _cor(tipo)
        r, g, b = _rgb(cor)
        nivel = evento.get("nivel", "INFO")
        cor_nivel = _NIVEL_COR.get(nivel, _MUTED)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        faixa = QFrame()
        faixa.setFixedWidth(4)
        faixa.setStyleSheet(f"background: {cor}; border: none;")
        root.addWidget(faixa)

        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setFixedHeight(36)
        sep.setStyleSheet(f"background: {_BORDA}; border: none;")
        root.addWidget(sep)

        corpo = QWidget()
        corpo.setStyleSheet("background: transparent;")
        cl = QVBoxLayout(corpo)
        cl.setContentsMargins(12, 8, 8, 8)
        cl.setSpacing(4)

        r1 = QHBoxLayout()
        r1.setSpacing(6)
        r1.setContentsMargins(0, 0, 0, 0)

        badge = QLabel(_lbl(tipo))
        badge.setFixedHeight(17)
        badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(f"""
            background: rgba({r},{g},{b}, 22);
            color: {cor};
            border: 1px solid rgba({r},{g},{b}, 65);
            border-radius: 3px;
            padding: 0 8px;
            font-family: Consolas, monospace;
            font-size: 9px;
            font-weight: bold;
            letter-spacing: 0.5px;
        """)

        # ── PATCH v6.1: não exibe "— >" quando ip_origem está vazio ──────
        ip_orig = (evento.get("ip_origem") or "").strip()
        ip_dest = (evento.get("ip_destino") or "").strip()

        lbl_dest = QLabel(ip_dest or "—")
        lbl_dest.setStyleSheet(
            f"color: {_ACCENT2}; font-family: Consolas; font-size: 11px; "
            "background: transparent;"
        )

        if nivel in ("CRITICO", "AVISO"):
            dot = QLabel("!")
            dot.setStyleSheet(
                f"color: {cor_nivel}; font-size: 10px; font-weight: bold; background: transparent;"
            )
            r1.addWidget(dot)

        r1.addWidget(badge)

        if ip_orig and ip_orig != "—":
            lbl_orig = QLabel(ip_orig)
            lbl_orig.setStyleSheet(
                f"color: {_TEXTO}; font-family: Consolas; font-size: 11px; "
                "font-weight: bold; background: transparent;"
            )
            lbl_seta = QLabel(">")
            lbl_seta.setStyleSheet(
                f"color: {_DIM}; font-size: 11px; background: transparent;"
            )
            lbl_seta.setFixedWidth(12)
            r1.addWidget(lbl_orig)
            r1.addWidget(lbl_seta)

        r1.addWidget(lbl_dest)
        r1.addStretch()
        cl.addLayout(r1)

        sub = (
            evento.get("dominio")
            or evento.get("http_caminho")
            or evento.get("mac_origem")
            or (f"> :{evento.get('porta_destino')}" if evento.get("porta_destino") else "")
            or ""
        )
        if sub:
            ls = QLabel(str(sub)[:52])
            ls.setStyleSheet(
                f"color: {_MUTED}; font-size: 10px; "
                "font-family: Consolas; background: transparent;"
            )
            ls.setContentsMargins(0, 0, 0, 0)
            cl.addWidget(ls)
        else:
            cl.addStretch()

        root.addWidget(corpo, 1)

        lbl_ts = QLabel(evento.get("timestamp", ""))
        lbl_ts.setFixedWidth(54)
        lbl_ts.setAlignment(
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight
        )
        lbl_ts.setStyleSheet(
            f"color: {_DIM}; font-family: Consolas; font-size: 9px; "
            f"padding-right: 12px; background: transparent;"
        )
        root.addWidget(lbl_ts)


# ══════════════════════════════════════════════════════════════
# SEPARADOR DE SEÇÃO
# ══════════════════════════════════════════════════════════════

class _SecaoHeader(QWidget):
    def __init__(self, titulo: str, cor: str = _MUTED, parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)

        lbl = QLabel(titulo)
        lbl.setStyleSheet(f"""
            color: {cor};
            font-size: 9px;
            font-weight: bold;
            font-family: 'Segoe UI', Arial, sans-serif;
            letter-spacing: 1.5px;
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
# PATCH v6.1: pré-filtra linhas sem valor antes de renderizar
# ══════════════════════════════════════════════════════════════

# Valores considerados "sem informação" — linhas com esses valores são omitidas
_META_SKIP = frozenset({
    "—", "", "none", "0 bytes", "0",
    "não extraído neste pacote", "não extraído",
})


class _MetaGrid(QFrame):
    def __init__(self, campos: list, parent=None):
        """campos: lista de (rotulo, valor, cor_valor_opcional)"""
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background: {_CARD};
                border: 1px solid {_BORDA};
                border-radius: 8px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── PATCH v6.1: remove linhas sem valor ──────────────────────────
        campos = [
            c for c in campos
            if str(c[1]).strip().lower() not in _META_SKIP
        ]
        # ─────────────────────────────────────────────────────────────────

        for i, campo in enumerate(campos):
            rot   = campo[0]
            val   = campo[1]
            cor_v = campo[2] if len(campo) > 2 else _TEXTO

            linha = QFrame()
            borda_b = f"border-bottom: 1px solid {_LINHA};" if i < len(campos) - 1 else ""
            linha.setStyleSheet(f"QFrame {{ {borda_b} background: transparent; }}")
            ll = QHBoxLayout(linha)
            ll.setContentsMargins(16, 9, 16, 9)
            ll.setSpacing(12)

            lr = QLabel(rot)
            lr.setFixedWidth(120)
            lr.setStyleSheet(
                f"color: {_MUTED}; font-size: 10px; background: transparent;"
            )

            lv = QLabel(str(val))
            lv.setStyleSheet(
                f"color: {cor_v}; font-family: Consolas; "
                f"font-size: 10px; background: transparent;"
            )
            lv.setWordWrap(True)

            ll.addWidget(lr)
            ll.addWidget(lv, 1)
            lay.addWidget(linha)


# ══════════════════════════════════════════════════════════════
# PAINEL PRINCIPAL — PainelEventos
# ══════════════════════════════════════════════════════════════

class PainelEventos(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)

        self._todos_eventos  = deque(maxlen=150)
        self._evento_atual   = None
        self._filtro_proto   = "Todos"
        self._filtro_texto   = ""
        self._aba_ativa      = "analise"
        self._badges         = {}
        self._contadores     = defaultdict(int)
        self._item_map       = []
        self._stats_cache    = {"pacotes": 0, "rede": "—", "dados": "0 B"}

        self._timer_busca = QTimer(self)
        self._timer_busca.setSingleShot(True)
        self._timer_busca.setInterval(120)
        self._timer_busca.timeout.connect(self._filtrar)

        self._montar_layout()

    # ─────────────────────────────────────────────────────────
    # MONTAGEM DO LAYOUT PRINCIPAL
    # ─────────────────────────────────────────────────────────

    def _montar_layout(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._mk_topbar())

        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setHandleWidth(1)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background: {_BORDA};
            }}
        """)
        self._splitter.addWidget(self._mk_painel_lista())
        self._splitter.addWidget(self._mk_painel_detalhe())
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 3)

        root.addWidget(self._splitter, 1)
        root.addWidget(self._mk_rodape())

    # ─────────────────────────────────────────────────────────
    # TOPBAR
    # ─────────────────────────────────────────────────────────

    def _mk_topbar(self) -> QWidget:
        container = QWidget()
        container.setStyleSheet(f"background: {_SURFACE};")
        v = QVBoxLayout(container)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        linha1 = QFrame()
        linha1.setFixedHeight(48)
        linha1.setStyleSheet(
            f"QFrame {{ background: {_SURFACE}; "
            f"border-bottom: 1px solid {_BORDA}; }}"
        )
        l1 = QHBoxLayout(linha1)
        l1.setContentsMargins(18, 0, 18, 0)
        l1.setSpacing(14)

        lbl_titulo = QLabel("MODO ANÁLISE")
        lbl_titulo.setStyleSheet(f"""
            color: {_TEXTO2};
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 2px;
            font-family: 'Segoe UI', Arial, sans-serif;
        """)
        l1.addWidget(lbl_titulo)

        sep_v = QFrame()
        sep_v.setFrameShape(QFrame.Shape.VLine)
        sep_v.setFixedHeight(18)
        sep_v.setStyleSheet(f"background: {_BORDA}; border: none;")
        l1.addWidget(sep_v)

        self._lbl_contagem_global = QLabel("0 eventos")
        self._lbl_contagem_global.setStyleSheet(
            f"color: {_DIM}; font-family: Consolas; font-size: 10px;"
        )
        l1.addWidget(self._lbl_contagem_global)

        l1.addStretch()

        self._campo_busca = QLineEdit()
        self._campo_busca.setPlaceholderText("Buscar IP, domínio, protocolo...")
        self._campo_busca.setMinimumWidth(220)
        self._campo_busca.setMaximumWidth(320)
        self._campo_busca.setFixedHeight(30)
        self._campo_busca.setStyleSheet(f"""
            QLineEdit {{
                background: {_CARD};
                border: 1px solid {_BORDA};
                border-radius: 6px;
                color: {_TEXTO};
                padding: 0 12px;
                font-size: 11px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
            QLineEdit:focus {{
                border-color: {_ACCENT};
                background: {_BG2};
            }}
            QLineEdit::placeholder {{
                color: {_DIM};
            }}
        """)
        self._campo_busca.textChanged.connect(self._ao_busca_mudou)
        l1.addWidget(self._campo_busca)

        self._btn_limpar_busca = QPushButton("X")
        self._btn_limpar_busca.setFixedSize(24, 24)
        self._btn_limpar_busca.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_limpar_busca.setVisible(False)
        self._btn_limpar_busca.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {_MUTED};
                border: none;
                border-radius: 12px;
                font-size: 10px;
            }}
            QPushButton:hover {{
                background: {_BORDA};
                color: {_TEXTO};
            }}
        """)
        self._btn_limpar_busca.clicked.connect(self._campo_busca.clear)
        l1.addWidget(self._btn_limpar_busca)

        v.addWidget(linha1)

        linha2 = QFrame()
        linha2.setFixedHeight(36)
        linha2.setStyleSheet(
            f"QFrame {{ background: {_SURFACE2}; "
            f"border-bottom: 1px solid {_BORDA}; }}"
        )
        l2 = QHBoxLayout(linha2)
        l2.setContentsMargins(18, 0, 18, 0)
        l2.setSpacing(6)

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
            f"color: {_DIM}; font-family: Consolas; font-size: 10px;"
        )
        l2.addWidget(self._lbl_contagem)

        v.addWidget(linha2)
        return container

    # ─────────────────────────────────────────────────────────
    # PAINEL ESQUERDO: lista de eventos
    # ─────────────────────────────────────────────────────────

    def _mk_painel_lista(self) -> QWidget:
        frame = QFrame()
        frame.setMinimumWidth(240)
        frame.setMaximumWidth(380)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_BG2};
                border-right: 1px solid {_BORDA};
            }}
        """)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        cab = QFrame()
        cab.setFixedHeight(32)
        cab.setStyleSheet(f"""
            QFrame {{
                background: {_SURFACE2};
                border-bottom: 1px solid {_BORDA};
            }}
        """)
        cl = QHBoxLayout(cab)
        cl.setContentsMargins(14, 0, 14, 0)
        lbl_h = QLabel("EVENTOS")
        lbl_h.setStyleSheet(
            f"color: {_DIM}; font-size: 9px; font-weight: bold; "
            "letter-spacing: 1.5px;"
        )
        cl.addWidget(lbl_h)
        cl.addStretch()
        lay.addWidget(cab)

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
                border-left: 0px;
            }}
            QListWidget::item:hover:!selected {{
                background: rgba(255, 255, 255, 3);
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
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {_BG}; }}
            {_SCROLL_SS}
        """)

        self._conteudo = QWidget()
        self._conteudo.setStyleSheet(f"background: {_BG};")
        self._lay_c = QVBoxLayout(self._conteudo)
        self._lay_c.setContentsMargins(24, 20, 24, 28)
        self._lay_c.setSpacing(16)
        self._lay_c.addStretch()

        scroll.setWidget(self._conteudo)
        lay.addWidget(scroll, 1)
        return frame

    def _mk_header_detalhe(self) -> QFrame:
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
        lay.setContentsMargins(24, 14, 24, 14)
        lay.setSpacing(6)

        r1 = QHBoxLayout()
        r1.setSpacing(12)
        r1.setContentsMargins(0, 0, 0, 0)

        self._det_badge = QLabel("—")
        self._det_badge.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed
        )
        self._det_badge.setFixedHeight(22)
        self._det_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._det_badge.setStyleSheet(f"""
            color: {_MUTED};
            border: 1px solid {_BORDA};
            border-radius: 4px;
            padding: 2px 12px;
            font-family: Consolas, monospace;
            font-size: 10px;
            font-weight: bold;
        """)

        self._det_titulo = QLabel("Selecione um evento na lista")
        self._det_titulo.setWordWrap(False)
        self._det_titulo.setStyleSheet(f"""
            font-size: 13px;
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
            f"color: {_MUTED}; font-family: Consolas; font-size: 10px; "
            "background: transparent;"
        )
        self._det_ts.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed
        )

        r1.addWidget(self._det_badge)
        r1.addWidget(self._det_titulo, 1)
        r1.addWidget(self._det_ts)
        lay.addLayout(r1)

        self._det_resumo = QLabel("")
        self._det_resumo.setStyleSheet(
            f"color: {_MUTED}; font-family: Consolas; font-size: 10px; "
            "background: transparent;"
        )
        lay.addWidget(self._det_resumo)

        return frame

    def _mk_barra_abas(self) -> QFrame:
        frame = QFrame()
        frame.setFixedHeight(40)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_SURFACE2};
                border-bottom: 1px solid {_BORDA};
            }}
        """)
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(4)

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
        btn.setFixedHeight(40)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._aplicar_estilo_aba(btn, ativo)
        btn.clicked.connect(lambda: self._trocar_aba(id_aba))
        return btn

    def _aplicar_estilo_aba(self, btn: QPushButton, ativo: bool):
        cor_txt  = _TEXTO if ativo else _MUTED
        borda_b  = _ACCENT if ativo else "transparent"
        bg       = f"rgba(61, 159, 211, 0.08)" if ativo else "transparent"
        peso     = "bold" if ativo else "normal"
        hover    = (
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
                padding: 0 20px;
                font-size: 10px;
                font-weight: {peso};
                letter-spacing: 1px;
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
        frame.setFixedHeight(28)
        frame.setStyleSheet(f"""
            QFrame {{
                background: {_SURFACE};
                border-top: 1px solid {_BORDA};
            }}
        """)
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(18, 0, 18, 0)
        lay.setSpacing(0)

        self._lbl_status = QLabel("Aguardando captura")
        self._lbl_status.setStyleSheet(
            f"color: {_MUTED}; font-size: 10px;"
        )

        self._lbl_stats = QLabel("Rede: — | Pacotes: 0 | Dados: 0 B")
        self._lbl_stats.setMinimumWidth(0)
        self._lbl_stats.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )
        self._lbl_stats.setWordWrap(False)
        self._lbl_stats.setStyleSheet(
            f"color: {_DIM}; font-family: Consolas; font-size: 10px;"
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
        if self._filtro_proto != "Todos" and e.get("tipo", "") != self._filtro_proto:
            return False
        if self._filtro_texto:
            campo = " ".join([
                e.get("ip_origem", ""),
                e.get("ip_destino", ""),
                e.get("titulo", ""),
                e.get("dominio", ""),
                e.get("tipo", ""),
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
        self._lbl_contagem_global.setText(
            f"{total} evento{'s' if total != 1 else ''}"
        )

    # ─────────────────────────────────────────────────────────
    # INSERÇÃO DE ITENS NA LISTA
    # ─────────────────────────────────────────────────────────

    def _inserir_item(self, evento: dict):
        widget = _ItemWidget(evento)
        item   = QListWidgetItem()
        item.setSizeHint(QSize(240, _ItemWidget.HEIGHT))
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

        tipo  = e.get("tipo", "")
        cor   = _cor(tipo)
        nivel = e.get("nivel", "INFO")
        r, g, b = _rgb(cor)

        self._det_badge.setText(_lbl(tipo))
        self._det_badge.setStyleSheet(f"""
            background: rgba({r},{g},{b}, 20);
            color: {cor};
            border: 1px solid rgba({r},{g},{b}, 60);
            border-radius: 4px;
            padding: 2px 12px;
            font-family: Consolas, monospace;
            font-size: 10px;
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

        resumo_parts = []
        if e.get("ip_origem"):
            resumo_parts.append(e["ip_origem"])
        if e.get("ip_destino"):
            resumo_parts.append(f">  {e['ip_destino']}")
        if e.get("tamanho"):
            resumo_parts.append(f"|  {e['tamanho']} bytes")
        if nivel in ("CRITICO", "AVISO"):
            cor_n = _NIVEL_COR.get(nivel, _MUTED)
            resumo_parts.append(f'<span style="color:{cor_n};">! {nivel}</span>')

        self._det_resumo.setText(
            '   '.join(resumo_parts) if resumo_parts else ""
        )
        self._lbl_status.setText(
            f"{tipo}  —  {e.get('ip_origem', '')} → {e.get('ip_destino', '')}"
        )

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
            line-height: 1.75;
            margin: 0;
            padding: 0;
            background: transparent;
        }}
        b {{ color: {_TEXTO}; font-weight: bold; }}
        i {{ color: {_MUTED}; }}
        code {{
            background: rgba(255,255,255, 0.07);
            padding: 1px 6px;
            border-radius: 3px;
            font-family: Consolas, monospace;
            font-size: 10px;
            color: #a8d8ff;
        }}
        table {{ border-collapse: collapse; width: 100%; }}
        td {{ padding: 4px 14px 4px 0; vertical-align: top; }}
        a {{ color: {_ACCENT2}; }}
    """

    def _browser(self, html: str, altura_min: int = 80, altura_max: int = 500) -> QTextBrowser:
        tb = QTextBrowser()
        tb.setOpenExternalLinks(False)
        tb.setReadOnly(True)
        tb.setMinimumHeight(altura_min)
        tb.setMaximumHeight(altura_max)
        tb.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        tb.setStyleSheet(f"""
            QTextBrowser {{
                background: {_CARD};
                border: 1px solid {_BORDA};
                border-radius: 8px;
                color: {_TEXTO};
                font-size: 11px;
                padding: 14px 16px;
                selection-background-color: {_SEL};
            }}
            {_SCROLL_SS}
        """)
        tb.setHtml(html)
        return tb

    def _bloco_alerta(self, texto: str, cor: str) -> QLabel:
        r, g, b = _rgb(cor)
        lbl = QLabel(texto)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"""
            background: rgba({r},{g},{b}, 14);
            border: 1px solid rgba({r},{g},{b}, 50);
            border-left: 3px solid {cor};
            border-radius: 6px;
            padding: 10px 14px;
            font-size: 11px;
            color: {cor};
            font-family: 'Segoe UI', Arial, sans-serif;
        """)
        return lbl

    def _inserir_secao(self, titulo: str, widget: QWidget,
                       cor: str = _MUTED, pos: int = -1):
        container = QWidget()
        container.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lay.addWidget(_SecaoHeader(titulo, cor))
        lay.addWidget(widget)
        if pos < 0:
            pos = max(0, self._lay_c.count() - 1)
        self._lay_c.insertWidget(pos, container)

    # ─────────────────────────────────────────────────────────
    # ABAS DE CONTEÚDO
    # ─────────────────────────────────────────────────────────

    def _aba_analise(self, e: dict):
        pos = 0

        html1 = f"""
            <style>{self._CSS_BASE}</style>
            <body>
              <div style="border-left: 3px solid {_ACCENT};
                          padding: 0 0 0 14px; margin: 0;">
                {e.get("nivel1", "<i>Análise não disponível.</i>")}
              </div>
            </body>
        """
        self._inserir_secao("O QUE ACONTECEU", self._browser(html1), _ACCENT, pos)
        pos += 1

        html2 = f"""
            <style>{self._CSS_BASE}</style>
            <body style="color: {_TEXTO2};">
              {e.get("nivel2", "<i>Informação técnica não disponível.</i>")}
            </body>
        """
        tb2 = self._browser(html2)
        tb2.setStyleSheet(
            tb2.styleSheet().replace(f"color: {_TEXTO}", f"color: {_TEXTO2}", 1)
        )
        self._inserir_secao("COMO FUNCIONA", tb2, _MUTED, pos)
        pos += 1

        alerta = e.get("alerta_seguranca", "")
        nivel  = e.get("nivel", "INFO")
        if alerta:
            cor_al = _NIVEL_COR.get(nivel, _MUTED)
            self._inserir_secao(
                f"ALERTA — {nivel}",
                self._bloco_alerta(alerta, cor_al),
                cor_al,
                pos,
            )

    def _aba_evidencias(self, e: dict):
        pos = 0

        tipo    = e.get("tipo", "")
        cifrado = "Sim — TLS" if tipo == "HTTPS" else ("Sim — SSH" if tipo == "SSH" else "Não")
        cor_cifrado = _OK if cifrado.startswith("Sim") else _CRITICO

        # ── PATCH v6.1: valores vazios/zero são omitidos pelo _MetaGrid ──
        tamanho = e.get("tamanho") or 0
        campos = [
            ("IP Origem",     e.get("ip_origem")  or "—",              _TEXTO),
            ("IP Destino",    e.get("ip_destino") or "—",              _ACCENT2),
            ("Protocolo",     e.get("protocolo")  or e.get("tipo", "—"), _cor(tipo)),
            ("Porta Destino", str(e.get("porta_destino") or "—"),       _TEXTO2),
            ("Tamanho",       f"{tamanho} bytes" if tamanho else "—",   _TEXTO2),
            ("Cifrado",       cifrado,                                   cor_cifrado),
        ]
        if e.get("dominio"):
            campos.insert(3, ("Domínio", e["dominio"], _ACCENT2))
        if e.get("mac_origem"):
            campos.append(("MAC Origem", e["mac_origem"], _TEXTO2))
        # _MetaGrid filtra automaticamente linhas com valor "—" ou "0 bytes"
        # ─────────────────────────────────────────────────────────────────

        self._inserir_secao("CAMPOS DO PACOTE", _MetaGrid(campos), _MUTED, pos)
        pos += 1

        n3 = e.get("nivel3", "")
        if n3:
            html3 = f"<style>{self._CSS_BASE}</style><body>{n3}</body>"
            self._inserir_secao("DETALHES TÉCNICOS", self._browser(html3, 80, 600), _MUTED, pos)

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
                "Monitore eventos <code>4624</code> (logon) e <code>4625</code> (falha) no Event Viewer.",
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
              <div style="border-left: 3px solid {_ACCENT};
                          padding: 0 0 0 14px; margin: 0;">
                {texto}
              </div>
            </body>
        """
        self._inserir_secao("SIGNIFICADO OPERACIONAL", self._browser(html_op), _ACCENT, pos)
        pos += 1

        n4 = e.get("nivel4", "")
        if n4:
            html_n4 = f"""
                <style>
                  body {{
                    font-family: Consolas, monospace;
                    font-size: 10px;
                    color: {_TEXTO2};
                    line-height: 1.55;
                    margin: 0; padding: 0;
                  }}
                </style>
                <body>{n4}</body>
            """
            tb_n4 = self._browser(html_n4, 80, 280)
            tb_n4.setStyleSheet(
                tb_n4.styleSheet().replace(f"background: {_CARD}", "background: #040810", 1)
            )
            self._inserir_secao("PAYLOAD BRUTO", tb_n4, _DIM, pos)

    # ─────────────────────────────────────────────────────────
    # EVENTOS ADAPT. DE REDIMENSIONAMENTO
    # ─────────────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        margin = max(14, min(28, self.width() // 50))
        self._lay_c.setContentsMargins(margin, 18, margin, 24)
        self._atualizar_rodape()

    def _atualizar_rodape(self):
        p = self._stats_cache.get("pacotes", 0)
        r = self._stats_cache.get("rede", "—")
        d = self._stats_cache.get("dados", "0 B")
        if self.width() < 900:
            self._lbl_stats.setText(f"Net: {r} | Pkt: {p:,} | {d}")
        else:
            self._lbl_stats.setText(f"Rede: {r}  |  Pacotes: {p:,}  |  Dados: {d}")

    # ─────────────────────────────────────────────────────────
    # API PÚBLICA
    # ─────────────────────────────────────────────────────────

    def adicionar_evento(self, e: dict):
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
        self._lbl_contagem_global.setText(
            f"{total} evento{'s' if total != 1 else ''}"
        )

    def limpar(self):
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
            border-radius: 4px;
            padding: 2px 12px;
            font-family: Consolas, monospace;
            font-size: 10px;
            font-weight: bold;
        """)
        self._lbl_contagem.setText("0 / 0")
        self._lbl_contagem_global.setText("0 eventos")
        self._lbl_status.setText("Aguardando captura")

        while self._lay_c.count() > 1:
            it = self._lay_c.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def atualizar_stats(self, pacotes: int, rede: str, dados: str):
        self._stats_cache = {"pacotes": pacotes, "rede": rede, "dados": dados}
        self._atualizar_rodape()

    def _reaplicar_filtros(self):
        self._filtrar()