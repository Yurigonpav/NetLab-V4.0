# interface/painel_eventos.py
# Painel do Modo Análise — v5.0
#
# OTIMIZAÇÕES vs versão anterior:
#   - Filtro via show/hide de itens existentes (O(n)) — sem recriar widgets
#   - Badges ocultos enquanto count == 0 (não aparecem categorias vazias)
#   - Debounce de 120ms na busca — sem filtrar a cada keystroke
#   - Layout com mais respiro: margens e alturas revisadas
#   - QTextBrowser para HTML rico — sem truncamento de QLabel
#   - _ao_selecionar corrige mapeamento index↔evento para itens ocultos

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

# ─────────────────────────────────────────────────────────────
# Tokens de design — espelham tema_escuro.qss
# ─────────────────────────────────────────────────────────────
_BG      = "#0f1423"
_SURFACE = "#12162a"
_CARD    = "#0d1120"
_BORDA   = "#1e2d40"
_SEL     = "#1e3a5f"
_ACCENT  = "#3498DB"
_TEXTO   = "#ecf0f1"
_MUTED   = "#7f8c8d"
_DIM     = "#566573"

_PROTO_COR = {
    "HTTPS":   "#2ECC71",
    "HTTP":    "#E74C3C",
    "DNS":     "#3498DB",
    "ARP":     "#E67E22",
    "ICMP":    "#1ABC9C",
    "TCP_SYN": "#9B59B6",
    "DHCP":    "#16A085",
    "SSH":     "#2980B9",
    "FTP":     "#E91E63",
    "SMB":     "#795548",
    "RDP":     "#FF5722",
}
_PROTO_LABEL = {
    "HTTPS": "HTTPS", "HTTP": "HTTP", "DNS": "DNS",
    "ARP": "ARP", "ICMP": "ICMP", "TCP_SYN": "SYN",
    "DHCP": "DHCP", "SSH": "SSH", "FTP": "FTP",
    "SMB": "SMB", "RDP": "RDP",
}

def _cor(tipo):  return _PROTO_COR.get(tipo, _MUTED)
def _lbl(tipo):  return _PROTO_LABEL.get(tipo, tipo[:4] if tipo else "PKT")
def _rgb(hex_c): c = QColor(hex_c); return c.red(), c.green(), c.blue()


# ─────────────────────────────────────────────────────────────
# Badge de filtro
# ─────────────────────────────────────────────────────────────

class _Badge(QPushButton):
    def __init__(self, proto, parent=None):
        super().__init__(parent)
        self.proto  = proto
        self._count = 0
        self._ativo = (proto == "Todos")
        self.setCheckable(True)
        self.setChecked(self._ativo)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(22)
        self._sync()
        if proto != "Todos":
            self.hide()

    def set_count(self, n):
        self._count = n
        self._sync()
        if self.proto != "Todos":
            self.setVisible(n > 0)

    def set_ativo(self, ativo):
        self._ativo = ativo
        self.setChecked(ativo)
        self._sync()

    def _sync(self):
        label = _lbl(self.proto) if self.proto != "Todos" else "Todos"
        self.setText(f"{label}  {self._count}" if self._count else label)
        cor = _cor(self.proto) if self.proto != "Todos" else _ACCENT
        if self._ativo:
            self.setStyleSheet(f"""
                QPushButton {{
                    background:{_SEL}; color:{cor};
                    border:1px solid {cor}; border-radius:4px;
                    padding:1px 11px; font-size:10px;
                    font-weight:bold; font-family:Consolas;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background:transparent; color:{_MUTED};
                    border:1px solid transparent; border-radius:4px;
                    padding:1px 11px; font-size:10px; font-family:Consolas;
                }}
                QPushButton:hover {{ color:{_TEXTO}; background:{_BORDA}; }}
            """)


# ─────────────────────────────────────────────────────────────
# Widget de item da lista
# ─────────────────────────────────────────────────────────────

class _ItemWidget(QWidget):
    def __init__(self, evento, parent=None):
        super().__init__(parent)
        self.evento = evento
        tipo = evento.get("tipo", "")
        cor  = _cor(tipo)
        r, g, b = _rgb(cor)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        faixa = QFrame()
        faixa.setFixedWidth(3)
        faixa.setStyleSheet(f"background:{cor}; border:none;")
        root.addWidget(faixa)

        corpo = QWidget()
        corpo.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(corpo)
        cl.setContentsMargins(12, 11, 12, 11)
        cl.setSpacing(5)

        # Linha 1: badge + IPs
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        badge = QLabel(_lbl(tipo))
        badge.setFixedHeight(16)
        badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        badge.setStyleSheet(f"""
            background:rgba({r},{g},{b},30); color:{cor};
            border:1px solid rgba({r},{g},{b},70); border-radius:3px;
            padding:1px 7px; font-family:Consolas;
            font-size:9px; font-weight:bold;
        """)
        ip_orig = evento.get("ip_origem", "")
        ip_dest = evento.get("ip_destino", "")
        lbl_ips = QLabel(f"{ip_orig}  →  {ip_dest}")
        lbl_ips.setStyleSheet(f"color:{_TEXTO}; font-family:Consolas; font-size:11px;")
        r1.addWidget(badge)
        r1.addWidget(lbl_ips)
        r1.addStretch()
        cl.addLayout(r1)

        # Linha 2: info extra + timestamp
        r2 = QHBoxLayout()
        r2.setSpacing(10)
        sub = (evento.get("dominio") or evento.get("http_caminho")
               or evento.get("mac_origem")
               or (f":{evento.get('porta_destino')}" if evento.get("porta_destino") else ""))
        if sub:
            ls = QLabel(str(sub)[:40])
            ls.setStyleSheet(f"color:{_DIM}; font-size:10px;")
            r2.addWidget(ls)
        lbl_ts = QLabel(evento.get("timestamp", ""))
        lbl_ts.setStyleSheet(f"color:{_MUTED}; font-family:Consolas; font-size:10px;")
        r2.addStretch()
        r2.addWidget(lbl_ts)
        cl.addLayout(r2)

        root.addWidget(corpo, 1)


# ─────────────────────────────────────────────────────────────
# Painel principal
# ─────────────────────────────────────────────────────────────

class PainelEventos(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._todos_eventos   = deque(maxlen=150)
        self._evento_atual    = None
        self._filtro_proto    = "Todos"
        self._filtro_texto    = ""
        self._aba_ativa       = "analise"
        self._badges          = {}
        self._contadores      = defaultdict(int)
        # (evento, QListWidgetItem, _ItemWidget)
        self._item_map        = []

        self._timer_busca = QTimer(self)
        self._timer_busca.setSingleShot(True)
        self._timer_busca.setInterval(120)
        self._timer_busca.timeout.connect(self._filtrar)

        self._montar_layout()

    # ── Layout ─────────────────────────────────────────────────

    def _montar_layout(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._mk_topbar())
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{_BORDA};}}")
        splitter.addWidget(self._mk_lista())
        splitter.addWidget(self._mk_detalhe())
        splitter.setSizes([310, 900])
        root.addWidget(splitter, 1)
        root.addWidget(self._mk_rodape())

    def _mk_topbar(self):
        bar = QFrame()
        bar.setFixedHeight(46)
        bar.setStyleSheet(f"QFrame{{background:{_SURFACE};border-bottom:1px solid {_BORDA};}}")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(10)

        lbl = QLabel("MODO ANÁLISE")
        lbl.setStyleSheet(f"color:{_MUTED};font-size:10px;font-weight:bold;letter-spacing:1px;")
        lay.addWidget(lbl)

        sep = QFrame(); sep.setFixedSize(1, 18)
        sep.setStyleSheet(f"background:{_BORDA};")
        lay.addWidget(sep)

        for proto in ("Todos","HTTPS","DNS","ARP","HTTP","ICMP","TCP_SYN",
                      "DHCP","SSH","FTP","SMB","RDP"):
            b = _Badge(proto)
            b.clicked.connect(lambda _, p=proto: self._ao_badge(p))
            self._badges[proto] = b
            lay.addWidget(b)

        lay.addStretch()

        self._campo_busca = QLineEdit()
        self._campo_busca.setPlaceholderText("Buscar IP, domínio...")
        self._campo_busca.setFixedWidth(210)
        self._campo_busca.setStyleSheet(f"""
            QLineEdit{{background:{_CARD};border:1px solid {_BORDA};
                       border-radius:4px;color:{_TEXTO};padding:4px 10px;font-size:11px;}}
            QLineEdit:focus{{border-color:{_ACCENT};}}
        """)
        self._campo_busca.textChanged.connect(
            lambda t: (setattr(self, "_filtro_texto", t.lower().strip()),
                       self._timer_busca.start())
        )
        lay.addWidget(self._campo_busca)
        return bar

    def _mk_lista(self):
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame{{background:{_BG};border-right:1px solid {_BORDA};}}")
        frame.setMinimumWidth(260)
        frame.setMaximumWidth(360)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        cab = QFrame(); cab.setFixedHeight(34)
        cab.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border-bottom:1px solid {_BORDA};}}")
        cl = QHBoxLayout(cab); cl.setContentsMargins(14, 0, 14, 0)
        lbl_h = QLabel("EVENTOS CAPTURADOS")
        lbl_h.setStyleSheet(
            f"color:{_MUTED};font-size:9px;font-weight:bold;letter-spacing:1px;")
        self._lbl_contagem = QLabel("0 / 0")
        self._lbl_contagem.setStyleSheet(
            f"color:{_DIM};font-family:Consolas;font-size:10px;")
        cl.addWidget(lbl_h); cl.addStretch(); cl.addWidget(self._lbl_contagem)
        lay.addWidget(cab)

        self._lista = QListWidget()
        self._lista.setStyleSheet(f"""
            QListWidget{{background:{_BG};border:none;outline:none;}}
            QListWidget::item{{border-bottom:1px solid {_BORDA};padding:0;background:transparent;}}
            QListWidget::item:selected{{background:{_SEL};}}
            QListWidget::item:hover:!selected{{background:rgba(30,45,64,0.55);}}
            QScrollBar:vertical{{background:{_BG};width:8px;border-radius:4px;}}
            QScrollBar::handle:vertical{{background:#2c3e50;border-radius:4px;min-height:20px;}}
            QScrollBar::handle:vertical:hover{{background:#3d5166;}}
            QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
        """)
        self._lista.setUniformItemSizes(True)
        self._lista.itemSelectionChanged.connect(self._ao_selecionar)
        lay.addWidget(self._lista)
        return frame

    def _mk_detalhe(self):
        frame = QFrame()
        frame.setStyleSheet(f"QFrame{{background:{_BG};}}")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self._mk_header())
        lay.addWidget(self._mk_abas())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"""
            QScrollArea{{border:none;background:{_BG};}}
            QScrollBar:vertical{{background:{_BG};width:8px;border-radius:4px;}}
            QScrollBar::handle:vertical{{background:#2c3e50;border-radius:4px;min-height:20px;}}
            QScrollBar::handle:vertical:hover{{background:#3d5166;}}
            QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
        """)
        self._conteudo = QWidget()
        self._conteudo.setStyleSheet(f"background:{_BG};")
        self._lay_c = QVBoxLayout(self._conteudo)
        self._lay_c.setContentsMargins(28, 24, 28, 28)
        self._lay_c.setSpacing(20)
        self._lay_c.addStretch()
        scroll.setWidget(self._conteudo)
        lay.addWidget(scroll, 1)
        return frame

    def _mk_header(self):
        frame = QFrame(); frame.setFixedHeight(76)
        frame.setStyleSheet(
            f"QFrame{{background:{_CARD};border-bottom:1px solid {_BORDA};}}")
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(24, 14, 24, 12); lay.setSpacing(7)

        r1 = QHBoxLayout(); r1.setSpacing(12)
        self._det_badge = QLabel("—")
        self._det_badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self._det_badge.setStyleSheet(f"""
            color:{_MUTED};border:1px solid {_BORDA};border-radius:3px;
            padding:2px 9px;font-family:Consolas;font-size:10px;font-weight:bold;
        """)
        self._det_titulo = QLabel("Selecione um evento")
        self._det_titulo.setStyleSheet(
            f"font-size:14px;font-weight:bold;color:{_TEXTO};font-family:Consolas;")
        self._det_ts = QLabel("")
        self._det_ts.setStyleSheet(f"color:{_MUTED};font-family:Consolas;font-size:11px;")
        r1.addWidget(self._det_badge)
        r1.addWidget(self._det_titulo, 1)
        r1.addWidget(self._det_ts)
        lay.addLayout(r1)

        self._det_resumo = QLabel("")
        self._det_resumo.setStyleSheet(
            f"color:{_MUTED};font-family:Consolas;font-size:11px;")
        lay.addWidget(self._det_resumo)
        return frame

    def _mk_abas(self):
        frame = QFrame(); frame.setFixedHeight(38)
        frame.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border-bottom:1px solid {_BORDA};}}")
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(24, 0, 24, 0); lay.setSpacing(0)
        self._btn_analise    = self._mk_btn_aba("ANÁLISE",    "analise",   True)
        self._btn_evidencias = self._mk_btn_aba("EVIDÊNCIAS", "evidencias")
        self._btn_pratica    = self._mk_btn_aba("NA PRÁTICA", "pratica")
        lay.addWidget(self._btn_analise)
        lay.addWidget(self._btn_evidencias)
        lay.addWidget(self._btn_pratica)
        lay.addStretch()
        return frame

    def _mk_btn_aba(self, texto, id_aba, ativo=False):
        btn = QPushButton(texto)
        btn.setCheckable(True); btn.setChecked(ativo)
        btn.setFixedHeight(38)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._estilo_aba(btn, ativo)
        btn.clicked.connect(lambda: self._trocar_aba(id_aba))
        return btn

    def _estilo_aba(self, btn, ativo):
        cor_txt = _TEXTO if ativo else _MUTED
        borda_b = _ACCENT if ativo else "transparent"
        peso    = "bold" if ativo else "normal"
        hover   = f"QPushButton:hover{{color:{_TEXTO};}}" if not ativo else ""
        btn.setStyleSheet(f"""
            QPushButton{{
                background:transparent;color:{cor_txt};border:none;
                border-bottom:2px solid {borda_b};border-radius:0;
                padding:0 16px;font-size:10px;font-weight:{peso};
                letter-spacing:1px;margin-bottom:-1px;
            }}
            {hover}
        """)

    def _mk_rodape(self):
        frame = QFrame(); frame.setFixedHeight(30)
        frame.setStyleSheet(
            f"QFrame{{background:{_SURFACE};border-top:1px solid {_BORDA};}}")
        lay = QHBoxLayout(frame); lay.setContentsMargins(16, 0, 16, 0)
        self._lbl_status = QLabel("Aguardando captura")
        self._lbl_status.setStyleSheet(f"color:{_MUTED};font-size:10px;")
        self._lbl_stats  = QLabel("Rede: — | Pacotes: 0 | Dados: 0 B")
        self._lbl_stats.setStyleSheet(
            f"color:{_DIM};font-family:Consolas;font-size:10px;")
        lay.addWidget(self._lbl_status); lay.addStretch()
        lay.addWidget(self._lbl_stats)
        return frame

    # ── Filtros ────────────────────────────────────────────────

    def _ao_badge(self, proto):
        self._filtro_proto = proto
        for p, b in self._badges.items():
            b.set_ativo(p == proto)
        self._filtrar()

    def _passa(self, e):
        if self._filtro_proto != "Todos" and e.get("tipo", "") != self._filtro_proto:
            return False
        if self._filtro_texto:
            campo = (f"{e.get('ip_origem','')} {e.get('ip_destino','')} "
                     f"{e.get('titulo','')} {e.get('dominio','')}").lower()
            if self._filtro_texto not in campo:
                return False
        return True

    def _filtrar(self):
        """O(n) show/hide — sem recriar widgets."""
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
        self._lbl_contagem.setText(f"{visiveis} / {len(self._todos_eventos)}")

    # ── Lista ──────────────────────────────────────────────────

    def _inserir_item(self, evento):
        widget = _ItemWidget(evento)
        item   = QListWidgetItem()
        item.setSizeHint(QSize(260, 66))
        self._lista.addItem(item)
        self._lista.setItemWidget(item, widget)
        self._item_map.append((evento, item, widget))
        if not self._passa(evento):
            item.setHidden(True)

    def _ao_selecionar(self):
        items = self._lista.selectedItems()
        if not items:
            return
        row = self._lista.row(items[0])
        # row refere-se à posição no QListWidget (inclui ocultos).
        # Buscamos o evento pelo índice direto no _item_map.
        if 0 <= row < len(self._item_map):
            self._evento_atual = self._item_map[row][0]
            self._renderizar()

    # ── Detalhe ────────────────────────────────────────────────

    def _trocar_aba(self, id_aba):
        self._aba_ativa = id_aba
        for btn, tid in [(self._btn_analise, "analise"),
                         (self._btn_evidencias, "evidencias"),
                         (self._btn_pratica, "pratica")]:
            ativo = (tid == id_aba)
            btn.setChecked(ativo)
            self._estilo_aba(btn, ativo)
        self._renderizar()

    def _renderizar(self):
        e = self._evento_atual
        if not e:
            return
        tipo = e.get("tipo", "")
        cor  = _cor(tipo)
        r, g, b = _rgb(cor)

        self._det_badge.setText(_lbl(tipo))
        self._det_badge.setStyleSheet(f"""
            background:rgba({r},{g},{b},28); color:{cor};
            border:1px solid rgba({r},{g},{b},65); border-radius:3px;
            padding:2px 9px; font-family:Consolas;
            font-size:10px; font-weight:bold;
        """)
        titulo = (e.get("dominio") or e.get("titulo")
                  or f"{e.get('ip_origem','')} → {e.get('ip_destino','')}")
        if len(str(titulo)) > 64:
            titulo = str(titulo)[:62] + "…"
        self._det_titulo.setText(str(titulo))
        self._det_ts.setText(e.get("timestamp", ""))
        resumo = f"{e.get('ip_origem','')}  →  {e.get('ip_destino','')}"
        if e.get("tamanho"):
            resumo += f"    ·    {e.get('tamanho')} bytes"
        self._det_resumo.setText(resumo)
        self._lbl_status.setText(
            f"{tipo} — {e.get('ip_origem','')} → {e.get('ip_destino','')}")

        # Limpa conteúdo anterior
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

    # ── Helpers de renderização ────────────────────────────────

    _CSS_BASE = f"""
        body{{font-family:'Segoe UI',Arial,sans-serif;font-size:11px;
              color:{_TEXTO};line-height:1.7;margin:0;padding:0;}}
        b{{color:{_TEXTO};}} i{{color:{_MUTED};}}
        code{{background:rgba(255,255,255,0.07);padding:1px 5px;
              border-radius:3px;font-family:Consolas;font-size:10px;color:#a8d8ff;}}
        table{{border-collapse:collapse;width:100%;}}
        td{{padding:3px 12px 3px 0;vertical-align:top;}}
    """

    def _browser(self, html, muted=False):
        tb = QTextBrowser()
        tb.setOpenExternalLinks(False)
        tb.setReadOnly(True)
        tb.setStyleSheet(f"""
            QTextBrowser{{
                background:{_CARD};border:1px solid {_BORDA};
                border-radius:5px;color:{"" + _MUTED if muted else _TEXTO};
                font-size:11px;padding:14px;
                selection-background-color:{_SEL};
            }}
            QScrollBar:vertical{{background:{_CARD};width:6px;border-radius:3px;}}
            QScrollBar::handle:vertical{{background:#2c3e50;border-radius:3px;min-height:16px;}}
            QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
        """)
        tb.setHtml(html)
        tb.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        return tb

    def _secao(self, titulo):
        w = QWidget(); w.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(w); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(10)
        lbl = QLabel(titulo)
        lbl.setStyleSheet(
            f"color:{_MUTED};font-size:9px;font-weight:bold;letter-spacing:1px;")
        lay.addWidget(lbl)
        return w

    # ── Conteúdo das abas ──────────────────────────────────────

    def _aba_analise(self, e):
        s1 = self._secao("O QUE ACONTECEU")
        s1.layout().addWidget(self._browser(f"""
            <style>{self._CSS_BASE}</style>
            <body>
              <div style="border-left:3px solid {_ACCENT};padding:0 0 0 12px;margin:0;">
                {e.get("nivel1","Análise não disponível.")}
              </div>
            </body>
        """))
        self._lay_c.insertWidget(0, s1)

        s2 = self._secao("COMO O PROTOCOLO FUNCIONA")
        s2.layout().addWidget(self._browser(f"""
            <style>{self._CSS_BASE.replace(_TEXTO, _MUTED, 1)}</style>
            <body>{e.get("nivel2","Informação técnica não disponível.")}</body>
        """, muted=True))
        self._lay_c.insertWidget(1, s2)

        alerta = e.get("alerta_seguranca", "")
        nivel  = e.get("nivel", "INFO")
        if alerta:
            cor_al = "#E74C3C" if nivel == "CRITICO" else "#E67E22"
            ra, ga, ba = _rgb(cor_al)
            s3 = self._secao("ALERTA DE SEGURANÇA")
            lbl = QLabel(f"⚠  {alerta}")
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"""
                background:rgba({ra},{ga},{ba},16);
                border:1px solid rgba({ra},{ga},{ba},55);
                border-left:3px solid {cor_al};border-radius:5px;
                padding:10px 14px;font-size:11px;color:{cor_al};
            """)
            s3.layout().addWidget(lbl)
            self._lay_c.insertWidget(2, s3)

    def _aba_evidencias(self, e):
        s1 = self._secao("CAMPOS DO PACOTE")
        grid = QFrame()
        grid.setStyleSheet(
            f"QFrame{{background:{_CARD};border:1px solid {_BORDA};border-radius:5px;}}")
        gl = QVBoxLayout(grid); gl.setContentsMargins(0,0,0,0); gl.setSpacing(0)
        campos = [
            ("IP Origem",     e.get("ip_origem",  "—")),
            ("IP Destino",    e.get("ip_destino", "—")),
            ("Protocolo",     e.get("protocolo",  e.get("tipo","—"))),
            ("Porta Destino", str(e.get("porta_destino") or "—")),
            ("Tamanho",       f"{e.get('tamanho',0)} bytes"),
            ("Cifrado",       "Sim (TLS)" if e.get("tipo")=="HTTPS" else "Não"),
        ]
        for i, (rot, val) in enumerate(campos):
            sep_b = f"border-bottom:1px solid {_BORDA};" if i < len(campos)-1 else ""
            linha = QFrame()
            linha.setStyleSheet(f"QFrame{{{sep_b}background:transparent;}}")
            ll = QHBoxLayout(linha); ll.setContentsMargins(14,9,14,9)
            lr = QLabel(rot); lr.setFixedWidth(115)
            lr.setStyleSheet(f"color:{_MUTED};font-size:10px;")
            lv = QLabel(str(val))
            lv.setStyleSheet(f"color:{_TEXTO};font-family:Consolas;font-size:10px;")
            ll.addWidget(lr); ll.addWidget(lv, 1)
            gl.addWidget(linha)
        s1.layout().addWidget(grid)
        self._lay_c.insertWidget(0, s1)

        n3 = e.get("nivel3", "")
        if n3:
            s2 = self._secao("DETALHES TÉCNICOS")
            s2.layout().addWidget(self._browser(f"""
                <style>{self._CSS_BASE}</style>
                <body>{n3}</body>
            """))
            self._lay_c.insertWidget(1, s2)

    def _aba_pratica(self, e):
        mapa = {
            "HTTPS":   "Tráfego normal e seguro. O TLS cifra todo o conteúdo — URL, headers e corpo ficam ilegíveis na rede. Analise o SNI para identificar o serviço sem descriptografar.",
            "HTTP":    "Tráfego em texto puro. URL, cabeçalhos e corpo visíveis para qualquer capturador na mesma rede. Solução: migrar para HTTPS com HSTS.",
            "DNS":     "Consultas DNS revelam a intenção de navegação. Sem DoH/DoT, qualquer dispositivo na rede pode mapear os domínios acessados.",
            "ARP":     "Protocolo sem autenticação — vulnerável a ARP Spoofing. Em redes corporativas, ative Dynamic ARP Inspection (DAI) no switch.",
            "ICMP":    "Diagnóstico de conectividade. O TTL revela saltos e permite estimar o sistema operacional do remetente.",
            "TCP_SYN": "Início do 3-way handshake TCP. Flood de SYNs sem ACK = ataque SYN Flood, que esgota a tabela de conexões do servidor.",
            "DHCP":    "Distribuição automática de IPs. Sem autenticação — rogue DHCP server pode distribuir gateway e DNS falsos. Ative DHCP Snooping.",
            "SSH":     "Acesso remoto completamente cifrado. Prefira autenticação por par de chaves em vez de senha.",
            "FTP":     "Credenciais e conteúdo em texto puro. Use SFTP (porta 22) ou FTPS como alternativa segura.",
            "SMB":     "Compartilhamento de arquivos. Desabilite SMBv1 (EternalBlue/WannaCry). Ative SMB Signing.",
            "RDP":     "Desktop remoto. Acesse somente via VPN, habilite NLA e monitore eventos 4624/4625.",
        }
        texto = mapa.get(e.get("tipo",""), "Análise operacional baseada no fluxo detectado.")
        s1 = self._secao("SIGNIFICADO OPERACIONAL")
        s1.layout().addWidget(self._browser(f"""
            <style>{self._CSS_BASE}</style>
            <body>
              <div style="border-left:3px solid {_ACCENT};padding:0 0 0 12px;margin:0;">
                {texto}
              </div>
            </body>
        """))
        self._lay_c.insertWidget(0, s1)

        n4 = e.get("nivel4", "")
        if n4:
            s2 = self._secao("PAYLOAD BRUTO")
            tb = self._browser(f"""
                <style>body{{font-family:Consolas;font-size:10px;
                             color:{_TEXTO};line-height:1.5;margin:0;padding:0;}}</style>
                <body>{n4}</body>
            """)
            tb.setStyleSheet(tb.styleSheet().replace(
                f"background:{_CARD}", "background:#000408", 1))
            s2.layout().addWidget(tb)
            self._lay_c.insertWidget(1, s2)

    # ── API pública ────────────────────────────────────────────

    def adicionar_evento(self, e):
        e["titulo"] = corrigir_mojibake(e.get("titulo", "Evento"))
        for k in ("nivel1","nivel2","nivel3","nivel4","alerta_seguranca"):
            if k in e:
                e[k] = corrigir_mojibake(e[k])

        self._todos_eventos.append(e)
        tipo = e.get("tipo", "OUTRO")
        self._contadores[tipo] += 1
        self._contadores["Todos"] += 1

        for proto, badge in self._badges.items():
            badge.set_count(self._contadores[proto])

        self._inserir_item(e)

        visiveis = sum(1 for _, it, _ in self._item_map if not it.isHidden())
        self._lbl_contagem.setText(f"{visiveis} / {len(self._todos_eventos)}")

    def limpar(self):
        self._todos_eventos.clear()
        self._item_map.clear()
        self._lista.clear()
        self._contadores.clear()
        self._evento_atual = None
        for b in self._badges.values():
            b.set_count(0)
        self._det_titulo.setText("Selecione um evento")
        self._det_ts.setText("")
        self._det_resumo.setText("")
        self._det_badge.setText("—")
        self._det_badge.setStyleSheet(f"""
            color:{_MUTED};border:1px solid {_BORDA};border-radius:3px;
            padding:2px 9px;font-family:Consolas;font-size:10px;font-weight:bold;
        """)
        self._lbl_contagem.setText("0 / 0")
        self._lbl_status.setText("Aguardando captura")
        while self._lay_c.count() > 1:
            it = self._lay_c.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def atualizar_stats(self, pacotes, rede, dados):
        self._lbl_stats.setText(
            f"Rede: {rede}  |  Pacotes: {pacotes:,}  |  Dados: {dados}")

    def _reaplicar_filtros(self):
        """Chamado pela janela principal ao trocar de aba (lazy-load)."""
        self._filtrar()