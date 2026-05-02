# interface/painel_eventos.py
# Painel do Modo Análise — Design Premium v4.2 (Cores Padronizadas)
#
# ESTRUTURA:
#   - Topbar: Título, Filtros por Badge, Busca
#   - Main: Splitter com Lista (Esquerda) e Detalhes (Direita)
#   - Detalhes: Header + Navegação por Abas (Análise, Evidências, Na Prática)
#   - Rodapé: Status de captura e estatísticas de rede

from collections import defaultdict, deque
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton, QTextEdit,
    QSplitter, QTabWidget, QLineEdit, QComboBox,
    QTableWidget, QProgressBar, QGridLayout, QListWidget, QListWidgetItem,
    QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSlot, QRect, QSize
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QIcon

from utils.constantes import CLASSIFICACAO_USO
from utils.rede import formatar_bytes, corrigir_mojibake

# ─────────────────────────────────────────────────────────────
# Design Tokens (Sincronizados com tema_escuro.qss)
# ─────────────────────────────────────────────────────────────
COLORS = {
    "bg":       "#0f1423", # Fundo principal QMainWindow
    "surface":  "#12162a", # Fundo QMenuBar / QToolBar
    "card":     "#0d1120", # Fundo QTableWidget
    "border":   "#1e2d40", # Borda padrão
    "border2":  "#2c3e50", # Borda destaque (Scrollbar handle)
    "text":     "#ecf0f1", # Texto principal
    "muted":    "#7f8c8d", # Texto secundário
    "dim":      "#566573", # Texto muito discreto
    "https":    "#3498DB", # Azul padrão
    "http":     "#E74C3C", # Vermelho padrão
    "dns":      "#9B59B6", # Roxo/Violeta
    "arp":      "#E67E22", # Laranja/Amber
    "icmp":     "#1ABC9C", # Verde água/Teal
    "syn":      "#9B59B6", # Roxo/Violeta
    "green":    "#2ECC71", # Verde padrão
}

PROTO_CONFIG = {
    "HTTPS":    {"color": COLORS["https"], "label": "HTTPS"},
    "HTTP":     {"color": COLORS["http"],  "label": "HTTP"},
    "DNS":      {"color": COLORS["dns"],   "label": "DNS"},
    "ARP":      {"color": COLORS["arp"],   "label": "ARP"},
    "ICMP":     {"color": COLORS["icmp"],  "label": "ICMP"},
    "TCP_SYN":  {"color": COLORS["syn"],   "label": "SYN"},
    "OUTRO":    {"color": COLORS["muted"], "label": "PKT"},
}

# ─────────────────────────────────────────────────────────────
# Componente: Badge de Protocolo (Filtro)
# ─────────────────────────────────────────────────────────────

class ProtocolBadge(QPushButton):
    def __init__(self, proto: str, count: int = 0, active: bool = False, parent=None):
        super().__init__(parent)
        self.proto = proto
        self.count = count
        self.active = active
        self.setCheckable(True)
        self.setChecked(active)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._update_style()

    def set_count(self, count: int):
        self.count = count
        self._update_style()

    def _update_style(self):
        cfg = PROTO_CONFIG.get(self.proto, PROTO_CONFIG["OUTRO"])
        cor = cfg["color"]
        opacity = "1.0" if self.isChecked() else "0.45"
        # Fundo levemente colorido se ativo, transparente se inativo
        bg = f"rgba({QColor(cor).red()}, {QColor(cor).green()}, {QColor(cor).blue()}, 0.15)" if self.isChecked() else "transparent"
        border = f"1px solid {cor}40" if self.isChecked() else f"1px solid transparent"
        
        self.setText(f"{self.proto}  {self.count}")
        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {cor};
                border: {border};
                border-radius: 4px;
                padding: 3px 10px;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
                font-size: 10px;
                font-weight: bold;
                opacity: {opacity};
            }}
            QPushButton:hover {{ opacity: 0.85; background: {cor}20; }}
        """)

# ─────────────────────────────────────────────────────────────
# Painel principal de Eventos
# ─────────────────────────────────────────────────────────────

class PainelEventos(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._todos_eventos = deque(maxlen=150)
        self._eventos_filtrados = []
        self._evento_atual = None
        self._filtro_protocolo = "Todos"
        self._filtro_texto = ""
        self._aba_ativa = "analise"
        self._badges = {}
        self._contadores = defaultdict(int)

        self.setStyleSheet(f"background: {COLORS['bg']}; color: {COLORS['text']};")
        self._montar_layout()

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 1. Topbar
        topbar = QFrame()
        topbar.setFixedHeight(45)
        topbar.setStyleSheet(f"background: {COLORS['surface']}; border-bottom: 1px solid {COLORS['border']};")
        top_layout = QHBoxLayout(topbar)
        top_layout.setContentsMargins(16, 0, 16, 0)
        top_layout.setSpacing(12)

        title = QLabel("MODO ANÁLISE")
        title.setStyleSheet(f"color: {COLORS['muted']}; font-size: 10px; font-weight: bold; letter-spacing: 1px;")
        top_layout.addWidget(title)

        sep = QFrame()
        sep.setFixedSize(1, 16)
        sep.setStyleSheet(f"background: {COLORS['border']};")
        top_layout.addWidget(sep)

        # Badges de Filtro
        self.badge_container = QWidget()
        self.badge_layout = QHBoxLayout(self.badge_container)
        self.badge_layout.setContentsMargins(0, 0, 0, 0)
        self.badge_layout.setSpacing(6)
        
        protos = ["Todos", "HTTPS", "DNS", "ARP", "HTTP", "ICMP", "TCP_SYN"]
        for p in protos:
            b = ProtocolBadge(p, active=(p == "Todos"))
            b.clicked.connect(lambda checked, proto=p: self._ao_clicar_badge(proto))
            self._badges[p] = b
            self.badge_layout.addWidget(b)
        
        top_layout.addWidget(self.badge_container)
        top_layout.addStretch()

        self.campo_busca = QLineEdit()
        self.campo_busca.setPlaceholderText("Buscar IP, domínio...")
        self.campo_busca.setFixedWidth(200)
        self.campo_busca.setStyleSheet(f"""
            QLineEdit {{
                background: {COLORS['card']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                color: {COLORS['text']};
                padding: 4px 10px;
                font-size: 11px;
            }}
            QLineEdit:focus {{ border-color: {COLORS['https']}; }}
        """)
        self.campo_busca.textChanged.connect(self._ao_mudar_busca)
        top_layout.addWidget(self.campo_busca)
        layout.addWidget(topbar)

        # 2. Main Area
        main_area = QSplitter(Qt.Orientation.Horizontal)
        main_area.setHandleWidth(2)
        main_area.setStyleSheet(f"QSplitter::handle {{ background: {COLORS['border']}; }}")

        # Lista (Esquerda)
        painel_lista = QFrame()
        painel_lista.setFixedWidth(300)
        l_lista = QVBoxLayout(painel_lista)
        l_lista.setContentsMargins(0, 0, 0, 0)
        l_lista.setSpacing(0)

        h_lista = QFrame()
        h_lista.setFixedHeight(34)
        h_lista.setStyleSheet(f"border-bottom: 1px solid {COLORS['border']}; background: {COLORS['surface']};")
        h_layout = QHBoxLayout(h_lista)
        h_layout.setContentsMargins(14, 0, 14, 0)
        
        lbl_h = QLabel("EVENTOS CAPTURADOS")
        lbl_h.setStyleSheet(f"color: {COLORS['muted']}; font-size: 9px; font-weight: bold; letter-spacing: 1px;")
        self.lbl_contagem = QLabel("0 / 0")
        self.lbl_contagem.setStyleSheet(f"color: {COLORS['dim']}; font-family: 'Consolas'; font-size: 10px;")
        
        h_layout.addWidget(lbl_h)
        h_layout.addStretch()
        h_layout.addWidget(self.lbl_contagem)
        l_lista.addWidget(h_lista)

        self.lista_eventos = QListWidget()
        self.lista_eventos.setStyleSheet(f"""
            QListWidget {{ background: transparent; border: none; }}
            QListWidget::item {{ border-bottom: 1px solid {COLORS['border']}; padding: 0; }}
            QListWidget::item:selected {{ background: rgba(52, 152, 219, 0.12); }}
        """)
        self.lista_eventos.itemSelectionChanged.connect(self._ao_selecionar_evento)
        l_lista.addWidget(self.lista_eventos)
        main_area.addWidget(painel_lista)

        # Detalhes (Direita)
        painel_detalhe = QFrame()
        l_det = QVBoxLayout(painel_detalhe)
        l_det.setContentsMargins(0, 0, 0, 0)
        l_det.setSpacing(0)

        # Header Detalhe
        self.det_header = QFrame()
        self.det_header.setFixedHeight(75)
        self.det_header.setStyleSheet(f"border-bottom: 1px solid {COLORS['border']}; background: {COLORS['card']};")
        l_header = QVBoxLayout(self.det_header)
        l_header.setContentsMargins(20, 14, 20, 10)
        l_header.setSpacing(6)

        row1 = QHBoxLayout()
        self.det_badge = QLabel("—")
        self.det_badge.setStyleSheet("font-family: 'Consolas'; font-size: 10px; font-weight: bold; padding: 2px 8px; border-radius: 4px;")
        self.det_titulo = QLabel("Selecione um evento")
        self.det_titulo.setStyleSheet(f"font-family: 'Consolas'; font-size: 14px; font-weight: bold; color: {COLORS['text']};")
        self.det_ts = QLabel("")
        self.det_ts.setStyleSheet(f"font-family: 'Consolas'; font-size: 11px; color: {COLORS['muted']};")
        
        row1.addWidget(self.det_badge)
        row1.addWidget(self.det_titulo)
        row1.addStretch()
        row1.addWidget(self.det_ts)
        l_header.addLayout(row1)

        self.det_resumo = QLabel("")
        self.det_resumo.setStyleSheet(f"font-size: 11px; color: {COLORS['muted']}; font-family: 'Consolas';")
        l_header.addWidget(self.det_resumo)
        l_det.addWidget(self.det_header)

        # Tab Nav
        tab_nav = QFrame()
        tab_nav.setFixedHeight(36)
        tab_nav.setStyleSheet(f"border-bottom: 1px solid {COLORS['border']}; background: {COLORS['surface']};")
        tn_layout = QHBoxLayout(tab_nav)
        tn_layout.setContentsMargins(20, 0, 20, 0)
        tn_layout.setSpacing(0)

        self.btn_tab_analise = self._criar_tab_btn("ANÁLISE", "analise", True)
        self.btn_tab_evidencias = self._criar_tab_btn("EVIDÊNCIAS", "evidencias")
        self.btn_tab_pratica = self._criar_tab_btn("NA PRÁTICA", "pratica")

        tn_layout.addWidget(self.btn_tab_analise)
        tn_layout.addWidget(self.btn_tab_evidencias)
        tn_layout.addWidget(self.btn_tab_pratica)
        tn_layout.addStretch()
        l_det.addWidget(tab_nav)

        self.scroll_detalhe = QScrollArea()
        self.scroll_detalhe.setWidgetResizable(True)
        self.scroll_detalhe.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        self.container_detalhe = QWidget()
        self.layout_detalhe = QVBoxLayout(self.container_detalhe)
        self.layout_detalhe.setContentsMargins(20, 20, 20, 20)
        self.layout_detalhe.setSpacing(20)
        self.layout_detalhe.addStretch()
        
        self.scroll_detalhe.setWidget(self.container_detalhe)
        l_det.addWidget(self.scroll_detalhe)
        main_area.addWidget(painel_detalhe)
        
        layout.addWidget(main_area)

        # 3. Rodapé
        rodape = QFrame()
        rodape.setFixedHeight(32)
        rodape.setStyleSheet(f"background: {COLORS['surface']}; border-top: 1px solid {COLORS['border']};")
        r_layout = QHBoxLayout(rodape)
        r_layout.setContentsMargins(16, 0, 16, 0)
        
        self.status_texto = QLabel("Aguardando captura")
        self.status_texto.setStyleSheet(f"color: {COLORS['muted']}; font-size: 10px;")
        
        self.stats_rede = QLabel("Rede: — | Pacotes: 0 | Dados: 0 B")
        self.stats_rede.setStyleSheet(f"color: {COLORS['dim']}; font-family: 'Consolas'; font-size: 10px;")
        
        r_layout.addWidget(self.status_texto)
        r_layout.addStretch()
        r_layout.addWidget(self.stats_rede)
        layout.addWidget(rodape)

    def _criar_tab_btn(self, texto, id_tab, ativo=False):
        btn = QPushButton(texto)
        btn.setCheckable(True)
        btn.setChecked(ativo)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedHeight(36)
        
        active_border = f"border-bottom: 2px solid {COLORS['https']}; color: {COLORS['text']};" if ativo else f"border-bottom: 2px solid transparent; color: {COLORS['muted']};"
        btn.setStyleSheet(f"""
            QPushButton {{
                background: none; border: none;
                font-size: 10px; font-weight: bold; letter-spacing: 1px;
                padding: 0 15px; margin-bottom: -1px;
                {active_border}
            }}
            QPushButton:hover {{ color: {COLORS['text']}; }}
        """)
        btn.clicked.connect(lambda: self._trocar_tab(id_tab))
        return btn

    def _trocar_tab(self, id_tab):
        self._aba_ativa = id_tab
        for b, tid in [(self.btn_tab_analise, "analise"), (self.btn_tab_evidencias, "evidencias"), (self.btn_tab_pratica, "pratica")]:
            ativo = (tid == id_tab)
            b.setChecked(ativo)
            active_border = f"border-bottom: 2px solid {COLORS['https']}; color: {COLORS['text']};" if ativo else f"border-bottom: 2px solid transparent; color: {COLORS['muted']};"
            b.setStyleSheet(f"QPushButton {{ background: none; border: none; font-size: 10px; font-weight: bold; letter-spacing: 1px; padding: 0 15px; margin-bottom: -1px; {active_border} }} QPushButton:hover {{ color: {COLORS['text']}; }}")
        self._renderizar_detalhes()

    def _ao_clicar_badge(self, proto):
        self._filtro_protocolo = proto
        for p, b in self._badges.items():
            b.setChecked(p == proto)
            b._update_style()
        self._reaplicar_filtros()

    def _ao_mudar_busca(self, texto):
        self._filtro_texto = texto.lower().strip()
        self._reaplicar_filtros()

    def _reaplicar_filtros(self):
        self.lista_eventos.clear()
        self._eventos_filtrados = [e for e in self._todos_eventos if self._passa_filtro(e)]
        for e in self._eventos_filtrados:
            self._adicionar_item_lista(e)
        self.lbl_contagem.setText(f"{len(self._eventos_filtrados)} / {len(self._todos_eventos)}")

    def _passa_filtro(self, e):
        if self._filtro_protocolo != "Todos" and e.get("tipo", "") != self._filtro_protocolo: return False
        if self._filtro_texto:
            text = f"{e.get('ip_origem','')} {e.get('ip_destino','')} {e.get('titulo','')} {e.get('dominio','')}".lower()
            if self._filtro_texto not in text: return False
        return True

    def _adicionar_item_lista(self, e):
        item = QListWidgetItem()
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 9, 14, 9)
        layout.setSpacing(2)

        row1 = QHBoxLayout()
        cfg = PROTO_CONFIG.get(e.get("tipo", "OUTRO"), PROTO_CONFIG["OUTRO"])
        pill = QLabel(cfg["label"])
        # Fundo leve da pílula na lista
        pill.setStyleSheet(f"background: {cfg['color']}33; color: {cfg['color']}; font-family: 'Consolas'; font-size: 9px; font-weight: bold; padding: 1px 5px; border-radius: 3px;")
        
        ips = QLabel(f"{e.get('ip_origem','')} → {e.get('ip_destino','')}")
        ips.setStyleSheet(f"font-family: 'Consolas'; font-size: 11px; color: {COLORS['text']};")
        row1.addWidget(pill)
        row1.addWidget(ips)
        row1.addStretch()
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        ts = QLabel(e.get("timestamp", ""))
        ts.setStyleSheet(f"font-family: 'Consolas'; font-size: 10px; color: {COLORS['muted']};")
        
        sub = e.get("dominio") or e.get("http_caminho") or e.get("mac_origem") or (f"porta {e.get('porta_destino')}" if e.get('porta_destino') else "")
        sub_lbl = QLabel(str(sub))
        sub_lbl.setStyleSheet(f"font-size: 10px; color: {COLORS['dim']};")
        
        row2.addWidget(ts)
        row2.addWidget(sub_lbl)
        row2.addStretch()
        layout.addLayout(row2)

        item.setSizeHint(widget.sizeHint())
        item.setData(Qt.ItemDataRole.UserRole, id(e))
        self.lista_eventos.addItem(item)
        self.lista_eventos.setItemWidget(item, widget)

    def _ao_selecionar_evento(self):
        items = self.lista_eventos.selectedItems()
        if not items: return
        ev_id = items[0].data(Qt.ItemDataRole.UserRole)
        self._evento_atual = next((e for e in self._todos_eventos if id(e) == ev_id), None)
        self._renderizar_detalhes()

    def _renderizar_detalhes(self):
        e = self._evento_atual
        if not e: return

        # Header
        cfg = PROTO_CONFIG.get(e.get("tipo", "OUTRO"), PROTO_CONFIG["OUTRO"])
        self.det_badge.setText(cfg["label"])
        self.det_badge.setStyleSheet(f"background: {cfg['color']}33; color: {cfg['color']}; font-family: 'Consolas'; font-size: 10px; font-weight: bold; padding: 3px 9px; border-radius: 4px;")
        
        titulo = e.get("dominio") or e.get("titulo") or f"{e.get('ip_origem')} → {e.get('ip_destino')}"
        self.det_titulo.setText(str(titulo))
        self.det_ts.setText(e.get("timestamp", ""))
        
        resumo = f"<span style='color:{COLORS['text']}'>{e.get('ip_origem')}</span> → <span style='color:{COLORS['text']}'>{e.get('ip_destino')}</span>"
        if e.get('tamanho'): resumo += f"  ·  <span>{e.get('tamanho')} bytes</span>"
        self.det_resumo.setText(resumo)
        self.status_texto.setText(f"{e.get('tipo')} — {e.get('ip_origem')} → {e.get('ip_destino')}")

        # Limpar tabs
        while self.layout_detalhe.count() > 1:
            item = self.layout_detalhe.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        # Renderizar Aba
        if self._aba_ativa == "analise":
            self._render_tab_analise(e)
        elif self._aba_ativa == "evidencias":
            self._render_tab_evidencias(e)
        else:
            self._render_tab_pratica(e)

    def _render_tab_analise(self, e):
        # O que aconteceu
        sec1 = self._criar_secao("O QUE ACONTECEU")
        call1 = QLabel(e.get("nivel1", "Análise não disponível."))
        call1.setWordWrap(True)
        call1.setStyleSheet(f"background: {COLORS['card']}; border: 1px solid {COLORS['border']}; border-left: 3px solid {COLORS['https']}; border-radius: 7px; padding: 12px; font-size: 12px; color: {COLORS['text']}; line-height: 150%;")
        sec1.layout().addWidget(call1)
        self.layout_detalhe.insertWidget(0, sec1)

        # Como funciona
        sec2 = self._criar_secao("COMO O PROTOCOLO FUNCIONA")
        box2 = QFrame()
        box2.setStyleSheet(f"background: {COLORS['card']}; border: 1px solid {COLORS['border']}; border-radius: 7px;")
        l_box = QVBoxLayout(box2)
        l_box.setSpacing(10)
        
        tecnica = e.get("nivel2", "Informação técnica não disponível.")
        for linha in tecnica.split("\n"):
            if not linha.strip(): continue
            lbl = QLabel(linha.strip())
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color: {COLORS['muted']}; font-size: 11px; line-height: 140%;")
            l_box.addWidget(lbl)
            
        sec2.layout().addWidget(box2)
        self.layout_detalhe.insertWidget(1, sec2)

    def _render_tab_evidencias(self, e):
        sec = self._criar_secao("CAMPOS DO PACOTE")
        grid = QFrame()
        grid.setStyleSheet(f"background: {COLORS['border']}; border: 1px solid {COLORS['border']}; border-radius: 7px;")
        gl = QGridLayout(grid)
        gl.setSpacing(1)
        gl.setContentsMargins(0,0,0,0)

        campos = [
            ("IP ORIGEM", e.get("ip_origem"), COLORS["https"]),
            ("IP DESTINO", e.get("ip_destino"), COLORS["https"]),
            ("PROTOCOLO", e.get("protocolo"), COLORS["text"]),
            ("PORTA DEST", str(e.get("porta_destino") or "—"), COLORS["text"]),
            ("TAMANHO", f"{e.get('tamanho')} B", COLORS["text"]),
            ("CIFRADO", "SIM" if e.get("tipo") == "HTTPS" else "NÃO", COLORS["green"] if e.get("tipo") == "HTTPS" else COLORS["http"]),
        ]

        for i, (c, v, cor) in enumerate(campos):
            f = QFrame()
            f.setStyleSheet(f"background: {COLORS['card']};")
            fl = QVBoxLayout(f)
            fl.setSpacing(2)
            lbl_c = QLabel(c)
            lbl_c.setStyleSheet(f"font-size: 9px; color: {COLORS['muted']}; letter-spacing: 0.5px;")
            lbl_v = QLabel(str(v))
            lbl_v.setStyleSheet(f"font-family: 'Consolas'; font-size: 11px; color: {cor}; font-weight: bold;")
            fl.addWidget(lbl_c)
            fl.addWidget(lbl_v)
            gl.addWidget(f, i // 2, i % 2)

        sec.layout().addWidget(grid)
        self.layout_detalhe.insertWidget(0, sec)

    def _render_tab_pratica(self, e):
        sec = self._criar_secao("SIGNIFICADO OPERACIONAL")
        box = QLabel(self._gerar_interpretacao_operacional(e))
        box.setWordWrap(True)
        # Tom de azul discreto para o box operacional
        box.setStyleSheet(f"background: rgba(52, 152, 219, 0.08); border: 1px solid rgba(52, 152, 219, 0.2); border-radius: 7px; padding: 12px; font-size: 12px; color: {COLORS['https']}; line-height: 150%;")
        sec.layout().addWidget(box)
        self.layout_detalhe.insertWidget(0, sec)

    def _criar_secao(self, titulo):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(8)
        lbl = QLabel(titulo)
        lbl.setStyleSheet(f"color: {COLORS['muted']}; font-size: 9px; font-weight: bold; letter-spacing: 1px;")
        l.addWidget(lbl)
        return w

    def _gerar_interpretacao_operacional(self, e):
        tipo = e.get("tipo", "")
        if tipo == "HTTPS": return "Tráfego normal e esperado. O HTTPS garante privacidade de ponta a ponta. Analise o SNI (Server Name Indication) para identificar o serviço sem precisar descriptografar."
        if tipo == "DNS": return "Consultas DNS revelam a intenção de navegação. DNS em texto puro pode ser monitorado pela rede para mapear o perfil do usuário."
        if tipo == "ARP": return "O ARP é fundamental para a rede local, mas sua falta de autenticação permite ataques de Man-in-the-Middle via ARP Spoofing."
        return "Análise operacional baseada no fluxo detectado."

    def adicionar_evento(self, e):
        e["titulo"] = corrigir_mojibake(e.get("titulo", "Evento"))
        for k in ["nivel1", "nivel2", "nivel3", "nivel4", "alerta_seguranca"]:
            if k in e: e[k] = corrigir_mojibake(e[k])
        self._todos_eventos.append(e)
        self._contadores[e.get("tipo", "OUTRO")] += 1
        self._contadores["Todos"] += 1
        
        # Atualizar badges
        for p, b in self._badges.items():
            b.set_count(self._contadores[p])

        if self._passa_filtro(e):
            self._adicionar_item_lista(e)
            self._eventos_filtrados.append(e)
        
        self.lbl_contagem.setText(f"{len(self._eventos_filtrados)} / {len(self._todos_eventos)}")

    def limpar(self):
        self._todos_eventos.clear()
        self._eventos_filtrados.clear()
        self.lista_eventos.clear()
        self._contadores.clear()
        for b in self._badges.values(): b.set_count(0)
        self.det_titulo.setText("Selecione um evento")
        self.det_ts.setText("")
        self.det_resumo.setText("")
        self.lbl_contagem.setText("0 / 0")

    def atualizar_stats(self, pacotes, rede, dados):
        self.stats_rede.setText(f"Rede: {rede} | Pacotes: {pacotes:,} | Dados: {dados}")
