# interface/janela_principal.py

import threading
import time
import ipaddress
import subprocess
import re
import ctypes
import json
from collections import deque

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QComboBox,
    QMessageBox, QTabWidget,
    QDialog, QHBoxLayout, QTextEdit,
    QProgressBar, QCheckBox, QScrollArea, QFrame, QGroupBox,
    QSizePolicy
)
from PyQt6.QtCore import QTimer, pyqtSlot, QThread, pyqtSignal, QObject, QRunnable, QThreadPool, Qt
from PyQt6.QtGui import QAction, QColor, QFont
import socket
import os
import platform
from datetime import datetime

# ============================================================================
# Seção colapsável reutilizável para o diagnóstico
# ============================================================================

class _SecaoColapsavel(QWidget):
    """
    Seção com cabeçalho clicável que expande/recolhe o conteúdo interno.
    """
    def __init__(self, titulo: str, cor: str, parent=None, colapsado: bool = False):
        super().__init__(parent)
        self._cor = cor

        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 4)
        self.lay.setSpacing(0)

        # Botão cabeçalho
        self.btn = QPushButton()
        self.btn.setCheckable(True)
        self.btn.setChecked(not colapsado)
        self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._titulo_base = titulo
        self._atualizar_texto_botao(not colapsado)
        self.btn.setStyleSheet(f"""
            QPushButton {{
                text-align: left;
                font-weight: bold;
                font-size: 11px;
                color: {cor};
                background: rgba(255,255,255, 0.03);
                border: none;
                border-bottom: 1px solid rgba(255,255,255, 0.05);
                padding: 10px 15px;
                border-radius: 4px 4px 0 0;
            }}
            QPushButton:hover {{ background: rgba(255,255,255, 0.08); }}
            QPushButton:!checked {{ border-radius: 4px; }}
        """)
        self.btn.toggled.connect(self._ao_alternar)

        # Container interno
        self.container = QFrame()
        self.container.setStyleSheet("""
            QFrame {
                background: rgba(0,0,0, 0.12);
                border: 1px solid rgba(255,255,255, 0.05);
                border-top: none;
                border-radius: 0 0 4px 4px;
            }
        """)
        self.c_lay = QVBoxLayout(self.container)
        self.c_lay.setContentsMargins(12, 10, 12, 12)
        self.c_lay.setSpacing(4)

        self.lay.addWidget(self.btn)
        self.lay.addWidget(self.container)

        if colapsado:
            self.container.hide()

    def _atualizar_texto_botao(self, expandido: bool):
        seta = "" if expandido else ""
        self.btn.setText(f"{seta}   {self._titulo_base}")

    def _ao_alternar(self, ativo: bool):
        self.container.setVisible(ativo)
        self._atualizar_texto_botao(ativo)

    def add_widget(self, widget: QWidget):
        self.c_lay.addWidget(widget)

    def add_layout(self, layout):
        self.c_lay.addLayout(layout)


# ============================================================================
# Diálogo de Diagnóstico Avançado — totalmente refatorado
# ============================================================================

class DiagnosticoAvançado(QDialog):
    """
    Painel de diagnóstico completo do NetLab Educacional.

    Verifica e exibe:
      - Privilégios de administrador
      - Versão do Npcap e do Scapy
      - Teste de ping ao gateway com latência real
      - Teste de resolução DNS com tempo de resposta
      - Sinal Wi-Fi (RSSI em %) e qualidade
      - Estatísticas da interface (pacotes, drops, erros via psutil)
      - Fila interna do analisador e eventos pendentes
      - Auto-refresh configurável a cada 3 segundos
      - Exportação completa para arquivo .txt
    """

    # Paleta de cores interna
    _COR_OK    = "#2ecc71"
    _COR_AVISO = "#e67e22"
    _COR_ERRO  = "#e74c3c"
    _COR_INFO  = "#3d9fd3"
    _COR_BG    = "#0a0e1a"
    _COR_SURF  = "#111827"
    _COR_TEXTO = "#ecf0f1"
    _COR_DIM   = "#7f8c8d"

    def __init__(self, janela_principal):
        super().__init__(janela_principal)
        self.main = janela_principal
        self.setWindowTitle("Diagnóstico do Sistema — NetLab Educacional")
        self.setMinimumSize(600, 500)
        self.resize(680, 750)

        # Cache dos resultados para exportação
        self._ultimo_relatorio: dict = {}

        self._construir_ui()

        # Timer de auto-refresh
        self._timer_auto = QTimer(self)
        self._timer_auto.timeout.connect(self.atualizar)

        # Primeira atualização ao abrir
        QTimer.singleShot(100, self.atualizar)

    # ── Construção da interface ──────────────────────────────────────────

    def _construir_ui(self):
        self.setStyleSheet(f"""
            QDialog {{
                background: {self._COR_BG};
                color: {self._COR_TEXTO};
            }}
            QLabel {{ color: {self._COR_TEXTO}; background: transparent; }}
            QCheckBox {{ color: {self._COR_DIM}; font-size: 11px; }}
            QPushButton {{
                background: #1a2540;
                color: #dde6f0;
                border: 1px solid #243352;
                border-radius: 5px;
                padding: 6px 16px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background: #243352; }}
            QScrollBar:vertical {{
                background: {self._COR_BG}; width: 6px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: #2c3e50; border-radius: 3px; min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(20, 20, 20, 16)
        raiz.setSpacing(14)

        # ── Cabeçalho ──────────────────────────────────────────────────
        raiz.addWidget(self._montar_cabecalho())

        # ── Área de rolagem com seções ──────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self._container_secoes = QWidget()
        self._container_secoes.setStyleSheet("background: transparent;")
        self._layout_secoes = QVBoxLayout(self._container_secoes)
        self._layout_secoes.setContentsMargins(0, 0, 0, 0)
        self._layout_secoes.setSpacing(8)
        self._layout_secoes.addStretch()
        scroll.setWidget(self._container_secoes)
        raiz.addWidget(scroll, 1)

        # ── Rodapé ──────────────────────────────────────────────────────
        raiz.addLayout(self._montar_rodape())

    def _montar_cabecalho(self) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: {self._COR_SURF};
                border: 1px solid #1e2d40;
                border-radius: 10px;
                padding: 4px;
            }}
        """)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)

        # Linha superior: título + timestamp
        linha_top = QHBoxLayout()
        lbl_titulo = QLabel("DIAGNÓSTICO DO SISTEMA")
        lbl_titulo.setStyleSheet(
            "font-size: 15px; font-weight: bold; letter-spacing: 1px; color: #ecf0f1;"
        )
        linha_top.addWidget(lbl_titulo)
        linha_top.addStretch()
        self._lbl_timestamp = QLabel("Gerado em: --:--:--")
        self._lbl_timestamp.setStyleSheet(f"color: {self._COR_DIM}; font-size: 10px;")
        linha_top.addWidget(self._lbl_timestamp)
        lay.addLayout(linha_top)

        # Linha da barra de saúde
        linha_saude = QHBoxLayout()
        linha_saude.setSpacing(10)
        self._lbl_saude = QLabel("Verificando…")
        self._lbl_saude.setFixedWidth(130)
        self._lbl_saude.setStyleSheet("font-size: 11px; font-weight: bold;")
        linha_saude.addWidget(self._lbl_saude)

        self._barra_saude = QProgressBar()
        self._barra_saude.setRange(0, 10)
        self._barra_saude.setValue(0)
        self._barra_saude.setFixedHeight(14)
        self._barra_saude.setTextVisible(False)
        self._barra_saude.setStyleSheet("""
            QProgressBar {
                background: #1a2540;
                border-radius: 7px;
                border: none;
            }
            QProgressBar::chunk {
                background: #2ecc71;
                border-radius: 7px;
            }
        """)
        linha_saude.addWidget(self._barra_saude, 1)

        self._lbl_placar = QLabel("0 / 0")
        self._lbl_placar.setFixedWidth(48)
        self._lbl_placar.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._lbl_placar.setStyleSheet(f"color: {self._COR_DIM}; font-family: Consolas; font-size: 10px;")
        linha_saude.addWidget(self._lbl_placar)
        lay.addLayout(linha_saude)

        return frame

    def _montar_rodape(self) -> QHBoxLayout:
        lay = QHBoxLayout()
        lay.setSpacing(8)

        self._chk_auto = QCheckBox("Atualizar a cada 3 s")
        self._chk_auto.toggled.connect(self._ao_alternar_auto_refresh)
        lay.addWidget(self._chk_auto)
        lay.addStretch()

        btn_exportar = QPushButton("Exportar .txt")
        btn_exportar.setToolTip("Salva o relatório completo em arquivo de texto")
        btn_exportar.clicked.connect(self._exportar_relatorio)
        lay.addWidget(btn_exportar)

        btn_atualizar = QPushButton("Atualizar")
        btn_atualizar.clicked.connect(self.atualizar)
        lay.addWidget(btn_atualizar)

        btn_fechar = QPushButton("Fechar")
        btn_fechar.setStyleSheet(
            f"background: {self._COR_INFO}; color: white; font-weight: bold;"
            "border-radius: 5px; padding: 6px 16px;"
        )
        btn_fechar.clicked.connect(self.accept)
        lay.addWidget(btn_fechar)

        return lay

    # ── Atualização principal ────────────────────────────────────────────

    def atualizar(self):
        """Recolhe todos os dados e reconstrói as seções do diagnóstico."""
        self._lbl_timestamp.setText(f"Gerado em: {datetime.now().strftime('%H:%M:%S')}")

        # Coleta de dados
        desc_interface = self.main.combo_interface.currentText()
        nome_iface     = self.main._mapa_interface_nome.get(desc_interface, desc_interface)
        ip_local       = self.main._mapa_interface_ip.get(desc_interface, "") or _obter_ip_local_seguro()
        eh_wifi        = any(p in nome_iface.lower() for p in ("wi-fi", "wifi", "wireless", "ax", "802.11"))
        eh_admin       = self._verificar_admin()
        versao_npcap   = self._versao_npcap()
        versao_scapy   = self._versao_scapy()
        info_dns        = self._testar_dns()
        info_gateway   = self._testar_ping_gateway()
        info_wifi      = self._sinal_wifi() if eh_wifi else None
        info_iface     = self._stats_interface(nome_iface)
        snap           = self.main._snapshot_atual

        # Monta relatorio para exportação
        self._ultimo_relatorio = {
            "timestamp":     datetime.now().isoformat(),
            "interface":     desc_interface,
            "nome_iface":    nome_iface,
            "ip_local":      ip_local,
            "eh_admin":      eh_admin,
            "versao_npcap":  versao_npcap,
            "versao_scapy":  versao_scapy,
            "dns":           info_dns,
            "gateway":       info_gateway,
            "wifi":          info_wifi,
            "iface":         info_iface,
            "snap":          snap,
        }

        # Calcula pontuação de saúde
        pontos_total    = 0
        pontos_obtidos  = 0
        problemas       = []
        avisos          = []

        def _checar(condicao: bool, peso: int, problema: str, aviso: str = ""):
            nonlocal pontos_total, pontos_obtidos
            pontos_total += peso
            if condicao:
                pontos_obtidos += peso
            elif aviso:
                avisos.append(aviso)
            else:
                problemas.append(problema)

        _checar(eh_admin,                    3, "Executar como Administrador")
        _checar(versao_npcap != "N/A",       3, "Npcap não instalado ou não detectado")
        _checar(versao_scapy != "N/A",       1, "Scapy não instalado")
        _checar(info_dns["ok"] and (info_dns.get("tempo_ms") or 0) <= 150, 1, "Resolução DNS falhou", "DNS lento" if info_dns["ok"] else "")
        _checar(info_gateway["ok"] and (info_gateway.get("latencia_ms") or 0) <= 50, 1, "Gateway inacessível", "Latência alta ao gateway" if info_gateway["ok"] else "")
        _checar(info_iface.get("drops", 0) == 0, 1, "",
                f"Drops detectados: {info_iface.get('drops', 0)} pacotes" if info_iface.get("drops", 0) > 0 else "")

        # Reconstrói seções
        self._limpar_secoes()

        self._adicionar_secao_checklist(eh_admin, versao_npcap, versao_scapy,
                                         info_dns, info_gateway)
        self._adicionar_secao_interface(desc_interface, nome_iface, ip_local,
                                         eh_wifi, info_iface, snap)
        if eh_wifi:
            self._adicionar_secao_wifi(info_wifi)
        self._adicionar_secao_versoes(versao_npcap, versao_scapy)
        self._adicionar_secao_rede(info_dns, info_gateway)
        if avisos or problemas:
            self._adicionar_secao_pendencias(problemas, avisos)

        # Atualiza barra de saúde com cor dinâmica
        self._barra_saude.setMaximum(pontos_total)
        self._barra_saude.setValue(pontos_obtidos)
        proporcao = pontos_obtidos / max(pontos_total, 1)
        if proporcao >= 0.8:
            cor_chunk = self._COR_OK
            status = "Sistema saudável"
        elif proporcao >= 0.5:
            cor_chunk = self._COR_AVISO
            status = "Atenção necessária"
        else:
            cor_chunk = self._COR_ERRO
            status = "Problemas encontrados"

        self._barra_saude.setStyleSheet(f"""
            QProgressBar {{
                background: #1a2540; border-radius: 7px; border: none;
            }}
            QProgressBar::chunk {{
                background: {cor_chunk}; border-radius: 7px;
            }}
        """)
        self._lbl_saude.setText(status)
        self._lbl_saude.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {cor_chunk};")
        self._lbl_placar.setText(f"{pontos_obtidos} / {pontos_total}")

    # ── Construção das seções ────────────────────────────────────────────

    def _limpar_secoes(self):
        """Remove todas as seções existentes antes de reconstruir."""
        while self._layout_secoes.count() > 1:
            item = self._layout_secoes.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _adicionar_secao_checklist(self, eh_admin, versao_npcap, versao_scapy,
                                     info_dns, info_gateway):
        secao = _SecaoColapsavel("  Checklist Rápido", self._COR_INFO)

        itens_html = "<div style='line-height:1.9;'>"
        itens_html += self._item_check(eh_admin, "Privilégios de Administrador",
                                        "Execute via 'Executar como Administrador'" if not eh_admin else "")
        itens_html += self._item_check(versao_npcap != "N/A",
                                        f"Npcap: {versao_npcap}",
                                        "Instale em npcap.com com 'WinPcap API-compatible mode'" if versao_npcap == "N/A" else "")
        itens_html += self._item_check(versao_scapy != "N/A",
                                        f"Scapy: {versao_scapy}",
                                        "pip install scapy" if versao_scapy == "N/A" else "")
        itens_html += self._item_check(info_dns["ok"],
                                        f"DNS: {info_dns['texto']}",
                                        "Verifique conexão com a internet" if not info_dns["ok"] else "")
        itens_html += self._item_check(info_gateway["ok"],
                                        f"Gateway: {info_gateway['texto']}",
                                        "Roteador inacessível" if not info_gateway["ok"] else "")
        itens_html += "</div>"

        lbl = QLabel(itens_html)
        lbl.setWordWrap(True)
        lbl.setStyleSheet("font-size: 11px;")
        secao.add_widget(lbl)
        self._inserir_secao(secao)

    def _adicionar_secao_interface(self, desc, nome, ip, eh_wifi, info_iface, snap):
        secao = _SecaoColapsavel("  Interface e Estatísticas", "#9B59B6")

        total_bytes   = snap.get("total_bytes", 0)
        total_pacotes = snap.get("total_pacotes", 0)
        kb = total_bytes / 1024

        linhas = [
            ("Interface selecionada", desc),
            ("Nome do dispositivo",   nome or "—"),
            ("IP local",              ip or "—"),
            ("Tipo",                  "Wi-Fi / Wireless" if eh_wifi else "Cabeado / Ethernet"),
            ("Pacotes capturados",    f"{total_pacotes:,}"),
            ("Volume total",          f"{kb/1024:.2f} MB" if kb > 1024 else f"{kb:.1f} KB"),
        ]

        # Adiciona contadores de erro/drop se psutil disponível
        if info_iface.get("disponivel"):
            drops   = info_iface.get("drops", 0)
            erros   = info_iface.get("erros", 0)
            cor_drop = self._COR_ERRO if drops > 0 else self._COR_OK
            cor_err  = self._COR_ERRO if erros > 0 else self._COR_OK
            linhas.append(("Pacotes descartados",
                            f"<span style='color:{cor_drop};'>{drops}</span>" +
                            ("  pacotes perdidos antes do Npcap" if drops > 0 else " ")))
            linhas.append(("Erros de recepção",
                            f"<span style='color:{cor_err};'>{erros}</span>" +
                            ("  verifique o driver da placa" if erros > 0 else " ")))
        else:
            linhas.append(("Drops/Erros",
                            "<span style='color:#7f8c8d;'>Instale psutil para monitorar (pip install psutil)</span>"))

        lbl = QLabel(self._tabela_html(linhas))
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        secao.add_widget(lbl)
        self._inserir_secao(secao)

    def _adicionar_secao_wifi(self, info_wifi):
        secao = _SecaoColapsavel("  Sinal Wi-Fi", self._COR_AVISO, colapsado=False)

        if info_wifi and info_wifi.get("disponivel"):
            sinal_pct = info_wifi.get("sinal_pct", 0)
            ssid      = info_wifi.get("ssid", "—")
            bssid     = info_wifi.get("bssid", "—")
            canal     = info_wifi.get("canal", "—")
            velocidade= info_wifi.get("velocidade", "—")

            if sinal_pct >= 70:
                cor_sinal = self._COR_OK
                qualidade = "Excelente"
            elif sinal_pct >= 45:
                cor_sinal = self._COR_AVISO
                qualidade = "Bom"
            else:
                cor_sinal = self._COR_ERRO
                qualidade = "Fraco — captura pode ser instável"

            linhas = [
                ("SSID",          ssid),
                ("BSSID",         bssid),
                ("Sinal",         f"<span style='color:{cor_sinal};'>{sinal_pct}% — {qualidade}</span>"),
                ("Canal",         str(canal)),
                ("Velocidade",    velocidade),
            ]

            # Aviso importante sobre modo promíscuo em Wi-Fi
            aviso_html = (
                "<div style='margin-top:8px; background:rgba(230,126,34,0.1); "
                "border-left:3px solid #e67e22; padding:8px 10px; border-radius:4px; "
                "font-size:10px; color:#e67e22;'>"
                "<b>Limitação Wi-Fi:</b> no Windows, o driver impede a captura de frames "
                "de outros dispositivos em modo promíscuo. Para demonstração em sala, "
                "use o <b>Hotspot do Windows</b> e conecte os colegas nele."
                "</div>"
            )

            conteudo = QLabel(self._tabela_html(linhas) + aviso_html)
            conteudo.setWordWrap(True)
            conteudo.setTextFormat(Qt.TextFormat.RichText)
        else:
            conteudo = QLabel(
                "<span style='color:#7f8c8d;'>Dados de sinal não disponíveis. "
                "Verifique se a interface Wi-Fi está ativa.</span>"
            )
        secao.add_widget(conteudo)
        self._inserir_secao(secao)

    def _adicionar_secao_versoes(self, versao_npcap, versao_scapy):
        secao = _SecaoColapsavel("  Versões dos Componentes", "#16A085", colapsado=True)

        linhas = [
            ("Python",  platform.python_version()),
            ("Npcap",   versao_npcap),
            ("Scapy",   versao_scapy),
            ("PyQt6",   self._versao_pyqt6()),
            ("Sistema", f"{platform.system()} {platform.release()} ({platform.machine()})"),
        ]
        lbl = QLabel(self._tabela_html(linhas))
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        secao.add_widget(lbl)
        self._inserir_secao(secao)

    def _adicionar_secao_rede(self, info_dns, info_gateway):
        secao = _SecaoColapsavel("  Conectividade de Rede", self._COR_INFO)

        linhas = []

        # Gateway
        cor_gw = self._COR_OK if info_gateway["ok"] else self._COR_ERRO
        linhas.append(("Ping ao gateway",
                        f"<span style='color:{cor_gw};'>{info_gateway['texto']}</span>"))

        # Detalhes do ping
        if info_gateway.get("latencia_ms") is not None:
            lat = info_gateway["latencia_ms"]
            cor_lat = self._COR_OK if lat < 10 else (self._COR_AVISO if lat < 50 else self._COR_ERRO)
            linhas.append(("Latência",
                            f"<span style='color:{cor_lat};'>{lat} ms</span>"))

        # DNS
        cor_dns = self._COR_OK if info_dns["ok"] else self._COR_ERRO
        linhas.append(("Resolução DNS",
                        f"<span style='color:{cor_dns};'>{info_dns['texto']}</span>"))

        if info_dns.get("tempo_ms") is not None:
            t = info_dns["tempo_ms"]
            cor_t = self._COR_OK if t < 50 else (self._COR_AVISO if t < 200 else self._COR_ERRO)
            linhas.append(("Tempo DNS",
                            f"<span style='color:{cor_t};'>{t} ms</span>"))

        lbl = QLabel(self._tabela_html(linhas))
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        secao.add_widget(lbl)
        self._inserir_secao(secao)

    def _adicionar_secao_pendencias(self, problemas, avisos):
        secao = _SecaoColapsavel("  Pendências Detectadas", self._COR_AVISO)
        html = "<div style='line-height:2.0;'>"
        for p in problemas:
            html += (f"<div style='color:{self._COR_ERRO}; font-size:11px;'>"
                     f" &nbsp;{p}</div>")
        for a in avisos:
            html += (f"<div style='color:{self._COR_AVISO}; font-size:11px;'>"
                     f" &nbsp;{a}</div>")
        html += "</div>"
        lbl = QLabel(html)
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        secao.add_widget(lbl)
        self._inserir_secao(secao)

    def _inserir_secao(self, secao: _SecaoColapsavel):
        """Insere a seção antes do stretch final."""
        pos = max(0, self._layout_secoes.count() - 1)
        self._layout_secoes.insertWidget(pos, secao)

    # ── Funções de coleta de dados ───────────────────────────────────────

    def _verificar_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _versao_npcap(self) -> str:
        """Lê a versão do Npcap do registro do Windows."""
        try:
            import winreg
            chaves_candidatas = [
                r"SOFTWARE\Npcap",
                r"SOFTWARE\WOW6432Node\Npcap",
            ]
            for chave in chaves_candidatas:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, chave) as k:
                        versao, _ = winreg.QueryValueEx(k, "")
                        if versao:
                            return str(versao).strip() or "Instalado"
                except FileNotFoundError:
                    continue
        except ImportError:
            pass
        # Fallback: verifica pela DLL do Npcap
        dll_path = r"C:\Windows\System32\Npcap\wpcap.dll"
        if os.path.exists(dll_path):
            return "Instalado (versão não detectada)"
        return "N/A"

    def _versao_scapy(self) -> str:
        try:
            import scapy
            return getattr(scapy, "VERSION", None) or scapy.__version__
        except Exception:
            return "N/A"

    def _versao_pyqt6(self) -> str:
        try:
            from PyQt6.QtCore import PYQT_VERSION_STR
            return PYQT_VERSION_STR
        except Exception:
            return "N/A"

    def _testar_ping_gateway(self) -> dict:
        """
        Faz ping real ao gateway local (último octeto .1 ou .254 na tabela ARP).
        Retorna dicionário com ok, texto, latencia_ms.
        """
        gateway = self._descobrir_gateway()
        if not gateway:
            return {"ok": False, "texto": "Gateway não detectado", "latencia_ms": None}
        try:
            resultado = subprocess.run(
                ["ping", "-n", "3", "-w", "800", gateway],
                capture_output=True,
                text=True,
                timeout=6,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            saida = resultado.stdout

            # Extrai latência média
            m_media = re.search(r"M[eé]dia\s*=\s*(\d+)\s*ms", saida, re.IGNORECASE)
            if not m_media:
                m_media = re.search(r"Average\s*=\s*(\d+)ms", saida, re.IGNORECASE)

            # Verifica perda
            m_perda = re.search(r"(\d+)%\s+(?:de\s+perda|loss)", saida, re.IGNORECASE)
            perda_pct = int(m_perda.group(1)) if m_perda else 100

            if resultado.returncode == 0 and perda_pct < 100:
                lat = int(m_media.group(1)) if m_media else 0
                texto = f"{gateway} — {lat} ms · {perda_pct}% perda"
                return {"ok": True, "texto": texto, "latencia_ms": lat, "gateway": gateway}
            else:
                return {
                    "ok": False,
                    "texto": f"{gateway} — sem resposta ({perda_pct}% perda)",
                    "latencia_ms": None,
                    "gateway": gateway,
                }
        except Exception as e:
            return {"ok": False, "texto": f"Erro no ping: {e}", "latencia_ms": None}

    def _descobrir_gateway(self) -> str:
        """Tenta encontrar o IP do gateway via tabela ARP do sistema."""
        try:
            saida = subprocess.check_output(
                ["arp", "-a"],
                text=True,
                timeout=4,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for linha in saida.splitlines():
                m = re.search(r'(\d+\.\d+\.\d+\.(?:1|254))\s+', linha)
                if m:
                    return m.group(1)
        except Exception:
            pass

        # Fallback: route print
        try:
            saida = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True,
                timeout=4,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            m = re.search(r'\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', saida)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    def _testar_dns(self) -> dict:
        """Resolve google.com e mede o tempo de resposta."""
        try:
            inicio = time.perf_counter()
            socket.setdefaulttimeout(3)
            ip_resolvido = socket.gethostbyname("google.com")
            tempo_ms = int((time.perf_counter() - inicio) * 1000)
            return {
                "ok": True,
                "texto": f"google.com → {ip_resolvido} ({tempo_ms} ms)",
                "tempo_ms": tempo_ms,
            }
        except Exception as e:
            return {"ok": False, "texto": f"Falha: {e}", "tempo_ms": None}

    def _sinal_wifi(self) -> dict:
        """
        Lê dados do Wi-Fi via netsh wlan show interfaces.
        Retorna sinal em %, SSID, BSSID, canal e velocidade.
        """
        try:
            resultado = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="ignore",
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            saida = resultado.stdout

            def _extrair(padrao, texto):
                m = re.search(padrao, texto, re.IGNORECASE)
                return m.group(1).strip() if m else "—"

            sinal_txt = _extrair(r"Sinal\s*:\s*(\d+)%", saida)
            if sinal_txt == "—":
                sinal_txt = _extrair(r"Signal\s*:\s*(\d+)%", saida)

            sinal_pct = int(sinal_txt) if sinal_txt.isdigit() else 0

            return {
                "disponivel": sinal_pct > 0,
                "sinal_pct":  sinal_pct,
                "ssid":       _extrair(r"SSID\s*:\s*(.+)", saida),
                "bssid":      _extrair(r"BSSID\s*:\s*(.+)", saida),
                "canal":      _extrair(r"Canal\s*:\s*(\d+)", saida) or _extrair(r"Channel\s*:\s*(\d+)", saida),
                "velocidade": _extrair(r"Taxa de recep[çc][aã]o\s*:\s*(.+)", saida) or
                              _extrair(r"Receive rate.*?:\s*(.+)", saida),
            }
        except Exception:
            return {"disponivel": False}

    def _stats_interface(self, nome_iface: str) -> dict:
        """Lê contadores de drops e erros via psutil."""
        try:
            import psutil
            contadores = psutil.net_io_counters(pernic=True)
            nome_lower = (nome_iface or "").lower()
            for nome_nic, stats in contadores.items():
                if nome_lower in nome_nic.lower() or nome_nic.lower() in nome_lower:
                    return {
                        "disponivel": True,
                        "drops": stats.dropin + stats.dropout,
                        "erros": stats.errin + stats.errout,
                        "bytes_enviados":   stats.bytes_sent,
                        "bytes_recebidos":  stats.bytes_recv,
                    }
            return {"disponivel": True, "drops": 0, "erros": 0}
        except ImportError:
            return {"disponivel": False}
        except Exception:
            return {"disponivel": False}

    # ── Utilitários de formatação HTML ────────────────────────────────────

    def _tabela_html(self, linhas: list) -> str:
        """Gera uma tabela HTML simples de dois campos: rótulo e valor."""
        html = "<table style='border-collapse:collapse; width:100%; font-size:11px;'>"
        for rotulo, valor in linhas:
            html += (
                f"<tr>"
                f"<td style='color:{self._COR_DIM}; padding:4px 14px 4px 0; "
                f"white-space:nowrap; vertical-align:top;'>{rotulo}</td>"
                f"<td style='color:{self._COR_TEXTO}; font-family:Consolas; "
                f"padding:4px 0; word-break:break-all;'>{valor}</td>"
                f"</tr>"
            )
        html += "</table>"
        return html

    def _item_check(self, ok: bool, texto: str, dica: str = "") -> str:
        """Retorna HTML de um item de checklist com ícone colorido."""
        icone = "" if ok else ""
        cor   = self._COR_OK if ok else self._COR_ERRO
        extra = f" <span style='color:{self._COR_DIM}; font-size:9px;'>— {dica}</span>" if dica else ""
        return (
            f"<div style='color:{cor}; padding:2px 0; font-size:11px;'>"
            f"<span style='font-weight:bold;'>{icone}</span>&nbsp;&nbsp;{texto}{extra}</div>"
        )

    # ── Auto-refresh ─────────────────────────────────────────────────────

    def _ao_alternar_auto_refresh(self, ativo: bool):
        if ativo:
            self._timer_auto.start(3000)
        else:
            self._timer_auto.stop()

    # ── Exportação ───────────────────────────────────────────────────────

    def _exportar_relatorio(self):
        """Salva o relatório completo em arquivo .txt na pasta atual."""
        try:
            nome_arquivo = f"netlab_diagnostico_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            r = self._ultimo_relatorio

            linhas = [
                "=" * 60,
                "NETLAB EDUCACIONAL — DIAGNÓSTICO COMPLETO",
                f"Gerado em: {r.get('timestamp', 'N/A')}",
                "=" * 60,
                "",
                "[ SISTEMA ]",
                f"  Python:         {platform.python_version()}",
                f"  Sistema:        {platform.system()} {platform.release()}",
                f"  Scapy:          {r.get('versao_scapy', 'N/A')}",
                f"  Npcap:          {r.get('versao_npcap', 'N/A')}",
                f"  Administrador:  {'Sim' if r.get('eh_admin') else 'Não'}",
                "",
                "[ INTERFACE ]",
                f"  Interface:  {r.get('interface', 'N/A')}",
                f"  Dispositivo:{r.get('nome_iface', 'N/A')}",
                f"  IP Local:   {r.get('ip_local', 'N/A')}",
                "",
                "[ CONECTIVIDADE ]",
            ]

            dns = r.get("dns", {})
            gw  = r.get("gateway", {})
            linhas.append(f"  DNS:     {dns.get('texto', 'N/A')}")
            linhas.append(f"  Gateway: {gw.get('texto', 'N/A')}")

            wifi = r.get("wifi")
            if wifi and wifi.get("disponivel"):
                linhas += [
                    "",
                    "[ WI-FI ]",
                    f"  SSID:       {wifi.get('ssid', 'N/A')}",
                    f"  Sinal:      {wifi.get('sinal_pct', 0)}%",
                    f"  Canal:      {wifi.get('canal', 'N/A')}",
                    f"  Velocidade: {wifi.get('velocidade', 'N/A')}",
                ]

            iface = r.get("iface", {})
            if iface.get("disponivel"):
                linhas += [
                    "",
                    "[ ESTATÍSTICAS DA INTERFACE ]",
                    f"  Drops: {iface.get('drops', 0)}",
                    f"  Erros: {iface.get('erros', 0)}",
                ]

            snap = r.get("snap", {})
            linhas += [
                "",
                "[ SESSÃO DE CAPTURA ]",
                f"  Pacotes:  {snap.get('total_pacotes', 0):,}",
                f"  Volume:   {snap.get('total_bytes', 0) / 1024:.1f} KB",
                "",
                "=" * 60,
            ]

            with open(nome_arquivo, "w", encoding="utf-8") as arq:
                arq.write("\n".join(linhas))

            QMessageBox.information(
                self, "Exportação concluída",
                f"Relatório salvo em:\n{os.path.abspath(nome_arquivo)}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Erro ao exportar", str(e))


# ── Função auxiliar fora da classe ──────────────────────────────────────────

def _obter_ip_local_seguro() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ============================================================================
# Importações do restante do projeto
# ============================================================================

from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor
from utils.constantes import PORTAS_HTTP, PORTAS_DHCP
from utils.gerenciador_subredes import GerenciadorSubRedes, Visibilidade
from utils.rede import obter_ip_local, detectar_cidr_robusto, converter_ip_mascara_para_cidr, formatar_bytes
from utils.identificador import GerenciadorDispositivos


# ============================================================================
# Estado da rede — cooldown de eventos e registro de dispositivos descobertos
# ============================================================================

def _ip_eh_topologizavel(ip: str) -> bool:
    if not ip:
        return False
    try:
        partes = [int(p) for p in ip.split('.')]
        if len(partes) != 4:
            return False
        a, b, _, d = partes
        return not (
            a == 0
            or a == 127
            or (a == 169 and b == 254)
            or (224 <= a <= 239)
            or ip == "255.255.255.255"
            or d == 255
        )
    except Exception:
        return False


class EstadoRede:
    def __init__(self):
        self.ultimos_eventos: dict = {}
        self.dispositivos:    dict = {}
        self._lock = threading.Lock()

    def deve_emitir_evento(self, chave: str, cooldown: int = 5) -> bool:
        agora = time.time()
        with self._lock:
            if chave in self.ultimos_eventos:
                if agora - self.ultimos_eventos[chave] < cooldown:
                    return False
            if len(self.ultimos_eventos) > 2000:
                corte = agora - 120
                chaves_antigas = [
                    k for k, ts in self.ultimos_eventos.items() if ts < corte
                ]
                for k in chaves_antigas:
                    del self.ultimos_eventos[k]
            self.ultimos_eventos[chave] = agora
            return True

    def registrar_dispositivo(self, ip: str, mac: str = "", hostname: str = "") -> str:
        with self._lock:
            if ip not in self.dispositivos:
                self.dispositivos[ip] = (mac, hostname, time.time())
                return "NOVO"
            return "EXISTENTE"

    def obter_dispositivo(self, ip: str):
        return self.dispositivos.get(ip)


# ============================================================================
# Fila global de pacotes
# ============================================================================

class _FilaPacotesGlobal:
    def __init__(self):
        self._fila: deque = deque(maxlen=20_000)
        self._lock = threading.Lock()

    def adicionar(self, pacote: dict):
        with self._lock:
            self._fila.append(pacote)

    def consumir_todos(self) -> list:
        with self._lock:
            pacotes = list(self._fila)
            self._fila.clear()
            return pacotes

    def limpar(self):
        with self._lock:
            self._fila.clear()


fila_pacotes_global = _FilaPacotesGlobal()


def obter_interfaces_disponiveis() -> list:
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        return [
            iface.get('description', iface.get('name', ''))
            for iface in interfaces
            if 'loopback' not in iface.get('description', '').lower()
        ]
    except Exception:
        return []


# ============================================================================
# Thread do sniffer
# ============================================================================

_MAX_PACOTES_POR_SEGUNDO      = 800
_MAX_PACOTES_WIFI_POR_SEGUNDO = 400


class _CapturadorPacotesThread(QThread):
    erro_ocorrido = pyqtSignal(str)
    sem_pacotes   = pyqtSignal(str)

    def __init__(self, interface: str, eh_wifi: bool = False):
        super().__init__()
        self.interface = interface
        self.eh_wifi   = eh_wifi
        self._rodando  = False
        self.sniffer   = None
        self._pps_contador = 0
        self._pps_reset_ts = 0.0
        self._limite_pps   = (
            _MAX_PACOTES_WIFI_POR_SEGUNDO if eh_wifi else _MAX_PACOTES_POR_SEGUNDO
        )

    def run(self):
        self._rodando = True
        while self._rodando:
            try:
                from scapy.all import AsyncSniffer
                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    prn=self._processar_pacote,
                    store=False,
                    filter="ip or arp",
                    promisc=not self.eh_wifi,
                )
                self.sniffer.start()
                while self._rodando:
                    self.sleep(1)
                    if not getattr(self.sniffer, 'running', False):
                        if self._rodando:
                            break
            except Exception as erro:
                if self._rodando:
                    print(f"[Capturador] Socket falhou: {erro} — reiniciando em 2s")
            finally:
                self._parar_sniffer_seguro()
            if self._rodando:
                for _ in range(20):
                    if not self._rodando:
                        break
                    time.sleep(0.1)

    def _parar_sniffer_seguro(self):
        if self.sniffer:
            try:
                if getattr(self.sniffer, 'running', False):
                    self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

    def _processar_pacote(self, pacote):
        if not self._rodando:
            return
        agora = time.time()
        if agora - self._pps_reset_ts >= 1.0:
            self._pps_contador = 0
            self._pps_reset_ts = agora
        self._pps_contador += 1
        if self._pps_contador > self._limite_pps:
            return
        try:
            self._parsear_e_enfileirar(pacote)
        except Exception:
            pass

    def _parsear_e_enfileirar(self, pacote):
        dados = {
            "tamanho":       len(pacote),
            "ip_origem":     None,
            "ip_destino":    None,
            "mac_origem":    None,
            "mac_destino":   None,
            "protocolo":     "Outro",
            "porta_origem":  None,
            "porta_destino": None,
        }

        from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, Raw, BOOTP, DHCP

        if pacote.haslayer(Ether):
            dados["mac_origem"]  = pacote[Ether].src
            dados["mac_destino"] = pacote[Ether].dst

        if pacote.haslayer(IP):
            dados["ip_origem"]  = pacote[IP].src
            dados["ip_destino"] = pacote[IP].dst

            if pacote.haslayer(TCP):
                dados["protocolo"]     = "TCP"
                dados["porta_origem"]  = pacote[TCP].sport
                dados["porta_destino"] = pacote[TCP].dport
                flags = pacote[TCP].flags
                if flags & 0x02:
                    dados["flags"] = "SYN"
                elif flags & 0x01:
                    dados["flags"] = "FIN"
                elif flags & 0x04:
                    dados["flags"] = "RST"

            elif pacote.haslayer(UDP):
                dados["protocolo"]     = "UDP"
                dados["porta_origem"]  = pacote[UDP].sport
                dados["porta_destino"] = pacote[UDP].dport

                if (
                    dados["porta_origem"] in PORTAS_DHCP
                    or dados["porta_destino"] in PORTAS_DHCP
                    or pacote.haslayer(DHCP)
                    or pacote.haslayer(BOOTP)
                ):
                    dados["protocolo"] = "DHCP"
                    dados["dhcp_tipo"] = ""
                    if pacote.haslayer(DHCP):
                        mapa_tipos_dhcp = {
                            1: "discover", 2: "offer",  3: "request",
                            4: "decline",  5: "ack",    6: "nak",
                            7: "release",  8: "inform",
                        }
                        for opcao in (pacote[DHCP].options or []):
                            if (
                                isinstance(opcao, tuple)
                                and len(opcao) >= 2
                                and opcao[0] == "message-type"
                            ):
                                valor_opcao = opcao[1]
                                if isinstance(valor_opcao, bytes) and valor_opcao:
                                    valor_opcao = valor_opcao[0]
                                if isinstance(valor_opcao, int):
                                    dados["dhcp_tipo"] = mapa_tipos_dhcp.get(
                                        valor_opcao, str(valor_opcao)
                                    )
                                else:
                                    dados["dhcp_tipo"] = str(valor_opcao)
                                break
                    if pacote.haslayer(BOOTP):
                        dados["dhcp_xid"] = int(
                            getattr(pacote[BOOTP], "xid", 0) or 0
                        )

                elif pacote.haslayer(DNS):
                    dados["protocolo"] = "DNS"
                    if pacote[DNS].qr == 0 and pacote[DNS].qd:
                        dados["dominio"] = pacote[DNS].qd.qname.decode(
                            'utf-8', errors='ignore'
                        ).rstrip('.')

        elif pacote.haslayer(ARP):
            dados["protocolo"]  = "ARP"
            dados["ip_origem"]  = pacote[ARP].psrc
            dados["ip_destino"] = pacote[ARP].pdst
            dados["mac_origem"] = dados["mac_origem"] or pacote[ARP].hwsrc
            dados["arp_op"]     = "request" if pacote[ARP].op == 1 else "reply"

        if pacote.haslayer(Raw) and (
            dados.get("porta_destino") in PORTAS_HTTP or
            dados.get("porta_origem")  in PORTAS_HTTP
        ):
            dados["payload"] = pacote[Raw].load

        fila_pacotes_global.adicionar(dados)

    def parar(self):
        self._rodando = False
        self._parar_sniffer_seguro()
        self.wait(3000)


# ============================================================================
# Thread de descoberta de dispositivos
# ============================================================================

class _DescobrirDispositivosThread(QThread):
    dispositivo_encontrado = pyqtSignal(str, str, str)
    varredura_concluida    = pyqtSignal(list)
    progresso_atualizado   = pyqtSignal(str)
    erro_ocorrido          = pyqtSignal(str)

    TIMEOUT_ARP   = 1.8
    TIMEOUT_ICMP  = 1.0
    TENTATIVAS    = 3
    BATCH_ARP     = 512
    MAX_HOSTS     = 4_096
    PAUSA_RODADAS = 0.6
    WORKERS_ICMP  = 64
    INTER_ARP     = 0.0

    def __init__(self, interface: str, cidr: str = "", habilitar_ping: bool = True,
                 parametros: dict = None):
        super().__init__()
        self.interface = interface
        self.cidr      = cidr
        self._ips_encontrados: set  = set()
        self._dispositivos:    list = []
        self._cache_mac:       dict = {}
        self._ips_sem_mac:     set  = set()
        self._mac_gateway:     str  = ""
        self._lock = threading.Lock()
        self._param_arps = dict(parametros) if parametros else {
            "batch":          self.BATCH_ARP,
            "inter":          self.INTER_ARP,
            "sleep_lote":     0.0,
            "pausa":          self.PAUSA_RODADAS,
            "timeout":        self.TIMEOUT_ARP,
            "tentativas":     self.TENTATIVAS,
            "limite_hosts":   self.MAX_HOSTS,
            "desativar_icmp": False,
            "descoberta_ativa": True,
            "wifi":           False,
            "timer_ms":       30000,
        }
        self._limite_hosts     = self._param_arps["limite_hosts"]
        self._eh_wifi          = self._param_arps.get("wifi", False)
        self._periodo_timer_ms = self._param_arps.get("timer_ms", 30000)

    def run(self):
        try:
            if not self._param_arps.get("descoberta_ativa", True):
                self.progresso_atualizado.emit(
                    "Descoberta ativa desativada para esta interface."
                )
                self.varredura_concluida.emit([])
                return

            rede_cidr = self.cidr or self._detectar_cidr() or self._cidr_por_ip_local()
            if not rede_cidr:
                self.erro_ocorrido.emit(
                    "Não foi possível determinar a sub-rede. "
                    "Verifique se a interface está ativa."
                )
                return

            self.progresso_atualizado.emit(f"Iniciando varredura em {rede_cidr} …")
            self._varrer_arp(rede_cidr)
            self._varrer_icmp(rede_cidr)

            if not self._eh_wifi:
                try:
                    rede_obj = ipaddress.ip_network(rede_cidr, strict=False)
                    if rede_obj.prefixlen >= 24:
                        novo_prefixo   = max(21, rede_obj.prefixlen - 2)
                        rede_expandida = str(rede_obj.supernet(new_prefix=novo_prefixo))
                        if rede_expandida != rede_cidr:
                            self.progresso_atualizado.emit(
                                f"Expandindo busca: {rede_cidr} → {rede_expandida} …"
                            )
                            self._varrer_arp(rede_expandida)
                            self._varrer_icmp(rede_expandida)
                except Exception:
                    pass

            total = len(self._dispositivos)
            self.progresso_atualizado.emit(
                f"Varredura concluída — {total} dispositivo(s) encontrado(s)."
            )
            self.varredura_concluida.emit(self._dispositivos)

        except Exception as erro:
            self.erro_ocorrido.emit(f"Erro na descoberta: {erro}")

    def _varrer_arp(self, rede_cidr: str):
        from scapy.all import ARP, Ether, srp

        try:
            rede  = ipaddress.ip_network(rede_cidr, strict=False)
            todos = self._selecionar_hosts(rede)
        except Exception as e:
            self.progresso_atualizado.emit(f"Erro ao listar hosts de {rede_cidr}: {e}")
            return

        batch      = self._param_arps["batch"]
        inter_pkt  = self._param_arps["inter"]
        pausa      = self._param_arps["pausa"]
        timeout    = self._param_arps["timeout"]
        sleep_lote = self._param_arps.get("sleep_lote", 0.0)
        tentativas = (
            self._param_arps["tentativas"]
            if len(todos) <= 1024
            else max(2, self._param_arps["tentativas"] - 1)
        )

        self.progresso_atualizado.emit(
            f"ARP sweep: {len(todos)} IPs · {tentativas} rodada(s) · "
            f"lotes de {batch} (inter={inter_pkt*1000:.0f}ms)…"
        )

        for rodada in range(1, tentativas + 1):
            pendentes = [h for h in todos if h not in self._ips_encontrados]
            if not pendentes:
                self.progresso_atualizado.emit(
                    f"Todos os hosts responderam após {rodada - 1} rodada(s)."
                )
                break
            if len(self._ips_encontrados) >= self._limite_hosts:
                self.progresso_atualizado.emit(
                    f"Limite de {self._limite_hosts} dispositivos atingido."
                )
                break

            self.progresso_atualizado.emit(
                f"Rodada ARP {rodada}/{tentativas}: {len(pendentes)} host(s) pendente(s) …"
            )
            encontrados_nesta_rodada = 0

            for inicio in range(0, len(pendentes), batch):
                lote = pendentes[inicio: inicio + batch]
                pacotes_arp = [
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                    for ip in lote
                ]
                try:
                    respostas, _ = srp(
                        pacotes_arp,
                        iface=self.interface,
                        timeout=timeout,
                        verbose=False,
                        retry=0,
                        inter=inter_pkt,
                    )
                    for _, resp in respostas:
                        try:
                            ip_resp  = resp[ARP].psrc
                            mac_resp = resp[ARP].hwsrc
                            if not mac_resp or mac_resp.lower() in (
                                "ff:ff:ff:ff:ff:ff",
                                "00:00:00:00:00:00",
                                "",
                            ):
                                continue
                            if not self._mac_gateway:
                                partes_ip = ip_resp.split(".")
                                if len(partes_ip) == 4:
                                    ultimo_octeto = int(partes_ip[-1])
                                    if ultimo_octeto in (1, 254):
                                        self._mac_gateway = mac_resp.lower()
                            if (
                                self._mac_gateway
                                and mac_resp.lower() == self._mac_gateway
                            ):
                                continue
                            if self._ip_valido(ip_resp):
                                self._registrar(ip_resp, mac_resp, "")
                                encontrados_nesta_rodada += 1
                        except Exception:
                            pass
                except Exception as e:
                    self.progresso_atualizado.emit(
                        f"Lote {inicio//batch + 1} falhou: {e}"
                    )

                if sleep_lote > 0:
                    time.sleep(sleep_lote)
                if len(self._ips_encontrados) >= self._limite_hosts:
                    break

            self.progresso_atualizado.emit(
                f"Rodada {rodada}: +{encontrados_nesta_rodada} novo(s) · "
                f"total {len(self._ips_encontrados)}"
            )

            if len(self._ips_encontrados) >= self._limite_hosts:
                break
            if rodada < tentativas and encontrados_nesta_rodada == 0:
                break
            if rodada < tentativas:
                time.sleep(pausa)

    def _varrer_icmp(self, rede_cidr: str):
        from scapy.all import IP, ICMP, Ether, srp

        if self._param_arps.get("desativar_icmp", False):
            return

        try:
            rede  = ipaddress.ip_network(rede_cidr, strict=False)
            todos = self._selecionar_hosts(rede)
        except Exception as e:
            self.progresso_atualizado.emit(f"ICMP abortado: {e}")
            return

        pendentes  = [ip for ip in todos if ip not in self._ips_encontrados]
        candidatos = []
        for ip in pendentes:
            if ip in self._ips_sem_mac:
                continue
            mac = self._cache_mac.get(ip) or self._resolver_mac_unico(ip)
            if mac:
                candidatos.append(ip)
            else:
                self._ips_sem_mac.add(ip)

        if not candidatos:
            self.progresso_atualizado.emit("ICMP: nenhum host restante com MAC resolvido.")
            return

        self.progresso_atualizado.emit(
            f"ICMP paralelo (L2): {len(candidatos)} host(s) com MAC resolvido …"
        )

        pacotes = [
            Ether(dst=self._cache_mac.get(ip, "ff:ff:ff:ff:ff:ff")) / IP(dst=ip) / ICMP()
            for ip in candidatos
        ]

        try:
            respostas, _ = srp(
                pacotes,
                iface=self.interface,
                timeout=self.TIMEOUT_ICMP,
                retry=0,
                verbose=False,
                inter=0,
            )
            for _, resp in respostas:
                try:
                    ip_resp  = resp[IP].src   if resp.haslayer(IP)    else ""
                    mac_resp = resp[Ether].src if resp.haslayer(Ether) else ""
                    if self._ip_valido(ip_resp):
                        self._registrar(ip_resp, mac_resp, "")
                except Exception:
                    pass
        except Exception as e:
            self.progresso_atualizado.emit(f"ICMP falhou: {e}")

    def _resolver_mac_unico(self, ip: str) -> str:
        from scapy.all import ARP, Ether, srp1
        try:
            resposta = srp1(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=self.interface,
                timeout=0.6,
                retry=0,
                verbose=False,
            )
            if resposta and resposta.haslayer(ARP):
                return resposta[ARP].hwsrc
        except Exception:
            pass
        return ""

    def _selecionar_hosts(self, rede: ipaddress.IPv4Network) -> list:
        total_hosts = max(0, rede.num_addresses - 2)
        if total_hosts <= 0:
            return []
        limite = self._limite_hosts
        if total_hosts <= limite:
            return [str(h) for h in rede.hosts()]
        passo        = max(1, total_hosts // limite)
        selecionados = []
        for idx, host in enumerate(rede.hosts()):
            if idx % passo == 0:
                selecionados.append(str(host))
            if len(selecionados) >= limite:
                break
        return selecionados

    def _registrar(self, ip: str, mac: str, hostname: str):
        with self._lock:
            if ip in self._ips_encontrados:
                return
            self._ips_encontrados.add(ip)
            if mac:
                self._cache_mac[ip] = mac
            self._dispositivos.append((ip, mac, hostname))
        self.dispositivo_encontrado.emit(ip, mac, hostname)

    @staticmethod
    def _ip_valido(ip: str) -> bool:
        try:
            partes = [int(x) for x in ip.split(".")]
            return len(partes) == 4 and not (
                partes[0] in (0, 127)
                or (partes[0] == 169 and partes[1] == 254)
                or 224 <= partes[0] <= 239
                or partes[3] == 255
            )
        except Exception:
            return False

    def _detectar_cidr(self) -> str:
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip      = get_if_addr(self.interface)
            mascara = get_if_netmask(self.interface)
            if ip and mascara and ip != "0.0.0.0":
                prefixo = sum(bin(int(p)).count("1") for p in mascara.split("."))
                rede    = ipaddress.ip_network(f"{ip}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    @staticmethod
    def _cidr_por_ip_local() -> str:
        ip = obter_ip_local()
        if not ip or ip == "127.0.0.1":
            return ""
        partes = ip.split(".")
        return f"{'.'.join(partes[:3])}.0/24" if len(partes) == 4 else ""


# ============================================================================
# Sinal global para resultados do motor pedagógico
# ============================================================================

class _SinalPedagogico(QObject):
    resultado = pyqtSignal(dict)

_sinal_pedagogico_global = _SinalPedagogico()


class _WorkerRunnable(QRunnable):
    def __init__(self, evento: dict, motor):
        super().__init__()
        self.evento = evento
        self.motor  = motor
        self.setAutoDelete(True)

    def run(self):
        try:
            explicacao = self.motor.gerar_explicacao(self.evento)
            if explicacao is None:
                explicacao = {
                    "nivel1": f"Evento: {self.evento.get('tipo', 'Desconhecido')}",
                    "nivel2": (
                        f"Origem: {self.evento.get('ip_origem', '?')} → "
                        f"Destino: {self.evento.get('ip_destino', '?')}"
                    ),
                    "nivel3": f"Dados: {self.evento}",
                    "icone": "", "nivel": "INFO",
                    "alerta_seguranca": "",
                }
            explicacao["sessao_id"] = self.evento.get("sessao_id")
            _sinal_pedagogico_global.resultado.emit(explicacao)
        except Exception as e:
            print(f"[Worker pedagógico] Erro: {e}")


# ============================================================================
# Janela principal do NetLab Educacional
# ============================================================================

class JanelaPrincipal(QMainWindow):

    def __init__(self):
        super().__init__()
        self.analisador       = AnalisadorPacotes()
        self.motor_pedagogico = MotorPedagogico()

        self.capturador:  _CapturadorPacotesThread     = None
        self.descobridor: _DescobrirDispositivosThread = None
        self.descoberta_rodando: bool = False
        self.em_captura: bool = False

        self._mapa_interface_nome:    dict = {}
        self._mapa_interface_ip:      dict = {}
        self._mapa_interface_mascara: dict = {}
        self._cache_interfaces_windows: list = []
        self._cache_interfaces_windows_ts: float = 0.0
        self._interface_captura = ""
        self._cidr_captura      = ""

        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()

        self.estado_rede = EstadoRede()
        self.gerenciador_subredes = GerenciadorSubRedes()
        self.gerenciador_dispositivos = GerenciadorDispositivos()
        self.fila_eventos_ui: deque = deque(maxlen=500)
        self.eventos_mostrados_recentemente: deque = deque(maxlen=200)

        self._thread_pool = QThreadPool.globalInstance()
        self._thread_pool.setMaxThreadCount(4)
        _sinal_pedagogico_global.resultado.connect(self._finalizar_exibicao_evento)

        self._kb_anterior:        float = 0.0
        self._param_arps:         dict  = {}
        self._limite_hosts:       int   = _DescobrirDispositivosThread.MAX_HOSTS
        self._eh_wifi:            bool  = False
        self._periodo_timer_ms:   int   = 30000

        self.timer_consumir = QTimer()
        self.timer_consumir.timeout.connect(self._consumir_fila)

        self.timer_ui = QTimer()
        self.timer_ui.timeout.connect(self._atualizar_ui_por_segundo)

        self.timer_descoberta = QTimer()
        self.timer_descoberta.timeout.connect(self._descoberta_periodica)

        self.timer_rotas = QTimer(self)
        self.timer_rotas.timeout.connect(self._atualizar_subredes_rotas)
        self.timer_rotas.start(120_000)

        self.timer_arp_sistema = QTimer(self)
        self.timer_arp_sistema.timeout.connect(self._popular_topologia_via_arp_sistema)
        self.timer_arp_sistema.start(60_000)

        self.timer_eventos = QTimer()
        self.timer_eventos.timeout.connect(self._descarregar_eventos_ui)
        self.timer_eventos.start(2000)

        self._configurar_janela()
        self._criar_menu()
        self._criar_barra_status()
        self._criar_barra_ferramentas()
        self._criar_area_central()

    # -------------------------------------------------------------------------
    # Configuração visual
    # -------------------------------------------------------------------------

    def _configurar_janela(self):
        self.setWindowTitle("NetLab Educacional - Monitor de Rede")
        self.setMinimumSize(1200, 700)
        self.resize(1440, 860)
        geo = self.screen().availableGeometry()
        self.move(
            (geo.width()  - self.width())  // 2,
            (geo.height() - self.height()) // 2,
        )

    def _criar_menu(self):
        menu = self.menuBar()

        m_arq = menu.addMenu("&Arquivo")
        a_nova = QAction("&Nova Sessão", self)
        a_nova.setShortcut("Ctrl+N")
        a_nova.triggered.connect(self._nova_sessao)
        m_arq.addAction(a_nova)
        m_arq.addSeparator()
        a_sair = QAction("&Sair", self)
        a_sair.setShortcut("Ctrl+Q")
        a_sair.triggered.connect(self.close)
        m_arq.addAction(a_sair)

        m_mon = menu.addMenu("&Monitoramento")
        self.acao_captura = QAction("Iniciar Captura", self)
        self.acao_captura.setShortcut("F10")
        self.acao_captura.triggered.connect(self._alternar_captura)
        m_mon.addAction(self.acao_captura)

        m_mon.addSeparator()
        a_atualizar_oui = QAction("Atualizar Base de Fabricantes", self)
        a_atualizar_oui.setToolTip(
            "Baixa a base OUI mais recente do Wireshark (requer internet)."
        )
        a_atualizar_oui.triggered.connect(self._solicitar_atualizacao_base_oui)
        m_mon.addAction(a_atualizar_oui)

        m_ajd = menu.addMenu("&Ajuda")
        a_sobre = QAction("Sobre o NetLab", self)
        a_sobre.triggered.connect(self._exibir_sobre)
        m_ajd.addAction(a_sobre)

    def _criar_barra_ferramentas(self):
        barra = self.addToolBar("Principal")
        barra.setMovable(False)

        barra.addWidget(QLabel("  Interface: "))
        self.combo_interface = QComboBox()
        self.combo_interface.setMinimumWidth(230)
        self._popular_interfaces()
        barra.addWidget(self.combo_interface)
        barra.addSeparator()

        self.botao_captura = QPushButton("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self.botao_captura.setMinimumWidth(155)
        self.botao_captura.clicked.connect(self._alternar_captura)
        barra.addWidget(self.botao_captura)

        barra.addSeparator()
        self.lbl_ip = QLabel(f"  Meu IP: {obter_ip_local()}  ")
        self.lbl_ip.setStyleSheet("color:#2ecc71; font-weight:bold;")
        barra.addWidget(self.lbl_ip)

        btn_diag = QPushButton("Diagnóstico")
        btn_diag.setToolTip("Exibe informações de diagnóstico da captura atual")
        btn_diag.clicked.connect(self._exibir_diagnostico_captura)
        barra.addWidget(btn_diag)

    def _criar_area_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.abas = QTabWidget()
        self.abas.currentChanged.connect(self._ao_mudar_aba)
        layout.addWidget(self.abas)

        self.painel_topologia = PainelTopologia()
        self.painel_trafego   = PainelTrafego()
        self.painel_eventos   = PainelEventos()
        self.painel_servidor  = PainelServidor()
        self.abas.addTab(self.painel_topologia, "Topologia da Rede")
        self.abas.addTab(self.painel_trafego,   "Tráfego em Tempo Real")
        self.abas.addTab(self.painel_eventos,   " Modo Análise")
        self.abas.addTab(self.painel_servidor,  "Servidor")

    def _criar_barra_status(self):
        barra = self.statusBar()
        self.lbl_status  = QLabel("Pronto. Clique em 'Iniciar Captura' para começar.")
        self.lbl_pacotes = QLabel("Pacotes: 0")
        self.lbl_dados   = QLabel("  Dados: 0 KB  ")
        barra.addWidget(self.lbl_status)
        barra.addPermanentWidget(self.lbl_pacotes)
        barra.addPermanentWidget(self.lbl_dados)

    # -------------------------------------------------------------------------
    # Lazy loading ao trocar de aba
    # -------------------------------------------------------------------------

    @pyqtSlot(int)
    def _ao_mudar_aba(self, idx: int):
        if self.abas.widget(idx) is self.painel_eventos:
            self.painel_eventos._reaplicar_filtros()

    # -------------------------------------------------------------------------
    # Detecção de interfaces e CIDR
    # -------------------------------------------------------------------------

    def _popular_interfaces(self):
        self.combo_interface.clear()
        self._mapa_interface_nome.clear()
        self._mapa_interface_ip.clear()
        self._mapa_interface_mascara.clear()
        interfaces_windows = self._interfaces_ipv4_windows(force=True)

        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces_raw = get_windows_if_list()
        except Exception:
            interfaces_raw = []

        if not interfaces_raw:
            nomes_fallback = [
                item["descricao"] or item["alias"]
                for item in interfaces_windows
                if item.get("descricao") or item.get("alias")
            ] or obter_interfaces_disponiveis()
            for desc in nomes_fallback:
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = desc
                self._aplicar_info_windows_interface(desc, desc, interfaces_windows)
            self._selecionar_interface_fallback()
            return

        for iface in interfaces_raw:
            desc = iface.get('description', iface.get('name', 'Desconhecida'))
            nome = iface.get('name', '')
            if not (desc and nome):
                continue
            self.combo_interface.addItem(desc)
            self._mapa_interface_nome[desc] = nome

            ips      = iface.get('ips',      []) or []
            mascaras = iface.get('netmasks', []) or []

            ip_v4 = next((
                ip for ip in ips
                if ip and ip.count('.') == 3
                and not ip.startswith(("169.254", "127."))
            ), "")

            if ip_v4:
                self._mapa_interface_ip[desc] = ip_v4

                def _normalizar_mascara(candidato, ip_ref: str) -> str:
                    if not candidato:
                        return ""
                    s = str(candidato).strip()
                    if '.' in s and s != '0.0.0.0':
                        return s
                    if s.isdigit() and 0 <= int(s) <= 32:
                        try:
                            rede_tmp = ipaddress.ip_network(
                                f"{ip_ref}/{int(s)}", strict=False
                            )
                            return str(rede_tmp.netmask)
                        except Exception:
                            pass
                    return ""

                try:
                    idx = ips.index(ip_v4)
                    if idx < len(mascaras):
                        m = _normalizar_mascara(mascaras[idx], ip_v4)
                        if m:
                            self._mapa_interface_mascara[desc] = m
                except Exception:
                    pass

                if desc not in self._mapa_interface_mascara:
                    for mask_candidata in mascaras:
                        m = _normalizar_mascara(mask_candidata, ip_v4)
                        if m:
                            self._mapa_interface_mascara[desc] = m
                            break

            if desc not in self._mapa_interface_mascara:
                for campo in ('netmask', 'mask'):
                    v = iface.get(campo)
                    if v and '.' in str(v):
                        self._mapa_interface_mascara[desc] = str(v)
                        break

            self._aplicar_info_windows_interface(desc, nome, interfaces_windows)

            if desc not in self._mapa_interface_mascara or not self._mapa_interface_mascara.get(desc):
                for iw in interfaces_windows:
                    iw_ip   = iw.get("ip", "")
                    iw_mask = iw.get("mascara", "")
                    iw_desc = self._normalizar_nome_iface(iw.get("descricao", ""))
                    iw_alias= self._normalizar_nome_iface(iw.get("alias", ""))
                    if iw_ip and iw_mask and iw_mask != "0.0.0.0":
                        if (
                            ip_v4 and ip_v4 == iw_ip
                            or self._normalizar_nome_iface(desc) in (iw_desc, iw_alias)
                            or self._normalizar_nome_iface(nome) in (iw_desc, iw_alias)
                        ):
                            self._mapa_interface_mascara[desc] = iw_mask
                            if not self._mapa_interface_ip.get(desc):
                                self._mapa_interface_ip[desc] = iw_ip
                            break

        ip_local = obter_ip_local()
        if ip_local:
            for iface in interfaces_raw:
                if ip_local in (iface.get('ips', []) or []):
                    desc = iface.get('description', iface.get('name', ''))
                    idx  = self.combo_interface.findText(desc)
                    if idx >= 0:
                        self.combo_interface.setCurrentIndex(idx)
                        self._status(f"Interface ativa detectada: {desc}")
                        return

        if self.combo_interface.count() > 0:
            self.combo_interface.setCurrentIndex(0)

    def _selecionar_interface_fallback(self):
        try:
            from scapy.all import conf
            default = str(conf.iface)
            for i in range(self.combo_interface.count()):
                if default in self.combo_interface.itemText(i):
                    self.combo_interface.setCurrentIndex(i)
                    return
        except Exception:
            pass

    @staticmethod
    def _prefixo_para_mascara(prefixo: int) -> str:
        try:
            prefixo = max(0, min(32, int(prefixo)))
            return str(ipaddress.ip_network(f"0.0.0.0/{prefixo}").netmask)
        except Exception:
            return ""

    @staticmethod
    def _mascara_para_prefixo(mascara: str) -> int:
        try:
            return sum(bin(int(p)).count("1") for p in mascara.split("."))
        except Exception:
            return 24

    def _cidr_por_ip_mascara(self, ip: str, mascara: str) -> str:
        if not ip or not mascara:
            return ""
        try:
            prefixo = self._mascara_para_prefixo(mascara)
            return str(ipaddress.ip_network(f"{ip}/{prefixo}", strict=False))
        except Exception:
            return ""

    def _interfaces_ipv4_windows(self, force: bool = False) -> list:
        if (
            not force
            and self._cache_interfaces_windows
            and time.time() - self._cache_interfaces_windows_ts < 30
        ):
            return list(self._cache_interfaces_windows)

        comando = (
            "$ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }; "
            "$adapters = Get-NetAdapter -ErrorAction SilentlyContinue; "
            "$ips | ForEach-Object { "
            "$ip = $_; "
            "$ad = $adapters | Where-Object { $_.ifIndex -eq $ip.InterfaceIndex } | Select-Object -First 1; "
            "[PSCustomObject]@{"
            "InterfaceAlias=$ip.InterfaceAlias;"
            "InterfaceDescription=$ad.InterfaceDescription;"
            "InterfaceIndex=$ip.InterfaceIndex;"
            "IPAddress=$ip.IPAddress;"
            "PrefixLength=$ip.PrefixLength"
            "} } | ConvertTo-Json -Depth 3"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", comando],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            saida = (proc.stdout or "").strip()
            if not saida:
                return []
            dados = json.loads(saida)
            if isinstance(dados, dict):
                dados = [dados]

            interfaces = []
            for item in dados:
                ip = str(item.get("IPAddress") or "")
                if not ip or ip.count(".") != 3:
                    continue
                try:
                    prefixo = int(item.get("PrefixLength"))
                    rede = ipaddress.ip_network(f"{ip}/{prefixo}", strict=False)
                except Exception:
                    continue
                interfaces.append({
                    "alias":    str(item.get("InterfaceAlias") or ""),
                    "descricao":str(item.get("InterfaceDescription") or ""),
                    "indice":   str(item.get("InterfaceIndex") or ""),
                    "ip":       ip,
                    "prefixo":  prefixo,
                    "mascara":  self._prefixo_para_mascara(prefixo),
                    "cidr":     str(rede),
                })

            self._cache_interfaces_windows    = interfaces
            self._cache_interfaces_windows_ts = time.time()
            return list(interfaces)
        except Exception:
            return []

    @staticmethod
    def _normalizar_nome_iface(texto: str) -> str:
        return re.sub(r"\s+", " ", (texto or "").lower()).strip()

    def _info_windows_para_interface(self, desc: str, nome: str = "") -> dict:
        alvos = {
            self._normalizar_nome_iface(desc),
            self._normalizar_nome_iface(nome),
        }
        alvos.discard("")
        interfaces = self._interfaces_ipv4_windows()
        for item in interfaces:
            campos = {
                self._normalizar_nome_iface(item.get("descricao", "")),
                self._normalizar_nome_iface(item.get("alias", "")),
            }
            if alvos & campos:
                return item
        for item in interfaces:
            campos = [
                self._normalizar_nome_iface(item.get("descricao", "")),
                self._normalizar_nome_iface(item.get("alias", "")),
            ]
            if any(a and c and (a in c or c in a) for a in alvos for c in campos):
                return item
        return {}

    def _aplicar_info_windows_interface(self, desc: str, nome: str, interfaces_windows: list):
        info = {}
        alvos = {
            self._normalizar_nome_iface(desc),
            self._normalizar_nome_iface(nome),
        }
        alvos.discard("")
        for item in interfaces_windows:
            campos = {
                self._normalizar_nome_iface(item.get("descricao", "")),
                self._normalizar_nome_iface(item.get("alias", "")),
            }
            if alvos & campos:
                info = item
                break
        if not info:
            return
        if info.get("ip"):
            self._mapa_interface_ip[desc] = info["ip"]
        if info.get("mascara"):
            self._mapa_interface_mascara[desc] = info["mascara"]

    @staticmethod
    def _detectar_cidr_via_powershell(ip_local: str) -> str:
        if not ip_local:
            return ""
        try:
            proc = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-Command",
                    f"(Get-NetIPAddress -IPAddress '{ip_local}' "
                    f"-AddressFamily IPv4 -ErrorAction SilentlyContinue)"
                    f".PrefixLength",
                ],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            saida = (proc.stdout or "").strip()
            if saida.isdigit():
                prefixo = int(saida)
                rede = ipaddress.ip_network(f"{ip_local}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    def _obter_cidr_via_ipconfig(self, ip_local: str) -> str:
        if not ip_local:
            return ""
        try:
            proc = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            raw   = proc.stdout
            saida = ""
            for enc in ("cp850", "cp1252", "utf-8", "latin-1"):
                try:
                    saida = raw.decode(enc, errors="strict")
                    break
                except (UnicodeDecodeError, LookupError):
                    continue
            if not saida:
                saida = raw.decode("utf-8", errors="replace")

            saida = saida.replace("\r\n", "\n").replace("\r", "\n")
            idx   = saida.find(ip_local)
            if idx == -1:
                return ""

            trecho = saida[max(0, idx - 400): idx + 700]
            m = re.search(
                r"(?:M[aá]scara[^:]*|Subnet\s+Mask)[^:]*:\s*"
                r"((?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3})",
                trecho,
                re.IGNORECASE,
            )
            if m:
                mascara = m.group(1)
                prefixo = sum(bin(int(p)).count("1") for p in mascara.split("."))
                rede    = ipaddress.ip_network(f"{ip_local}/{prefixo}", strict=False)
                return str(rede)

        except Exception as e:
            print(f"[NetLab] _obter_cidr_via_ipconfig: {e}")
        return ""

    @staticmethod
    def _detectar_cidr_via_scapy(nome_interface: str) -> str:
        try:
            from scapy.all import get_if_addr, get_if_netmask
            ip      = get_if_addr(nome_interface)
            mascara = get_if_netmask(nome_interface)
            if ip and mascara and ip != "0.0.0.0":
                prefixo = sum(bin(int(p)).count("1") for p in mascara.split("."))
                rede    = ipaddress.ip_network(f"{ip}/{prefixo}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    @staticmethod
    def _detectar_cidr_via_psutil(ip_local: str) -> str:
        try:
            import psutil
            AF_INET = socket.AF_INET
            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    if addr.family == AF_INET and addr.address == ip_local:
                        mascara = addr.netmask
                        if mascara and '.' in mascara and mascara != '0.0.0.0':
                            rede = ipaddress.ip_network(
                                f"{ip_local}/{mascara}", strict=False
                            )
                            return str(rede)
        except Exception:
            pass
        return ""

    @staticmethod
    def _detectar_cidr_via_netifaces(ip_local: str) -> str:
        try:
            import netifaces
            for iface in netifaces.interfaces():
                for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                    if addr.get("addr") == ip_local:
                        mascara = addr.get("netmask", "")
                        if mascara and '.' in mascara and mascara != '0.0.0.0':
                            rede = ipaddress.ip_network(
                                f"{ip_local}/{mascara}", strict=False
                            )
                            return str(rede)
        except Exception:
            pass
        return ""

    @staticmethod
    def _detectar_cidr_via_wmi(ip_local: str) -> str:
        try:
            resultado = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    f"(Get-WmiObject Win32_NetworkAdapterConfiguration | "
                    f"Where-Object {{$_.IPAddress -contains '{ip_local}'}}).IPSubnet | "
                    f"Select-Object -First 1",
                ],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            saida = (resultado.stdout or "").strip()
            if saida and '.' in saida and saida != '0.0.0.0':
                rede = ipaddress.ip_network(f"{ip_local}/{saida}", strict=False)
                return str(rede)
        except Exception:
            pass
        return ""

    def _cidr_da_interface(self, desc: str) -> str:
        ip_interface = (
            self._mapa_interface_ip.get(desc.strip(), "")
            or self._mapa_interface_ip.get(desc, "")
            or obter_ip_local()
        )

        mascara = (
            self._mapa_interface_mascara.get(desc.strip(), "")
            or self._mapa_interface_mascara.get(desc, "")
        )
        if mascara:
            cidr = converter_ip_mascara_para_cidr(ip_interface, mascara)
            if cidr:
                self._status(f" CIDR via mapas internos: {cidr}")
                return cidr

        cidr = detectar_cidr_robusto(ip_interface)
        if cidr:
            self._status(f" CIDR via motor robusto: {cidr}")
            return cidr

        return f"{ip_interface}/32"

    def _parametros_iface_seguro(self, nome_iface: str) -> dict:
        nome_lower = (nome_iface or "").lower()
        eh_wifi = any(
            p in nome_lower
            for p in ("wi-fi", "wifi", "wireless", "ax", "802.11")
        )

        base = {
            "limite_hosts":     100,
            "desativar_icmp":   False,
            "descoberta_ativa": True,
            "tentativas":       _DescobrirDispositivosThread.TENTATIVAS,
            "timeout":          _DescobrirDispositivosThread.TIMEOUT_ARP,
            "pausa":            _DescobrirDispositivosThread.PAUSA_RODADAS,
            "inter":            _DescobrirDispositivosThread.INTER_ARP,
            "sleep_lote":       0.0,
            "batch":            _DescobrirDispositivosThread.BATCH_ARP,
            "wifi":             eh_wifi,
            "timer_ms":         30000,
        }

        if eh_wifi:
            base.update({
                "batch":            0,
                "sleep_lote":       0.0,
                "pausa":            0.0,
                "timeout":          0.0,
                "tentativas":       0,
                "desativar_icmp":   True,
                "descoberta_ativa": False,
                "timer_ms":         60_000,
            })

        return base

    def _sincronizar_subredes_topologia(self):
        self.painel_topologia.atualizar_subredes(
            self.gerenciador_subredes.todas_subredes()
        )

    def _registrar_subrede_local(self):
        if not self._cidr_captura:
            return

        try:
            rede_local = ipaddress.ip_network(self._cidr_captura, strict=False)
        except ValueError:
            return

        gateway_candidato = None
        if rede_local.num_addresses > 2:
            try:
                gateway_candidato = str(rede_local.network_address + 1)
            except Exception:
                gateway_candidato = None

        self.gerenciador_subredes.adicionar_subrede(
            self._cidr_captura,
            gateway=gateway_candidato,
            visibilidade=Visibilidade.PARCIAL,
            local=True,
        )
        self._sincronizar_subredes_topologia()

    def _registrar_host_confirmado(
        self,
        ip: str,
        mac: str,
        hostname: str = "",
        confirmado_por_arp: bool = False,
        atualizar_subredes: bool = True,
        cidr_forcado: str = "",
    ) -> bool:
        if not ip or not _ip_eh_topologizavel(ip):
            return False

        subrede  = None
        eh_local = False
        if cidr_forcado:
            subrede_forcada = self.gerenciador_subredes.subredes.get(cidr_forcado)
            if subrede_forcada and subrede_forcada.contem(ip):
                subrede  = subrede_forcada
                eh_local = (subrede.cidr == self.gerenciador_subredes._cidr_local())

        if subrede is None:
            subrede, eh_local = self.gerenciador_subredes.classificar_ip(ip)
        houve_alteracao = False

        if subrede:
            total_hosts_antes  = len(subrede.hosts)
            visibilidade_antes = subrede.visibilidade

            subrede.adicionar_host(ip, confirmado=confirmado_por_arp)
            self.painel_topologia.adicionar_dispositivo_com_subrede(
                ip, mac, subrede.cidr, eh_local, hostname, confirmado_por_arp
            )

            houve_alteracao = (
                len(subrede.hosts) != total_hosts_antes
                or subrede.visibilidade != visibilidade_antes
            )
            if houve_alteracao and atualizar_subredes:
                self._sincronizar_subredes_topologia()
            return houve_alteracao

        if confirmado_por_arp:
            self.painel_topologia.adicionar_dispositivo_manual(ip, mac, hostname)
        else:
            self.painel_topologia.adicionar_dispositivo(ip, mac, hostname)

        return False

    def _gerar_historias(self) -> list:
        top_dns = (
            self.analisador.obter_top_dns()
            if hasattr(self.analisador, "obter_top_dns") else []
        )
        return [
            f"Domínio {d['dominio']} acessado {d['acessos']}x "
            f"({d['bytes']/1024:.1f} KB)."
            for d in top_dns[:5]
        ]

    # -------------------------------------------------------------------------
    # Controle de captura
    # -------------------------------------------------------------------------

    @pyqtSlot()
    def _alternar_captura(self):
        if self.em_captura:
            self._parar_captura()
        else:
            self._iniciar_captura()

    def _validar_pre_captura(self, nome_dispositivo: str):
        try:
            if hasattr(ctypes, "windll") and not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError(
                    "Execute o NetLab como Administrador para capturar pacotes."
                )
        except PermissionError:
            raise
        except Exception:
            pass

        try:
            from scapy.arch.windows import get_windows_if_list
            adaptadores   = get_windows_if_list()
            nomes_validos = (
                {a.get("name") for a in adaptadores}
                | {a.get("description") for a in adaptadores}
            )
            if nome_dispositivo not in nomes_validos:
                raise RuntimeError(
                    "Adaptador não reconhecido pelo Npcap/Scapy. "
                    "Reinstale o Npcap ou escolha outra interface."
                )
        except ImportError as exc:
            raise RuntimeError(
                "Scapy ausente. Instale com 'pip install scapy'."
            ) from exc
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Falha ao acessar o Npcap/Scapy: {exc}") from exc

    def _limpar_pos_falha(self):
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()
        if self.capturador:
            try:
                self.capturador.parar()
            except Exception:
                pass
            self.capturador = None
        self.analisador.parar_thread()
        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")

    def _iniciar_captura(self):
        desc_sel = self.combo_interface.currentText()
        if not desc_sel or "nenhuma" in desc_sel.lower():
            QMessageBox.warning(
                self, "Interface Inválida",
                "Selecione uma interface de rede válida.\n\n"
                "Execute como Administrador e verifique a instalação do Npcap."
            )
            return

        nome_dispositivo = self._mapa_interface_nome.get(desc_sel, desc_sel)

        try:
            self._validar_pre_captura(nome_dispositivo)
        except Exception as exc:
            self._status(f"Falha ao iniciar: {exc}")
            QMessageBox.critical(self, "Captura não iniciada", str(exc))
            self._limpar_pos_falha()
            return

        self._interface_captura = nome_dispositivo
        self._cidr_captura      = self._cidr_da_interface(desc_sel)
        self.painel_topologia.definir_rede_local(self._cidr_captura)
        self._registrar_subrede_local()

        self._param_arps       = self._parametros_iface_seguro(self._interface_captura)
        self._periodo_timer_ms = self._param_arps.get("timer_ms", 30000)
        self._eh_wifi          = self._param_arps.get("wifi", False)
        self._limite_hosts     = self._param_arps.get(
            "limite_hosts", _DescobrirDispositivosThread.MAX_HOSTS
        )

        fila_pacotes_global.limpar()
        self.analisador.resetar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0, "top_dns": [], "historias": [],
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()

        self.analisador.iniciar_thread()

        try:
            self.capturador = _CapturadorPacotesThread(
                interface=nome_dispositivo,
                eh_wifi=self._eh_wifi,
            )
            self.capturador.erro_ocorrido.connect(self._ao_ocorrer_erro)
            self.capturador.sem_pacotes.connect(self._ao_ocorrer_erro)
            self.capturador.start()
        except Exception as exc:
            msg = f"Não foi possível iniciar o sniffer: {exc}"
            self._status(msg)
            QMessageBox.critical(self, "Captura não iniciada", msg)
            self._limpar_pos_falha()
            return

        self.timer_consumir.start(400)
        self.timer_ui.start(1000)
        self.timer_descoberta.start(self._periodo_timer_ms)

        self.em_captura = True
        self.botao_captura.setText("Parar Captura")
        self.botao_captura.setObjectName("botao_parar")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Parar Captura")

        rede_info = f" · rede {self._cidr_captura}" if self._cidr_captura else ""
        self._status(
            f"Capturando em: {desc_sel} (dispositivo: {nome_dispositivo}){rede_info}"
        )

        self._atualizar_subredes_rotas()
        QTimer.singleShot(4000, self._varredura_inicial_segura)
        QTimer.singleShot(500,  self._popular_topologia_via_arp_sistema)

    def _parar_captura(self):
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()

        if self.capturador:
            self.capturador.parar()
            self.capturador = None

        self.analisador.parar_thread()
        self._consumir_fila()

        self._interface_captura = ""
        self._cidr_captura      = ""
        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")
        self._status("Captura encerrada.")

    @staticmethod
    def _repolir(botao: QPushButton):
        botao.style().unpolish(botao)
        botao.style().polish(botao)

    # -------------------------------------------------------------------------
    # Consumo da fila e atualização da UI
    # -------------------------------------------------------------------------

    @pyqtSlot()
    def _consumir_fila(self):
        for dados in fila_pacotes_global.consumir_todos():
            self.analisador.enfileirar(dados)

        eventos, _ = self.analisador.coletar_resultados()
        subredes_alteradas = False

        for evento in eventos:
            ip_origem  = evento.get("ip_origem",  "")
            ip_destino = evento.get("ip_destino", "")
            mac_origem = evento.get("mac_origem", "")
            tipo       = evento.get("tipo",       "")

            mac_e_valido = (
                mac_origem
                and mac_origem not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "")
            )

            if ip_origem and _ip_eh_topologizavel(ip_origem) and mac_e_valido:
                subredes_alteradas = (
                    self._registrar_host_confirmado(
                        ip=ip_origem,
                        mac=mac_origem,
                        confirmado_por_arp=(tipo == "ARP"),
                        atualizar_subredes=False,
                    )
                    or subredes_alteradas
                )

            if (
                ip_origem and ip_destino
                and _ip_eh_topologizavel(ip_origem)
                and _ip_eh_topologizavel(ip_destino)
            ):
                self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)

            if tipo:
                if tipo == "NOVO_DISPOSITIVO":
                    if ip_origem:
                        status = self.estado_rede.registrar_dispositivo(
                            ip_origem, mac_origem
                        )
                        if status == "NOVO" and self.estado_rede.deve_emitir_evento(
                            f"novo_{ip_origem}", cooldown=30
                        ):
                            self.fila_eventos_ui.append(evento)
                else:
                    discriminador = (
                        evento.get("dominio", "")
                        or f"{evento.get('metodo', '')}:{evento.get('recurso', '')}"
                    )
                    chave = f"{tipo}_{ip_origem}_{discriminador}"

                    if tipo in ("HTTP", "HTTPS"):
                        self.fila_eventos_ui.append(evento)
                    elif tipo == "DNS":
                        chave_dns = f"DNS_{ip_origem}_{evento.get('dominio', '')}"
                        if self.estado_rede.deve_emitir_evento(chave_dns, cooldown=3):
                            self.fila_eventos_ui.append(evento)
                    else:
                        if self.estado_rede.deve_emitir_evento(chave, cooldown=5):
                            self.fila_eventos_ui.append(evento)

        if subredes_alteradas:
            self._sincronizar_subredes_topologia()

        self._snapshot_atual = {
            "total_bytes":        self.analisador.total_bytes,
            "total_pacotes":      self.analisador.total_pacotes,
            "estatisticas":       self.analisador.obter_estatisticas_protocolos(),
            "top_dispositivos":   self.analisador.obter_top_dispositivos(),
            "dispositivos_ativos": len(self.analisador.trafego_dispositivos),
            "top_dns":            self.analisador.obter_top_dns(),
            "historias":          self._gerar_historias(),
        }

    def _agregar_eventos(self, eventos: list) -> list:
        agregados: dict = {}
        resultado: list = []
        for ev in eventos:
            if ev.get("tipo") in ("HTTP", "HTTPS"):
                resultado.append(ev)
                continue
            chave = (
                ev.get("tipo"),
                ev.get("ip_origem"),
                ev.get("ip_destino"),
                ev.get("dominio",  ""),
                ev.get("metodo",   ""),
                ev.get("recurso",  ""),
            )
            if chave not in agregados:
                item = {**ev, "contagem": 1}
                agregados[chave] = item
                resultado.append(item)
            else:
                agregados[chave]["contagem"] += 1
        return resultado

    @pyqtSlot()
    def _descarregar_eventos_ui(self):
        if not self.fila_eventos_ui:
            return

        lote = list(self.fila_eventos_ui)
        self.fila_eventos_ui.clear()
        lote = lote[-8:]

        for ev in self._agregar_eventos(lote):
            tipo = ev.get("tipo", "")
            if tipo in ("HTTP", "HTTPS"):
                self._exibir_evento_pedagogico(ev)
                continue

            discriminador_visual = (
                ev.get("dominio", "")
                or f"{ev.get('metodo', '')}:{ev.get('recurso', '')}"
            )
            chave_visual = (
                ev.get("tipo"), ev.get("ip_origem"),
                ev.get("ip_destino"), discriminador_visual,
            )
            if chave_visual in self.eventos_mostrados_recentemente:
                continue
            self.eventos_mostrados_recentemente.append(chave_visual)
            self._exibir_evento_pedagogico(ev)

    @pyqtSlot()
    def _atualizar_ui_por_segundo(self):
        snap          = self._snapshot_atual
        total_bytes   = snap.get("total_bytes",   0)
        total_pacotes = snap.get("total_pacotes", 0)

        agora   = time.perf_counter()
        delta_t = max(agora - self._instante_anterior, 0.001)
        delta_b = max(0, total_bytes - self._bytes_total_anterior)
        kb_raw  = (delta_b / 1024.0) / delta_t

        alpha         = 0.3
        kb_por_s      = alpha * kb_raw + (1.0 - alpha) * self._kb_anterior
        self._kb_anterior = kb_por_s

        self._bytes_total_anterior = total_bytes
        self._instante_anterior    = agora

        self.painel_trafego.adicionar_ponto_grafico(kb_por_s)
        self.painel_trafego.atualizar_tabelas(
            estatisticas_protocolos=snap.get("estatisticas",      []),
            top_dispositivos       =snap.get("top_dispositivos",  []),
            total_pacotes          =total_pacotes,
            total_bytes            =total_bytes,
            total_topologia        =self.painel_topologia.total_dispositivos(),
            total_ativos           =self.painel_topologia.total_dispositivos(),
        )
        self.painel_topologia.atualizar()

        kb = total_bytes / 1024
        curr_cidr = self._cidr_captura or ""

        self.painel_eventos.atualizar_stats(
            pacotes=total_pacotes,
            rede=curr_cidr if curr_cidr else "—",
            dados=formatar_bytes(total_bytes)
        )
        cidr_label = (
            f"Rede: {curr_cidr}"
            if (curr_cidr and "/32" not in str(curr_cidr))
            else "Rede: Detectando..."
        )

        self.lbl_pacotes.setText(f"Pacotes: {total_pacotes:,}")
        self.lbl_dados.setText(
            f"  {cidr_label}  |  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  {cidr_label}  |  Dados: {kb:.1f} KB  "
        )

    # -------------------------------------------------------------------------
    # Motor pedagógico
    # -------------------------------------------------------------------------

    def _exibir_evento_pedagogico(self, evento: dict):
        runnable = _WorkerRunnable(evento, self.motor_pedagogico)
        self._thread_pool.start(runnable)

    def _finalizar_exibicao_evento(self, explicacao: dict):
        self.painel_eventos.adicionar_evento(explicacao)

    def _finalizar_workers(self):
        self._thread_pool.waitForDone(3000)

    # -------------------------------------------------------------------------
    # Descoberta de dispositivos
    # -------------------------------------------------------------------------

    def _varredura_inicial_segura(self):
        if not self.em_captura or not self._interface_captura:
            return
        if self._eh_wifi or not self._param_arps.get("descoberta_ativa", True):
            self._popular_topologia_via_arp_sistema()
            self._status(
                " Wi-Fi em modo laboratorio: descoberta ativa desativada; "
                "usando tabela ARP do Windows e captura passiva."
            )
            return
        if self.descoberta_rodando or (
            self.descobridor and self.descobridor.isRunning()
        ):
            return

        cidr_local    = self.gerenciador_subredes._cidr_local()
        cidr_varredura = cidr_local if cidr_local else self._cidr_captura
        limite_inicial = min(500, self._limite_hosts)

        parametros_leves = {
            "limite_hosts":   limite_inicial,
            "tentativas":     2 if self._eh_wifi else 2,
            "timeout":        2.8 if self._eh_wifi else 1.8,
            "batch":          8 if self._eh_wifi else 32,
            "inter":          0.02,
            "sleep_lote":     0.25 if self._eh_wifi else 0.05,
            "desativar_icmp": True,
            "pausa":          1.0,
            "wifi":           self._eh_wifi,
            "timer_ms":       self._periodo_timer_ms,
        }

        self.descoberta_rodando = True
        self._status(
            f" Varredura inicial: descobrindo até {limite_inicial} "
            f"dispositivo(s) na rede {cidr_varredura or 'local'}…"
        )

        self.descobridor = _DescobrirDispositivosThread(
            interface=self._interface_captura,
            cidr=cidr_varredura,
            parametros=parametros_leves,
        )
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura_inicial)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_erro_varredura_silencioso)
        self.descobridor.start()

    @pyqtSlot(list)
    def _ao_concluir_varredura_inicial(self, dispositivos: list):
        total = len(dispositivos)
        self._status(
            f" Varredura inicial: {total} dispositivo(s) encontrado(s). "
            f"Captura passiva ativa."
        )
        self.descoberta_rodando = False

    @pyqtSlot(str)
    def _ao_erro_varredura_silencioso(self, mensagem: str):
        self._status(f" Varredura: {mensagem[:80]}")
        self.descoberta_rodando = False

    def _popular_topologia_via_arp_sistema(self):
        if not self.em_captura:
            return

        entradas    = self._obter_tabela_arp_sistema()
        adicionados = 0
        subredes_alteradas = False
        cidr_local = self.gerenciador_subredes._cidr_local() or self._cidr_captura
        for entrada in entradas:
            if not _ip_eh_topologizavel(entrada["ip"]):
                continue
            subredes_alteradas = (
                self._registrar_host_confirmado(
                    ip=entrada["ip"],
                    mac=entrada["mac"],
                    confirmado_por_arp=True,
                    atualizar_subredes=False,
                    cidr_forcado=cidr_local,
                )
                or subredes_alteradas
            )
            adicionados += 1

        if subredes_alteradas:
            self._sincronizar_subredes_topologia()

        if adicionados:
            self._status(
                f" Tabela ARP do sistema: {adicionados} dispositivo(s) "
                f"importado(s) para a topologia."
            )

    def _atualizar_subredes_rotas(self):
        if not self.em_captura:
            return

        novas = self.gerenciador_subredes.detectar_subredes_via_rotas()
        if not novas:
            return

        self._sincronizar_subredes_topologia()
        self._status(
            f" {len(novas)} nova(s) sub-rede(s) inferida(s) via tabela de rotas."
        )

    @staticmethod
    def _obter_tabela_arp_sistema() -> list:
        entradas = []
        try:
            if platform.system() == "Windows":
                saida = subprocess.check_output(
                    ["arp", "-a"],
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                padrao = re.compile(
                    r'\s+([\d.]+)\s+([\da-f]{2}[-:][\da-f]{2}[-:]'
                    r'[\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2}[-:][\da-f]{2})'
                    r'\s+(\w+)',
                    re.IGNORECASE
                )
            else:
                saida = subprocess.check_output(
                    ["ip", "neigh"], text=True, timeout=5
                )
                padrao = re.compile(
                    r'^([\d.]+)\s+dev\s+\S+\s+lladdr\s+'
                    r'([\da-f:]{17})\s+(\w+)',
                    re.IGNORECASE | re.MULTILINE
                )

            for corr in padrao.finditer(saida):
                ip_arp  = corr.group(1)
                mac_arp = corr.group(2).replace("-", ":").lower()
                tipo    = corr.group(3)
                if mac_arp in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue
                entradas.append({"ip": ip_arp, "mac": mac_arp, "tipo": tipo})

        except Exception:
            pass

        return entradas

    def _descoberta_periodica(self):
        if not self.em_captura:
            return
        if self._eh_wifi or not self._param_arps.get("descoberta_ativa", True):
            self._popular_topologia_via_arp_sistema()
            self._status(
                " Descoberta Wi-Fi segura: tabela ARP do sistema atualizada "
                "sem injetar pacotes."
            )
            return
        if self.descoberta_rodando or (
            self.descobridor and self.descobridor.isRunning()
        ):
            return
        if not self._interface_captura:
            return

        cidr_local     = self.gerenciador_subredes._cidr_local()
        cidr_varredura = cidr_local if cidr_local else self._cidr_captura

        self.descoberta_rodando = True
        self._status(
            f" Varrendo a rede local em busca de dispositivos em {cidr_varredura or 'local'}…"
        )

        self.descobridor = _DescobrirDispositivosThread(
            interface=self._interface_captura,
            cidr=cidr_varredura,
            parametros=self._param_arps,
        )
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_ocorrer_erro)
        self.descobridor.start()

    @pyqtSlot(str, str, str)
    def _ao_encontrar_dispositivo(self, ip: str, mac: str, hostname: str):
        if not _ip_eh_topologizavel(ip):
            return
        self._registrar_host_confirmado(
            ip=ip,
            mac=mac,
            hostname=hostname,
            confirmado_por_arp=True,
        )
        self.fila_eventos_ui.append({
            "tipo":       "NOVO_DISPOSITIVO",
            "ip_origem":  ip,
            "ip_destino": "",
            "mac_origem": mac,
            "protocolo":  "ARP",
            "tamanho":    0,
        })

    def _exibir_diagnostico_captura(self):
        diag = DiagnosticoAvançado(self)
        diag.exec()

    @pyqtSlot(list)
    def _ao_concluir_varredura(self, dispositivos: list):
        self._status(
            f"Varredura concluída — {len(dispositivos)} dispositivo(s) encontrado(s)."
        )
        self.descoberta_rodando = False

    # -------------------------------------------------------------------------
    # Erros e ações gerais
    # -------------------------------------------------------------------------

    @pyqtSlot(str)
    def _ao_ocorrer_erro(self, mensagem: str):
        self._status(f"Erro: {mensagem[:80]}")
        QMessageBox.warning(self, "Erro", mensagem)
        if self.em_captura:
            self._parar_captura()
        self.descoberta_rodando = False

    def _nova_sessao(self):
        self._finalizar_workers()
        if self.em_captura:
            self._parar_captura()
        self.analisador.resetar()
        self.gerenciador_subredes.limpar()
        self.painel_topologia.limpar()
        self.painel_topologia.definir_rede_local(self._cidr_captura)
        self.painel_trafego.limpar()
        self.painel_eventos.limpar()
        self._snapshot_atual = {
            "total_bytes": 0, "total_pacotes": 0,
            "estatisticas": [], "top_dispositivos": [],
            "dispositivos_ativos": 0,
        }
        self._bytes_total_anterior = 0
        self._instante_anterior    = time.perf_counter()
        self._status("Nova sessão iniciada. Pronto para capturar.")

    def _status(self, mensagem: str):
        self.lbl_status.setText(mensagem)

    def _exibir_sobre(self):
        QMessageBox.about(
            self,
            "Sobre o NetLab Educacional",
            "<h2>NetLab Educacional V4.0</h2>"
            "<p>Plataforma educacional para análise de redes locais com "
            "captura de pacotes em tempo real e explicações didáticas "
            "automatizadas.</p>"
            "<hr>"
            "<p><b>TCC — Curso Técnico em Informática</b></p>"
            "<p><b>Tecnologias:</b> Python · PyQt6 · Scapy · PyQtGraph</p>"
            "<p><b>Destaques:</b> DPI, detecção de dados sensíveis, "
            "identificação via MAC/OUI e monitoramento em tempo real.</p>"
            "<p><b>Autor:</b> Yuri Gonçalves Pavão</p>"
            "<p><b>Instagram:</b> @yuri_g0n | "
            "<b>GitHub:</b> github.com/Yurigonpav</p>"
        )

    # ─────────────────────────────────────────────────────────────────────
    # Atualização da base OUI de fabricantes
    # ─────────────────────────────────────────────────────────────────────

    def _solicitar_atualizacao_base_oui(self):
        self._status(" Baixando base de fabricantes do Wireshark… (em segundo plano)")

        def ao_concluir(sucesso: bool, mensagem: str):
            self._resultado_atualizacao_oui = (sucesso, mensagem)
            QTimer.singleShot(0, self._ao_concluir_atualizacao_oui)

        self.gerenciador_dispositivos.atualizar_base_wireshark(
            callback_conclusao=ao_concluir
        )

    @pyqtSlot()
    def _ao_concluir_atualizacao_oui(self):
        sucesso, mensagem = getattr(self, "_resultado_atualizacao_oui", (False, ""))

        if sucesso:
            self._status(f" {mensagem}")
            QMessageBox.information(self, "Base OUI Atualizada", f" {mensagem}")
        else:
            self._status(f" Falha: {mensagem}")
            QMessageBox.warning(self, "Falha na Atualização", mensagem)

    def closeEvent(self, evento):
        self._finalizar_workers()
        if self.em_captura:
            self._parar_captura()
        evento.accept()