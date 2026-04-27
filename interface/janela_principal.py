
# interface/janela_principal.py

import threading
import time
import ipaddress
import subprocess
import re
import ctypes
from collections import deque
from typing import Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QComboBox,
    QMessageBox, QToolBar, QTabWidget,
    QDialog, QHBoxLayout, QTextEdit,
    QDialogButtonBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QThread, pyqtSignal, QObject, QRunnable, QThreadPool
from PyQt6.QtGui import QAction, QFont

from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor
from utils.constantes import PORTAS_HTTP, PORTAS_DHCP
from utils.gerenciador_subredes import GerenciadorSubRedes, Visibilidade
from utils.rede import obter_ip_local
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

            # Limpeza periódica: remove entradas com mais de 120 segundos.
            # Sem isso o dicionário cresce indefinidamente — cada URL, IP e
            # domínio únicos visto na sessão fica armazenado para sempre.
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

_MAX_PACOTES_POR_SEGUNDO = 800


class _CapturadorPacotesThread(QThread):
    erro_ocorrido = pyqtSignal(str)
    sem_pacotes   = pyqtSignal(str)

    def __init__(self, interface: str, eh_wifi: bool = False):
        super().__init__()
        self.interface = interface
        self.eh_wifi   = eh_wifi   # <-- NOVO
        self._rodando  = False
        self.sniffer   = None
        self._pps_contador  = 0
        self._pps_reset_ts  = 0.0

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
                    promisc=not self.eh_wifi,   # <-- MUDANÇA: Wi-Fi não usa promisc
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
        if self._pps_contador > _MAX_PACOTES_POR_SEGUNDO:
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
            "wifi":           False,
            "timer_ms":       30000,
        }
        self._limite_hosts     = self._param_arps["limite_hosts"]
        self._eh_wifi          = self._param_arps.get("wifi", False)
        self._periodo_timer_ms = self._param_arps.get("timer_ms", 30000)

    def run(self):
        try:
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
        # Gerenciador de identificação de fabricantes via OUI (Singleton)
        # Inicializado uma única vez; compartilhado com painel_topologia
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

        # ── Menu: Atualizar base OUI ──────────────────────────────────────
        m_mon.addSeparator()
        a_atualizar_oui = QAction("Atualizar Base de Fabricantes", self)
        a_atualizar_oui.setToolTip(
            "Baixa a base OUI mais recente do Wireshark (requer internet).\n"
            "A identificação de fabricantes em dispositivos novos será aprimorada."
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
        # ── PATCH: lazy loading ao trocar de aba ──────────────────────────
        self.abas.currentChanged.connect(self._ao_mudar_aba)
        # ──────────────────────────────────────────────────────────────────
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
        """
        PATCH v3.1: quando o usuário abre o Modo Análise, reaplicar os
        filtros com o guard de chave ativo — reconstrói a lista apenas se
        houve eventos novos desde a última vez que a aba ficou visível.
        Isso elimina o freeze causado por centenas de widgets sendo
        instanciados de uma só vez no momento da troca de aba.
        """
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

        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces_raw = get_windows_if_list()
        except Exception:
            interfaces_raw = []

        if not interfaces_raw:
            for desc in obter_interfaces_disponiveis():
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = desc
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
                try:
                    idx = ips.index(ip_v4)
                    if idx < len(mascaras):
                        candidato = mascaras[idx]
                        if candidato and '.' in str(candidato):
                            self._mapa_interface_mascara[desc] = str(candidato)
                except Exception:
                    pass
                if desc not in self._mapa_interface_mascara:
                    for mask_candidata in mascaras:
                        if mask_candidata and '.' in str(mask_candidata):
                            self._mapa_interface_mascara[desc] = str(mask_candidata)
                            break

            if desc not in self._mapa_interface_mascara:
                for campo in ('netmask', 'mask'):
                    v = iface.get(campo)
                    if v and '.' in str(v):
                        self._mapa_interface_mascara[desc] = str(v)
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
    def _mascara_para_prefixo(mascara: str) -> int:
        try:
            return sum(bin(int(p)).count("1") for p in mascara.split("."))
        except Exception:
            return 24

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
            raw  = proc.stdout
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

    def _cidr_da_interface(self, desc: str) -> str:
        ip_interface = self._mapa_interface_ip.get(desc, "") or obter_ip_local()
        if not ip_interface or ip_interface == "127.0.0.1":
            return ""

        cidr = self._detectar_cidr_via_powershell(ip_interface)
        if cidr:
            self._status(f" CIDR via PowerShell: {cidr}")
            return cidr

        cidr = self._obter_cidr_via_ipconfig(ip_interface)
        if cidr:
            self._status(f" CIDR via ipconfig: {cidr}")
            return cidr

        mascara = self._mapa_interface_mascara.get(desc, "")
        if mascara and '.' in mascara:
            try:
                prefixo = self._mascara_para_prefixo(mascara)
                rede    = ipaddress.ip_network(f"{ip_interface}/{prefixo}", strict=False)
                self._status(f" CIDR via Scapy mapeamento: {rede}")
                return str(rede)
            except Exception:
                pass

        nome_dispositivo = self._mapa_interface_nome.get(desc, desc)
        cidr = self._detectar_cidr_via_scapy(nome_dispositivo)
        if cidr:
            self._status(f" CIDR via Scapy direto: {cidr}")
            return cidr

        rede_restrita = f"{ip_interface}/32"
        self._status(
            f" Máscara não detectada para '{desc}'. "
            f"Usando /32 ({rede_restrita}). "
            f"Apenas este computador aparecerá como local."
        )
        return rede_restrita

    def _parametros_iface_seguro(self, nome_iface: str) -> dict:
        nome_lower = (nome_iface or "").lower()
        eh_wifi = any(
            p in nome_lower
            for p in ("wi-fi", "wifi", "wireless", "ax", "802.11")
        )

        base = {
            "limite_hosts":   100,
            "desativar_icmp": False,
            "tentativas":     _DescobrirDispositivosThread.TENTATIVAS,
            "timeout":        _DescobrirDispositivosThread.TIMEOUT_ARP,
            "pausa":          _DescobrirDispositivosThread.PAUSA_RODADAS,
            "inter":          _DescobrirDispositivosThread.INTER_ARP,
            "sleep_lote":     0.0,
            "batch":          _DescobrirDispositivosThread.BATCH_ARP,
            "wifi":           eh_wifi,
            "timer_ms":       30000,
        }

        if eh_wifi:
            base.update({
                "batch":          8,
                "sleep_lote":     0.25,
                "pausa":          3.0,
                "timeout":        3.5,
                "tentativas":     2,
                "desativar_icmp": True,
                "timer_ms":       300_000,
            })

        return base

    def _sincronizar_subredes_topologia(self):
        """Envia ao painel a fotografia atual das sub-redes conhecidas."""
        self.painel_topologia.atualizar_subredes(
            self.gerenciador_subredes.todas_subredes()
        )

    def _registrar_subrede_local(self):
        """
        Registra a sub-rede da interface ativa sem alargar o escopo artificialmente.

        Se o CIDR nao puder ser determinado com seguranca, o projeto ja usa /32.
        Mantemos esse comportamento para preservar a honestidade da topologia.
        """
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
        """
        Registra um host observado sem criar evidencias artificiais.

        Retorna True quando houve mudanca de hosts/visibilidade em alguma sub-rede.
        """
        if not ip or not _ip_eh_topologizavel(ip):
            return False

        subrede = None
        eh_local = False
        if cidr_forcado:
            subrede_forcada = self.gerenciador_subredes.subredes.get(cidr_forcado)
            if subrede_forcada and subrede_forcada.contem(ip):
                subrede = subrede_forcada
                eh_local = (subrede.cidr == self.gerenciador_subredes._cidr_local())

        if subrede is None:
            subrede, eh_local = self.gerenciador_subredes.classificar_ip(ip)
        houve_alteracao = False

        if subrede:
            total_hosts_antes = len(subrede.hosts)
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
                eh_wifi=self._eh_wifi          # <-- NOVO
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

        # 400ms é suficiente — a thread de análise já processa em paralelo.
        # Em 250ms com volume alto de pacotes, _consumir_fila era chamado
        # antes dos resultados estarem prontos, gerando ciclos vazios frequentes.
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
        """
        Timer a cada 2s: descarrega a fila de eventos para o motor pedagógico.

        PATCH v3.1 — backpressure:
          Limita a 8 eventos por ciclo (descarta os mais antigos se a fila
          acumulou mais). Em redes movimentadas, o cooldown em _consumir_fila
          já filtra duplicatas; descartar eventos antigos é aceitável e
          previne que a UI thread seja sobrecarregada.
        """
        if not self.fila_eventos_ui:
            return

        lote = list(self.fila_eventos_ui)
        self.fila_eventos_ui.clear()

        # ── Backpressure: máx 8 eventos por ciclo de 2s ──────────────────
        lote = lote[-8:]
        # ──────────────────────────────────────────────────────────────────

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
        self.painel_eventos.atualizar_insights(
            snap.get("top_dns",   []),
            snap.get("historias", []),
        )

        kb = total_bytes / 1024
        self.lbl_pacotes.setText(f"Pacotes: {total_pacotes:,}")
        self.lbl_dados.setText(
            f"  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  Dados: {kb:.1f} KB  "
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
        if self.descoberta_rodando or (
            self.descobridor and self.descobridor.isRunning()
        ):
            return

        cidr_local = self.gerenciador_subredes._cidr_local()
        cidr_varredura = cidr_local if cidr_local else self._cidr_captura
        limite_inicial = min(500, self._limite_hosts)

        parametros_leves = {
            "limite_hosts":   limite_inicial,
            "tentativas":     1,
            "timeout":        0.8,
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
        """Atualiza segmentos inferidos via tabela de rotas."""
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
        import platform
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
        if self.descoberta_rodando or (
            self.descobridor and self.descobridor.isRunning()
        ):
            return
        if not self._interface_captura:
            return

        cidr_local = self.gerenciador_subredes._cidr_local()
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

    @pyqtSlot(list)
    def _ao_concluir_varredura(self, dispositivos: list):
        self._status(
            f"Varredura concluída — {len(dispositivos)} dispositivo(s) encontrado(s)."
        )
        self.descoberta_rodando = False

    # -------------------------------------------------------------------------
    # Diagnóstico
    # -------------------------------------------------------------------------

    def _exibir_diagnostico_captura(self):
        import os
        try:
            import winreg
            _winreg_ok = True
        except ImportError:
            _winreg_ok = False

        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout

        desc_sel         = self.combo_interface.currentText()
        nome_dispositivo = self._mapa_interface_nome.get(desc_sel, desc_sel)
        ip_local         = self._mapa_interface_ip.get(desc_sel, obter_ip_local())
        mascara          = self._mapa_interface_mascara.get(desc_sel, "")
        cidr             = self._cidr_captura or ""

        if not mascara and cidr:
            try:
                import ipaddress
                mascara = str(ipaddress.ip_network(cidr, strict=False).netmask)
            except Exception:
                pass

        total_local      = self.painel_topologia.total_dispositivos()
        snap             = getattr(self, "_snapshot_atual", {})

        # ── Testes ──────────────────────────────────────────────────────────────

        # Admin
        is_admin = False
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass

        # Npcap
        npcap_path = ""
        npcap_ok   = False
        if _winreg_ok:
            try:
                for hive, path in [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
                ]:
                    try:
                        with winreg.OpenKey(hive, path) as k:
                            try:
                                npcap_path, _ = winreg.QueryValueEx(k, "")
                            except Exception:
                                npcap_path = "Instalado"
                            npcap_ok = True
                            break
                    except Exception:
                        continue
            except Exception:
                pass
        if not npcap_ok:
            for dll in [
                r"C:\Windows\System32\Npcap\wpcap.dll",
                r"C:\Windows\SysWOW64\wpcap.dll",
            ]:
                if os.path.exists(dll):
                    npcap_ok   = True
                    npcap_path = os.path.dirname(dll)
                    break

        # Wi-Fi
        nome_lower = (nome_dispositivo or desc_sel or "").lower()
        eh_wifi = any(p in nome_lower for p in ("wi-fi", "wifi", "wireless", "ax", "802.11"))

        # Interface reconhecida pelo Scapy
        iface_em_scapy = False
        iface_scapy_label = ""
        try:
            from scapy.all import get_if_list
            lista = get_if_list()
            # Tenta pelo nome interno (Npcap NPF)
            iface_em_scapy = nome_dispositivo in lista
            if not iface_em_scapy and eh_wifi:
                # Wi-Fi: Scapy usa \Device\NPF_{GUID}, nunca o nome amigável.
                # Confirma presença verificando se alguma entrada NPF existe.
                iface_em_scapy = any("NPF_" in i for i in lista)
                iface_scapy_label = "Wi-Fi usa identificador interno (NPF)"
            elif iface_em_scapy:
                iface_scapy_label = "Reconhecida pelo Scapy"
            else:
                iface_scapy_label = "Não listada"
        except Exception:
            iface_scapy_label = "Não foi possível verificar"

        # CIDR válido
        cidr_ok = False
        if cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
                cidr_ok = True
            except Exception:
                pass

        # Threads
        thread_cap_ok  = bool(self.capturador and self.capturador.isRunning())
        thread_anal_ok = False
        try:
            thread_anal_ok = bool(
                self.analisador._thread and self.analisador._thread.is_alive()
            )
        except Exception:
            pass

        # Filas
        fila_global_n  = 0
        fila_entrada_n = 0
        fila_saida_n   = 0
        try:
            from interface.analisador_trafego import fila_pacotes_global
            fila_global_n  = len(fila_pacotes_global._fila)
            fila_entrada_n = len(self.analisador._fila_entrada)
            fila_saida_n   = len(self.analisador._fila_saida)
        except Exception:
            pass

        fila_global_pct  = int(fila_global_n  / 20_000 * 100)
        fila_entrada_pct = int(fila_entrada_n / 20_000 * 100)
        fila_saida_pct   = int(fila_saida_n   / 5_000  * 100)

        def _cor_fila(pct):
            return "#2ECC71" if pct < 50 else ("#E67E22" if pct < 80 else "#E74C3C")

        # Pacotes
        total_pacotes = snap.get("total_pacotes", 0)
        total_bytes   = snap.get("total_bytes", 0)
        kb_atual      = getattr(self, "_kb_anterior", 0)
        cap_ativa     = self.em_captura and thread_cap_ok
        pacotes_ok    = cap_ativa and total_pacotes > 0

        # Gateway via tabela ARP
        gateway_ip  = ""
        gateway_mac = ""
        try:
            for entrada in self._obter_tabela_arp_sistema():
                partes = entrada["ip"].split(".")
                if len(partes) == 4 and int(partes[-1]) in (1, 254):
                    gateway_ip  = entrada["ip"]
                    gateway_mac = entrada["mac"]
                    break
        except Exception:
            pass

        # Param ARP
        param = (
            self._param_arps
            if self._param_arps
            else self._parametros_iface_seguro(nome_dispositivo)
        )

        # ── Checklist ──────────────────────────────────────────────────────────

        ok_items  = []
        avisos    = []
        problemas = []

        if is_admin:
            ok_items.append("Executando como Administrador")
        else:
            problemas.append("Sem privilégios de Administrador — captura impossível")

        if npcap_ok:
            ok_items.append(f"Npcap instalado ({npcap_path or 'detectado via DLL'})")
        else:
            problemas.append("Npcap não encontrado — instale em npcap.com")

        if desc_sel and "nenhuma" not in desc_sel.lower():
            ok_items.append(f"Interface selecionada: {desc_sel}")
        else:
            problemas.append("Nenhuma interface válida selecionada")

        if iface_em_scapy:
            ok_items.append(f"Interface verificada no Scapy/Npcap ({iface_scapy_label})")
        else:
            avisos.append(f"Interface não reconhecida pelo Scapy — {iface_scapy_label}")

        if cidr_ok:
            ok_items.append(f"CIDR detectado: {cidr}")
        else:
            avisos.append("CIDR não detectado — dispositivos locais podem aparecer como Internet")

        if eh_wifi:
            ok_items.append("Wi-Fi: modo promíscuo desativado intencionalmente (preserva conectividade)")
        else:
            ok_items.append("Ethernet: modo promíscuo ativo")

        if cap_ativa:
            ok_items.append("Thread de captura ativa e responsiva")
        elif self.em_captura:
            problemas.append("Thread de captura iniciada mas não está respondendo")

        if self.em_captura:
            if thread_anal_ok:
                ok_items.append("Thread de análise de pacotes ativa")
            else:
                problemas.append("Thread de análise inativa — eventos não estão sendo processados")

        if pacotes_ok:
            ok_items.append(f"Pacotes sendo capturados ({total_pacotes:,} total, {kb_atual:.1f} KB/s)")
        elif self.em_captura and total_pacotes == 0:
            problemas.append("Nenhum pacote capturado — verifique interface e Npcap")

        if self.em_captura and fila_entrada_pct >= 80:
            avisos.append(f"Fila de análise quase cheia ({fila_entrada_pct}%) — risco de descarte")
        elif self.em_captura:
            ok_items.append(f"Filas dentro do limite (entrada {fila_entrada_pct}%, saída {fila_saida_pct}%)")

        if gateway_ip:
            ok_items.append(f"Gateway detectado: {gateway_ip} ({gateway_mac})")
        else:
            avisos.append("Gateway não visível na tabela ARP do sistema")

        # Score
        n_prob = len(problemas)
        n_avi  = len(avisos)

        if n_prob == 0 and n_avi == 0:
            sc, si, st, sf, sb = "#2ECC71", "", "Tudo funcionando corretamente", "#001a00", "#2ECC71"
        elif n_prob == 0:
            sc, si, st, sf, sb = "#E67E22", "", f"Funcionando com {n_avi} aviso(s)", "#1a1000", "#E67E22"
        else:
            sc, si, st, sf, sb = "#E74C3C", "", f"{n_prob} problema(s) crítico(s)", "#1a0000", "#E74C3C"

        # ── Helpers HTML ────────────────────────────────────────────────────────

        def secao(titulo, cor):
            return (
                f"<div style='margin:14px 0 5px 0;'>"
                f"<span style='color:{cor};font-weight:bold;font-size:9px;"
                f"text-transform:uppercase;letter-spacing:1px;'>{titulo}</span>"
                f"</div>"
                f"<hr style='border:none;border-top:1px solid {cor}44;margin:0 0 6px 0;'>"
            )

        def tr(rotulo, valor, cor_v="#ecf0f1", mono=False):
            f = "font-family:Consolas;" if mono else ""
            return (
                f"<tr>"
                f"<td style='color:#7f8c8d;padding:3px 14px 3px 0;white-space:nowrap;"
                f"font-size:10px;vertical-align:top;width:140px;'>{rotulo}</td>"
                f"<td style='color:{cor_v};font-size:10px;{f}'>{valor}</td>"
                f"</tr>"
            )

        def check_item(texto, tipo):
            cfg = {
                "ok":    ("", "#2ECC71", "#002200"),
                "warn":  ("",  "#E67E22", "#1f1200"),
                "error": ("", "#E74C3C", "#200000"),
            }[tipo]
            return (
                f"<div style='background:{cfg[2]};padding:4px 10px;"
                f"border-left:3px solid {cfg[1]};margin:2px 0;border-radius:0 4px 4px 0;'>"
                f"<span style='color:{cfg[1]};font-size:10px;'>{cfg[0]} {texto}</span>"
                f"</div>"
            )

        def rec_item(icone, cor, texto):
            return (
                f"<div style='border-left:3px solid {cor};padding:6px 10px;"
                f"margin:3px 0;background:{cor}15;border-radius:0 4px 4px 0;'>"
                f"<span style='color:{cor};font-size:10px;'>{icone} {texto}</span>"
                f"</div>"
            )

        # ── HTML ─────────────────────────────────────────────────────────────────

        html = (
            "<div style='font-family:Arial,sans-serif;font-size:11px;"
            "line-height:1.6;color:#ecf0f1;'>"
        )

        # Status geral
        html += (
            f"<div style='background:{sf};border:2px solid {sb};"
            f"border-radius:8px;padding:12px 16px;margin-bottom:14px;'>"
            f"<span style='color:{sc};font-size:14px;font-weight:bold;'>{si} {st}</span>"
            f"<span style='color:#566573;font-size:10px;margin-left:12px;'>"
            f"{len(ok_items)} ok · {n_avi} aviso(s) · {n_prob} problema(s)</span>"
            f"</div>"
        )

        # Checklist
        html += secao("Checklist de Requisitos", "#3498DB")
        for item in ok_items:
            html += check_item(item, "ok")
        for item in avisos:
            html += check_item(item, "warn")
        for item in problemas:
            html += check_item(item, "error")

        # Adaptador
        html += secao("Adaptador de Rede", "#9B59B6")
        html += "<table style='width:100%;'>"
        html += tr("Interface",       desc_sel)
        html += tr("Dispositivo",     f"<code style='font-size:9px;'>{nome_dispositivo}</code>")
        html += tr("Tipo",            ("<span style='color:#E67E22;'>Wi-Fi 802.11</span>"
                                        if eh_wifi else "Ethernet / LAN"))
        html += tr("Npcap",           (f"<span style='color:#2ECC71;'> {npcap_path or 'Instalado'}</span>"
                                        if npcap_ok else
                                        "<span style='color:#E74C3C;'> Não encontrado</span>"))
        html += tr("Scapy/Npcap",
                   (f"<span style='color:#2ECC71;'> {iface_scapy_label}</span>"
                    if iface_em_scapy else
                    f"<span style='color:#E74C3C;'> {iface_scapy_label}</span>"))
        html += "</table>"

        # Rede
        html += secao("Rede", "#2ECC71")
        html += "<table style='width:100%;'>"
        html += tr("IP local",  f"<b style='color:#2ECC71;'>{ip_local}</b>")
        html += tr("Máscara",   mascara or "<span style='color:#E67E22;'>Não detectada</span>")
        html += tr("CIDR",      (f"<b style='color:#F39C12;'>{cidr}</b>"
                                   if cidr_ok else
                                   "<span style='color:#E74C3C;'>Não definido</span>"))
        html += tr("Gateway",   (f"{gateway_ip} <span style='color:#566573;font-size:9px;'>"
                                   f"({gateway_mac})</span>"
                                   if gateway_ip else
                                   "<span style='color:#7f8c8d;'>Não detectado na tabela ARP</span>"))
        html += tr("Dispositivos locais", str(total_local))
        html += "</table>"

        # Captura
        html += secao("Estado da Captura", "#3498DB")
        html += "<table style='width:100%;'>"
        if cap_ativa:
            html += tr("Estado", "<span style='color:#2ECC71;'> Capturando</span>")
        elif self.em_captura:
            html += tr("Estado", "<span style='color:#E74C3C;'> Problema na thread</span>")
        else:
            html += tr("Estado", "<span style='color:#7f8c8d;'> Parado</span>")

        html += tr("Modo promíscuo", ("<span style='color:#E67E22;'> Desativado (Wi-Fi)</span>"
                                       if eh_wifi else
                                       "<span style='color:#2ECC71;'> Ativo</span>"))
        html += tr("Rate limit",      f"{_MAX_PACOTES_POR_SEGUNDO} pkt/s")
        html += tr("Admin",           " Sim" if is_admin else " Não")

        if self.em_captura:
            html += tr("Pacotes",     f"{total_pacotes:,}")
            html += tr("Dados",       f"{total_bytes / 1_048_576:.2f} MB")
            html += tr("Taxa atual",  f"{kb_atual:.1f} KB/s")
            html += tr("Thread captura",
                       ("<span style='color:#2ECC71;'> Ativa</span>"
                        if thread_cap_ok else
                        "<span style='color:#E74C3C;'> Inativa</span>"))
            html += tr("Thread análise",
                       ("<span style='color:#2ECC71;'> Ativa</span>"
                        if thread_anal_ok else
                        "<span style='color:#E74C3C;'> Inativa</span>"))
            html += tr("Fila global",
                       (f"<span style='color:{_cor_fila(fila_global_pct)};'>"
                        f"{fila_global_n:,} / 20.000 ({fila_global_pct}%)</span>"))
            html += tr("Fila análise",
                       (f"<span style='color:{_cor_fila(fila_entrada_pct)};'>"
                        f"{fila_entrada_n:,} / 20.000 ({fila_entrada_pct}%)</span>"))
            html += tr("Fila saída",
                       (f"<span style='color:{_cor_fila(fila_saida_pct)};'>"
                        f"{fila_saida_n:,} / 5.000 ({fila_saida_pct}%)</span>"))

        html += "</table>"

        # Descoberta ARP
        html += secao("Descoberta ARP", "#E67E22")
        html += "<table style='width:100%;'>"
        html += tr("Timer periódico",   f"{param.get('timer_ms', 30000) // 1000}s")
        html += tr("Batch / lote",      str(param.get('batch', '—')))
        html += tr("Pausa entre lotes", f"{int(param.get('sleep_lote', 0) * 1000)} ms")
        html += tr("Inter-pacote",      f"{int(param.get('inter', 0) * 1000)} ms")
        html += tr("ICMP",              ("<span style='color:#E67E22;'>Desativado (Wi-Fi)</span>"
                                          if param.get('desativar_icmp') else
                                          "<span style='color:#2ECC71;'>Ativo</span>"))
        html += tr("Limite de hosts",   str(param.get('limite_hosts', '—')))
        html += "</table>"

        # Recomendações
        recs = []
        if not is_admin:
            recs.append(("", "#E74C3C",
                         "Execute o NetLab como <b>Administrador</b> para capturar pacotes."))
        if not npcap_ok:
            recs.append(("", "#E74C3C",
                         "Instale o <b>Npcap</b> em npcap.com marcando "
                         "'WinPcap API-compatible mode'."))
        if self.em_captura and total_pacotes == 0:
            recs.append(("", "#E74C3C",
                         "Nenhum pacote capturado. Tente selecionar outra interface "
                         "ou execute <code>python diagnostico.py</code> para identificar a interface ativa."))
        if not cidr_ok and self.em_captura:
            recs.append(("", "#E67E22",
                         "CIDR não detectado. Dispositivos da rede podem aparecer como 'Internet'. "
                         "Reinicie a captura ou verifique com <code>ipconfig /all</code>."))
        if eh_wifi and self.em_captura:
            recs.append(("", "#E67E22",
                         "Para captura mais completa e estável, use <b>cabo Ethernet</b>. "
                         "Wi-Fi não captura tráfego de outros dispositivos no Windows."))
        if self.em_captura and fila_entrada_pct >= 80:
            recs.append(("", "#E67E22",
                         f"Fila de análise em {fila_entrada_pct}%. Reduza o tráfego "
                         "ou reinicie a sessão para evitar descarte de pacotes."))
        if not gateway_ip and self.em_captura:
            recs.append(("", "#3498DB",
                         "Gateway não detectado. Execute <code>arp -a</code> no terminal "
                         "para verificar a tabela ARP do sistema."))
        if self.em_captura and not thread_anal_ok:
            recs.append(("", "#E74C3C",
                         "Thread de análise inativa. Pare e reinicie a captura para restaurar "
                         "o processamento de eventos."))

        if recs:
            html += secao("Recomendações", "#F39C12")
            for icone, cor, texto in recs:
                html += rec_item(icone, cor, texto)

        # Wi-Fi — explicação da queda
        if eh_wifi:
            html += secao("Por que a internet pode cair em Wi-Fi?", "#566573")
            html += (
                "<div style='background:#0a0f1a;border:1px solid #1e2d40;"
                "border-radius:5px;padding:10px 14px;'>"
                "<ul style='color:#9fb2c8;font-size:10px;margin:0 0 0 14px;line-height:1.9;'>"
                "<li><b style='color:#ecf0f1;'>Modo promíscuo:</b> causa reset de ~2s no driver "
                "Intel. <span style='color:#2ECC71;'>Corrigido automaticamente</span> nesta versão.</li>"
                "<li><b style='color:#ecf0f1;'>ARP sweep:</b> lotes de 8 pacotes com pausa de "
                "250ms. Roteadores sensíveis podem acionar proteção anti-flood.</li>"
                "<li><b style='color:#ecf0f1;'>Injeção Npcap:</b> <code>srp()</code> injeta "
                "diretamente no adaptador, podendo interferir com o stack Wi-Fi.</li>"
                "</ul>"
                "<p style='color:#566573;font-size:9px;margin:8px 0 0 0;'>"
                " Solução definitiva: use cabo Ethernet para capturas longas."
                "</p></div>"
            )

        html += "</div>"

        # ── Dialog ───────────────────────────────────────────────────────────────

        dialogo = QDialog(self)
        dialogo.setWindowTitle("Diagnóstico de Captura")
        dialogo.setMinimumSize(560, 640)
        layout_d = QVBoxLayout(dialogo)
        layout_d.setSpacing(4)

        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setHtml(html)
        txt.setStyleSheet("QTextEdit { background:#0f1423; border:none; padding:8px; }")
        layout_d.addWidget(txt)

        row_btn = QHBoxLayout()
        btn_refresh = QPushButton(" Atualizar")
        btn_refresh.setToolTip("Roda o diagnóstico novamente com os dados atuais")
        btn_refresh.clicked.connect(
            lambda: (dialogo.accept(), self._exibir_diagnostico_captura())
        )
        row_btn.addWidget(btn_refresh)
        row_btn.addStretch()
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(dialogo.accept)
        row_btn.addWidget(btn_ok)
        layout_d.addLayout(row_btn)

        dialogo.exec()

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
            "<h2>NetLab Educacional V3.1</h2>"
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
        """
        Versão simplificada: usa QTimer.singleShot para redirecionar
        o callback para a UI thread de forma segura no PyQt6.
        """
        self._status(" Baixando base de fabricantes do Wireshark… (em segundo plano)")

        def ao_concluir(sucesso: bool, mensagem: str):
            # Agenda execução na UI thread via QTimer (thread-safe)
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
