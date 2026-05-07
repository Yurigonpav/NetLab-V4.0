# netlab_core.py
# ============================================================
# NÚCLEO DE MÉTRICAS — NetLab Educacional
# ============================================================

import threading
import time
from typing import Tuple, List

# ─── Implementação Python pura ───────────────────────────────────────────────

_MAX_PROTO = 16
_CBUF_CAP  = 8_192  # potência de 2

class _FallbackCore:
    """
    Implementação Python pura com buffer circular de tamanho fixo.
    """
    __slots__ = (
        "_buf", "_head", "_count",
        "_total_bytes", "_total_pacotes",
        "_cont", "_bytes_proto",
        "_ts_inicio", "_lock",
    )

    def __init__(self):
        self._buf           = [(0, 0, 0)] * _CBUF_CAP
        self._head          = 0
        self._count         = 0
        self._total_bytes   = 0
        self._total_pacotes = 0
        self._cont          = [0] * _MAX_PROTO
        self._bytes_proto   = [0] * _MAX_PROTO
        self._ts_inicio     = time.monotonic()
        self._lock          = threading.Lock()

    def resetar(self):
        with self._lock:
            self._buf           = [(0, 0, 0)] * _CBUF_CAP
            self._head          = 0
            self._count         = 0
            self._total_bytes   = 0
            self._total_pacotes = 0
            self._cont          = [0] * _MAX_PROTO
            self._bytes_proto   = [0] * _MAX_PROTO
            self._ts_inicio     = time.monotonic()

    def adicionar_pacote(self, proto_idx: int, tamanho: int):
        if proto_idx >= _MAX_PROTO:
            proto_idx = 9
        agora_ms  = int((time.monotonic() - self._ts_inicio) * 1000)
        with self._lock:
            self._buf[self._head] = (tamanho, proto_idx, agora_ms)
            self._head  = (self._head + 1) & (_CBUF_CAP - 1)
            if self._count < _CBUF_CAP:
                self._count += 1
            self._total_bytes          += tamanho
            self._total_pacotes        += 1
            self._cont[proto_idx]      += 1
            self._bytes_proto[proto_idx] += tamanho

    def bytes_por_segundo(self, janela_ms: int = 1000) -> float:
        if janela_ms <= 0:
            return 0.0
        agora_rel = int((time.monotonic() - self._ts_inicio) * 1000)
        corte     = max(0, agora_rel - janela_ms)
        with self._lock:
            count    = self._count
            head     = self._head
            mais_antigo = 0 if count < _CBUF_CAP else head
            soma = sum(
                self._buf[(mais_antigo + i) & (_CBUF_CAP - 1)][0]
                for i in range(count)
                if self._buf[(mais_antigo + i) & (_CBUF_CAP - 1)][2] >= corte
            )
        return soma / (janela_ms / 1000.0)

    def obter_estatisticas(self) -> Tuple[List[int], List[int]]:
        with self._lock:
            return list(self._cont), list(self._bytes_proto)

    def total_pacotes(self) -> int:
        return self._total_pacotes

    def total_bytes(self) -> int:
        return self._total_bytes


# ─── Classe pública ─────────────────────────────────────────────────────────

class NetlabCore:
    """
    Interface unificada para o núcleo de métricas.
    """

    PROTO_TCP     = 0
    PROTO_UDP     = 1
    PROTO_DNS     = 2
    PROTO_HTTP    = 3
    PROTO_HTTPS   = 4
    PROTO_ARP     = 5
    PROTO_ICMP    = 6
    PROTO_DHCP    = 7
    PROTO_TCP_SYN = 8
    PROTO_OUTRO   = 9
    PROTO_SSH     = 10
    PROTO_FTP     = 11
    PROTO_SMB     = 12
    PROTO_RDP     = 13

    _NOMES = {
        0: "TCP", 1: "UDP", 2: "DNS", 3: "HTTP", 4: "HTTPS",
        5: "ARP", 6: "ICMP", 7: "DHCP", 8: "TCP_SYN", 9: "Outro",
        10: "SSH", 11: "FTP", 12: "SMB", 13: "RDP",
    }

    def __init__(self):
        self._fallback = _FallbackCore()

    @property
    def usando_nativo(self) -> bool:
        return False

    def resetar(self):
        self._fallback.resetar()

    def adicionar_pacote(self, proto_idx: int, tamanho: int):
        self._fallback.adicionar_pacote(proto_idx, tamanho)

    def bytes_por_segundo(self, janela_ms: int = 1_000) -> float:
        return self._fallback.bytes_por_segundo(janela_ms)

    def obter_estatisticas(self) -> Tuple[List[int], List[int]]:
        return self._fallback.obter_estatisticas()

    def total_pacotes(self) -> int:
        return self._fallback.total_pacotes()

    def total_bytes(self) -> int:
        return self._fallback.total_bytes()

    def estatisticas_protocolos(self) -> List[dict]:
        cont, byt = self.obter_estatisticas()
        resultado = []
        for idx, nome in self._NOMES.items():
            if cont[idx] > 0:
                resultado.append({
                    "protocolo": nome,
                    "pacotes":   cont[idx],
                    "bytes":     byt[idx],
                })
        resultado.sort(key=lambda x: x["pacotes"], reverse=True)
        return resultado
