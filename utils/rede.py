"""
Utilitarios de rede compartilhados pelo projeto NetLab.
Centraliza funcoes que estavam duplicadas em multiplos modulos.
"""

from __future__ import annotations

import socket

# Cache simples para classificacao de IP local.
_CACHE_LOCAL: dict[str, bool] = {}


def obter_ip_local() -> str:
    """
    Retorna o IP local da interface ativa.
    Usa socket UDP sem envio de dados reais.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_udp:
            socket_udp.connect(("8.8.8.8", 80))
            return socket_udp.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _calcular_eh_local(ip: str) -> bool:
    """Calcula se o IP pertence as faixas privadas RFC 1918."""
    try:
        partes = ip.split(".", 2)
        primeiro = int(partes[0])
        if primeiro == 10:
            return True
        if primeiro == 192:
            return len(partes) >= 2 and int(partes[1]) == 168
        if primeiro == 172:
            return len(partes) >= 2 and 16 <= int(partes[1]) <= 31
    except Exception:
        pass
    return False


def eh_ip_local(ip: str) -> bool:
    """
    Retorna se o IP eh local (RFC 1918), com cache interno.
    """
    resultado_cache = _CACHE_LOCAL.get(ip)
    if resultado_cache is not None:
        return resultado_cache

    resultado = _calcular_eh_local(ip)
    if len(_CACHE_LOCAL) < 8192:
        _CACHE_LOCAL[ip] = resultado
    return resultado


def eh_endereco_valido(ip: str) -> bool:
    """
    Filtra enderecos invalidos para visualizacao na topologia.
    Remove loopback, multicast, link-local, broadcast e 0.x.x.x.
    """
    if not ip:
        return False
    try:
        partes = [int(parte) for parte in ip.split(".")]
        if len(partes) != 4:
            return False
        primeiro, segundo, ultimo = partes[0], partes[1], partes[3]
        return not (
            primeiro in (0, 127)
            or (primeiro == 169 and segundo == 254)
            or 224 <= primeiro <= 239
            or ultimo == 255
            or ip == "255.255.255.255"
        )
    except Exception:
        return False


def formatar_bytes(bytes_totais: int) -> str:
    """Converte bytes para representacao legivel."""
    if bytes_totais >= 1_073_741_824:
        return f"{bytes_totais / 1_073_741_824:.2f} GB"
    if bytes_totais >= 1_048_576:
        return f"{bytes_totais / 1_048_576:.1f} MB"
    if bytes_totais >= 1_024:
        return f"{bytes_totais / 1_024:.1f} KB"
    return f"{bytes_totais} B"


def corrigir_mojibake(texto: str):
    """
    Tenta recuperar textos com encoding quebrado (cp1252/latin1 -> utf-8).
    """
    if not isinstance(texto, str):
        return texto
    for encoding in ("cp1252", "latin1"):
        try:
            return texto.encode(encoding, errors="ignore").decode("utf-8")
        except Exception:
            continue
    return texto

def converter_ip_mascara_para_cidr(ip: str, mascara: str) -> str | None:
    """Calcula o CIDR (ex: 192.168.1.0/24) a partir de IP e Máscara."""
    try:
        import ipaddress
        if not ip or not mascara or "." not in str(mascara):
            return None
        rede = ipaddress.ip_network(f"{ip}/{mascara}", strict=False)
        return str(rede)
    except Exception:
        return None


def detectar_cidr_robusto(ip_local: str) -> str | None:
    """
    Tenta detectar o CIDR de todas as formas possíveis no Windows.
    Retorna a string do CIDR (ex: '192.168.1.0/24') ou None.
    """
    if not ip_local or ip_local.startswith(("127.", "0.0.0.0")):
        return None

    import subprocess
    import re
    import ipaddress

    # ── 1. PowerShell (Get-NetIPAddress) ──
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-NetIPAddress -IPAddress '{ip_local}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).PrefixLength"],
            capture_output=True, text=True, timeout=5,
            creationflags=0x08000000 # CREATE_NO_WINDOW
        )
        out = proc.stdout.strip()
        if out.isdigit():
            prefix = int(out)
            return str(ipaddress.ip_network(f"{ip_local}/{prefix}", strict=False))
    except Exception:
        pass

    # ── 2. WMI (via PowerShell) ──
    try:
        cmd = f"(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {{$_.IPAddress -contains '{ip_local}'}}).IPSubnet[0]"
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=5,
            creationflags=0x08000000
        )
        out = proc.stdout.strip()
        if out and "." in out:
            return converter_ip_mascara_para_cidr(ip_local, out)
    except Exception:
        pass

    # ── 3. psutil (se instalado) ──
    try:
        import psutil
        import socket
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip_local:
                    if addr.netmask:
                        return converter_ip_mascara_para_cidr(ip_local, addr.netmask)
    except Exception:
        pass

    # ── 4. ipconfig /all (Parsing manual) ──
    try:
        proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=5, creationflags=0x08000000)
        out = proc.stdout
        idx = out.find(ip_local)
        if idx != -1:
            trecho = out[max(0, idx-500):idx+500]
            m = re.search(r"(?:M[aá]scara[^:]*|Subnet\s+Mask)[^:]*:\s*((?:\d+\.){3}\d+)", trecho, re.I)
            if m:
                return converter_ip_mascara_para_cidr(ip_local, m.group(1))
    except Exception:
        pass

    # ── 5. RFC 1918 (Último recurso útil para IPs privados) ──
    try:
        if ipaddress.ip_address(ip_local).is_private:
            prefixo = ".".join(ip_local.split(".")[:3])
            return f"{prefixo}.0/24"
    except Exception:
        pass

    return None
