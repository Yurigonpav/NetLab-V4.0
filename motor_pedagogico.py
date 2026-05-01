# motor_pedagogico.py
# Motor pedagógico do NetLab Educacional.
#
# FILOSOFIA DE ALERTAS:
#   INFO    — atividade normal de rede; conteúdo educativo sobre o protocolo.
#   AVISO   — protocolo intrinsecamente inseguro em uso (FTP, RDP, SMB) OU
#             indício concreto que merece atenção (cookie via HTTP, método
#             HTTP incomum).
#   CRITICO — evidência real de dado sensível exposto (credenciais, tokens,
#             CPF, etc.) ou padrão de ataque detectado no payload.
#
# REGRA GERAL:
#   Só emitir alerta_seguranca quando há evidência concreta no pacote.
#   ARP, DNS, ICMP, DHCP, HTTPS e TCP_SYN normais → sem alerta.

import urllib.parse
import re
from datetime import datetime
from utils.rede import corrigir_mojibake

# ── Campos sensíveis ─────────────────────────────────────────────────────────
CAMPOS_SENSIVEIS = {
    "senha", "password", "pass", "pwd", "passwd", "secret", "passphrase",
    "pin", "otp", "totp", "mfa_code", "auth_code", "verification_code",
    "token", "access_token", "refresh_token", "id_token", "bearer",
    "api_key", "apikey", "api_secret", "client_secret", "app_secret",
    "auth", "auth_token", "session_token", "session_key", "sessionid",
    "cookie", "csrf_token", "csrfmiddlewaretoken", "xsrf_token",
    "private_key", "secret_key", "signing_key", "encryption_key",
    "credential", "credentials",
    "user", "usuario", "username", "login", "account", "uid", "user_id",
    "cpf", "cnpj", "rg", "ssn", "sin", "nif", "passport_number",
    "birth_date", "data_nascimento", "dob",
    "email", "e_mail", "telefone", "phone", "celular", "mobile",
    "credit_card", "card_number", "cardnumber", "pan",
    "cvv", "cvc", "cvv2", "cvc2",
    "expiry", "expiry_date", "expiration",
    "iban", "bic", "pix", "chave_pix",
}

# ── OUI → fabricante ─────────────────────────────────────────────────────────
OUI_VENDORS = {
    "001B63": "Apple",      "A8BE27": "Apple",      "F0DBE2": "Apple",
    "3C0754": "Apple",      "BC926B": "Apple",      "D8BB2C": "Apple",
    "001422": "Dell",       "B083FE": "Dell",       "848F69": "Dell",
    "001A2B": "Intel",      "A0369F": "Intel",      "4CEB42": "Intel",
    "001D09": "Samsung",    "38ECE4": "Samsung",    "ACC327": "Samsung",
    "001A6B": "Lenovo",     "40742B": "Lenovo",     "54EEF7": "Lenovo",
    "001E0B": "HP",         "3C4A92": "HP",         "B05ADA": "HP",
    "00155D": "Microsoft",  "606BFF": "Microsoft",
    "F88FCA": "Google",     "54607E": "Google",     "ACE415": "Google Nest",
    "44650D": "Amazon Echo","0C5765": "Amazon Fire","74C246": "Amazon",
    "000569": "Cisco",      "001C42": "Cisco",      "70B3D5": "Cisco Meraki",
    "94D9B3": "TP-Link",    "F4F26D": "TP-Link",    "C025E9": "TP-Link",
    "001E10": "Huawei",     "287B09": "Huawei",     "B4CD27": "Huawei",
    "002722": "Ubiquiti",   "246895": "Ubiquiti",   "E063DA": "Ubiquiti",
    "4C5E0C": "MikroTik",   "2CC8F3": "MikroTik",
    "0014BF": "Netgear",    "20E52A": "Netgear",    "C03F0E": "Netgear",
    "001CF0": "D-Link",     "34A84E": "D-Link",
    "94652D": "Intelbras",  "7834E2": "Intelbras",
    "B827EB": "Raspberry Pi","DCA632": "Raspberry Pi",
    "BCDDC2": "Espressif",  "30AEA4": "Espressif",  "E868E7": "Espressif",
    "000C29": "VMware",     "005056": "VMware vSphere",
    "080027": "VirtualBox", "525400": "QEMU/KVM",
    "0242AC": "Docker Bridge",
}

_RE_MAC_SEP   = re.compile(r'[:\.\-\s]')
_RE_CAMPO     = re.compile(
    r'\b(' + '|'.join(re.escape(c) for c in
                      sorted(CAMPOS_SENSIVEIS, key=len, reverse=True)) + r')\b',
    re.IGNORECASE,
)
_RE_SQLI = re.compile(
    r"(\bunion\b.{0,20}\bselect\b|'\s*or\s+'?1'?\s*=\s*'?1|"
    r"'\s*--|\bsleep\s*\(|\bbenchmark\s*\(|xp_cmdshell|load_file\s*\()",
    re.IGNORECASE,
)
_RE_XSS = re.compile(
    r"(<\s*script|javascript\s*:|on\w+\s*=|<\s*iframe|document\.cookie"
    r"|eval\s*\(|alert\s*\()",
    re.IGNORECASE,
)


def _fabricante(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    oui = _RE_MAC_SEP.sub("", mac).upper()[:6]
    if not all(c in "0123456789ABCDEF" for c in oui):
        return ""
    return OUI_VENDORS.get(oui, "")


def _estimar_os(ttl) -> str:
    if ttl is None:
        return ""
    try:
        t = int(ttl)
        if t >= 120:
            return "Windows (TTL padrão 128)"
        if t >= 55:
            return "Linux / macOS (TTL padrão 64)"
        return "Dispositivo embarcado (TTL padrão 32)"
    except Exception:
        return ""


def _escape(texto: str) -> str:
    return (texto or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _hexdump(texto: str, limite: int = 1024) -> str:
    dados = (texto or "").encode("latin-1", "replace")[:limite]
    linhas = []
    for i in range(0, len(dados), 16):
        chunk = dados[i:i + 16]
        hexes = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        linhas.append(f"{i:04x}  {hexes}  {ascii_}")
    return "\n".join(linhas)


def _tabela(campos: list) -> str:
    linhas = "".join(
        f"<tr>"
        f"<td style='padding:3px 14px 3px 0;color:#7f8c8d;white-space:nowrap;"
        f"font-size:10px;'>{nome}</td>"
        f"<td style='padding:3px 0;color:#ecf0f1;font-family:Consolas;"
        f"font-size:10px;'>{valor}</td>"
        f"</tr>"
        for nome, valor in campos
        if valor not in (None, "", "None", "—")
    )
    if not linhas:
        return "<i style='color:#7f8c8d;'>Campos não disponíveis.</i>"
    return f"<table style='border-collapse:collapse;width:100%;'>{linhas}</table>"


def _bloco(conteudo: str, cor: str = "#1e2d40") -> str:
    if not conteudo or not conteudo.strip():
        return ""
    return (
        f"<div style='background:#080d1a;border:1px solid {cor};"
        f"border-radius:5px;padding:10px 14px;margin:4px 0 10px 0;"
        f"font-size:11px;line-height:1.7;color:#ecf0f1;'>{conteudo}</div>"
    )


def _cabecalho_secao(titulo: str, subtitulo: str, cor: str, icone: str = "•") -> str:
    return (
        f"<div style='margin:14px 0 6px 0;border-left:3px solid {cor};"
        f"padding:4px 10px;background:rgba(0,0,0,0.18);border-radius:0 4px 4px 0;'>"
        f"<span style='color:{cor};font-weight:bold;font-size:11px;'>{icone} {titulo}</span>"
        f"<span style='color:#566573;font-size:9px;margin-left:8px;'>{subtitulo}</span>"
        f"</div>"
    )


# ─────────────────────────────────────────────────────────────────────────────

class MotorPedagogico:
    """
    Gera explicações didáticas baseadas nos dados reais de cada pacote.

    Níveis de severidade:
      INFO    — atividade normal; conteúdo educativo.
      AVISO   — protocolo inseguro em uso ou indício concreto de atenção.
      CRITICO — dado sensível exposto ou padrão de ataque confirmado.
    """

    def __init__(self):
        self._contadores: dict = {}
        self._alertas_educacionais: list = []

    # ── Interface pública ────────────────────────────────────────────────────

    def gerar_explicacao(self, evento: dict) -> dict:
        tipo = evento.get("tipo", "")
        self._contadores[tipo] = self._contadores.get(tipo, 0) + 1

        geradores = {
            "DNS":              self._dns,
            "HTTP":             self._http,
            "HTTPS":            self._https,
            "TCP_SYN":          self._tcp_syn,
            "TCP_FIN":          self._tcp_fin,
            "TCP_RST":          self._tcp_rst,
            "ICMP":             self._icmp,
            "ARP":              self._arp,
            "DHCP":             self._dhcp,
            "SSH":              self._ssh,
            "FTP":              self._ftp,
            "SMB":              self._smb,
            "RDP":              self._rdp,
            "NOVO_DISPOSITIVO": self._novo_dispositivo,
            "HTTP_CREDENTIALS": self._http_credenciais,
            "HTTP_REQUEST":     self._http_request,
        }
        resultado = geradores.get(tipo, self._generico)(evento)

        try:
            self._registrar_alerta_http(evento, resultado)
        except Exception:
            pass

        return resultado

    # ── Base ─────────────────────────────────────────────────────────────────

    def _base(self, evento: dict, icone: str, titulo: str, nivel: str,
              n1: str, n2: str, n3: str, n4: str = "",
              fluxo: str = "", alerta: str = "") -> dict:
        tipo = evento.get("tipo", "")
        resultado = {
            "timestamp":        datetime.now().strftime("%H:%M:%S"),
            "tipo":             tipo,
            "icone":            icone,
            "titulo":           titulo,
            "nivel":            nivel,
            "fluxo_visual":     fluxo,
            "nivel1":           n1,
            "nivel2":           n2,
            "nivel3":           n3,
            "nivel4":           n4,
            "alerta_seguranca": alerta,
            "payload_visivel":  "",
            "ip_envolvido":     evento.get("ip_origem", ""),
            "ip_destino":       evento.get("ip_destino", ""),
            "contador":         self._contadores.get(tipo, 1),
        }
        for k, v in list(resultado.items()):
            if isinstance(v, str):
                resultado[k] = corrigir_mojibake(v)
        return resultado

    @staticmethod
    def _fluxo(origem: str, protocolo: str, destino: str) -> str:
        return f"{origem}  --[{protocolo}]-->  {destino}"

    # ── Registro de alertas HTTP para Insights ───────────────────────────────

    _KW_SENSIVEIS = (
        b"password", b"passwd", b"senha", b"token", b"auth",
        b"cpf", b"credential", b"secret", b"api_key",
    )

    def _registrar_alerta_http(self, evento: dict, resultado: dict):
        if evento.get("tipo") != "HTTP":
            return
        alerta = resultado.get("alerta_seguranca", "")
        if not alerta:
            return
        if len(self._alertas_educacionais) >= 200:
            self._alertas_educacionais.pop(0)
        ts  = resultado.get("timestamp", "")
        ipo = evento.get("ip_origem", "?")
        ipd = evento.get("ip_destino", "?")
        self._alertas_educacionais.append({
            "timestamp":  ts,
            "ip_origem":  ipo,
            "ip_destino": ipd,
            "mensagem":   f"[HTTP] {ts} · {ipo} → {ipd} | {alerta}",
            "nivel":      resultado.get("nivel", "INFO"),
        })

    def obter_alertas_educacionais(self, ultimo_n: int = 20) -> list:
        return list(self._alertas_educacionais[-ultimo_n:])

    def resetar_alertas_educacionais(self):
        self._alertas_educacionais.clear()

    # ────────────────────────────────────────────────────────────────────────
    # DNS
    # ────────────────────────────────────────────────────────────────────────

    def _dns(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        dominio = e.get("dominio", "")
        porta   = e.get("porta_destino") or 53
        tamanho = e.get("tamanho", 0)
        titulo  = f"Consulta DNS — {dominio}" if dominio else "Consulta DNS"
        fluxo   = self._fluxo(origem, "DNS/UDP 53", destino)

        n1 = (
            f"O dispositivo <b>{origem}</b> está perguntando ao servidor DNS "
            f"<b>{destino}</b> qual é o endereço IP de "
            f"<b style='color:#3498DB;'>{dominio or 'um domínio'}</b>.<br><br>"
            f"Esse processo se chama <b>resolução de nomes</b> e acontece antes "
            f"de qualquer conexão com um site. Funciona como uma lista telefônica: "
            f"você sabe o nome, o DNS te dá o número (IP)."
        )

        n2 = (
            f"<b>Protocolo:</b> DNS sobre UDP porta {porta} — pacote de {tamanho} bytes.<br>"
            f"<b>Servidor consultado:</b> <code>{destino}</code><br>"
            f"<b>Domínio:</b> <code style='color:#3498DB;'>{dominio or '—'}</code><br><br>"
            f"<b>Como funciona o DNS:</b> a consulta sai em texto puro (UDP). "
            f"Qualquer dispositivo na mesma rede pode ver quais domínios você acessa. "
            f"Alternativas que cifram a consulta: "
            f"<b>DNS over HTTPS (DoH)</b> — porta 443 — e "
            f"<b>DNS over TLS (DoT)</b> — porta 853. "
            f"O DNS tradicional também é vulnerável a <b>cache poisoning</b> sem DNSSEC."
        )

        campos = [
            ("IP Origem",    origem),
            ("Servidor DNS", destino),
            ("Domínio",      dominio or "—"),
            ("Porta",        f"UDP/{porta}"),
            ("Tamanho",      f"{tamanho} bytes"),
            ("Cifrado",      "Não (DNS padrão)"),
        ]
        n3 = _tabela(campos)
        n4 = ""

        return self._base(e, "🔍", titulo, "INFO", n1, n2, n3, n4, fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # HTTP — análise completa com DPI
    # ────────────────────────────────────────────────────────────────────────

    def _http(self, e: dict) -> dict:
        origem       = e.get("ip_origem",  "?")
        destino      = e.get("ip_destino", "?")
        porta        = e.get("porta_destino") or 80
        porta_orig   = e.get("porta_origem", "")
        tamanho      = e.get("tamanho", 0)
        ttl          = e.get("ttl")
        metodo       = (e.get("http_metodo") or e.get("metodo", "") or "GET").upper()
        caminho      = e.get("http_caminho") or e.get("recurso", "") or "/"
        versao       = e.get("http_versao", "") or "HTTP/1.1"
        host         = e.get("http_host", "")
        headers      = e.get("http_headers", {}) or {}
        corpo        = e.get("http_corpo", "") or e.get("corpo", "") or e.get("payload_resumo", "") or ""
        if isinstance(corpo, bytes):
            corpo = corpo.decode("utf-8", errors="ignore")
        cookie       = e.get("http_cookie", "") or headers.get("Cookie", "")
        content_type = e.get("http_content_type", "") or headers.get("Content-Type", "") or ""
        payload_raw  = e.get("payload_resumo") or e.get("payload_bruto", "") or ""

        # Reconstrói corpo a partir de credenciais brutas se necessário
        creds_raw = e.get("credenciais", [])
        if creds_raw and not corpo:
            corpo = "&".join(f"{k}={v}" for k, v in creds_raw)
            content_type = content_type or "application/x-www-form-urlencoded"

        alvo  = host or destino
        fluxo = self._fluxo(origem, "HTTP", f"{alvo}:{porta}")

        # ── Parse de campos do formulário ────────────────────────────────────
        campos_form: dict = {}
        if corpo:
            try:
                if "urlencoded" in content_type.lower() or re.search(r'\w+=', corpo):
                    campos_form = {
                        k: v[0] if v else ""
                        for k, v in urllib.parse.parse_qs(
                            corpo, keep_blank_values=True
                        ).items()
                    }
            except Exception:
                pass

        sensiveis = [k for k in campos_form if _RE_CAMPO.search(re.sub(r'[_\-]', ' ', k))]
        tem_sensiveis   = bool(sensiveis)
        tem_form        = bool(campos_form) and not tem_sensiveis
        tem_cookie_http = bool(cookie)
        injecao_sql     = bool(_RE_SQLI.search(caminho) or _RE_SQLI.search(corpo))
        injecao_xss     = bool(_RE_XSS.search(caminho) or _RE_XSS.search(corpo))
        metodo_incomum  = metodo in ("TRACE", "OPTIONS", "PUT", "DELETE", "CONNECT")

        # ── Determinação de nível e alerta ────────────────────────────────────
        if tem_sensiveis or injecao_sql or injecao_xss:
            nivel = "CRITICO"
            if injecao_sql:
                alerta = f"Padrão de SQL Injection detectado na requisição para {alvo}."
            elif injecao_xss:
                alerta = f"Padrão de XSS detectado na requisição para {alvo}."
            else:
                alerta = (
                    f"Campos sensíveis enviados em texto puro: "
                    f"{', '.join(sensiveis[:4])}."
                )
        elif tem_cookie_http:
            nivel  = "AVISO"
            alerta = f"Cookie de sessão trafegando sem criptografia para {alvo}."
        elif tem_form or metodo_incomum:
            nivel  = "AVISO"
            alerta = (
                f"Dados de formulário enviados sem criptografia via HTTP para {alvo}."
                if tem_form else
                f"Método HTTP {metodo} — use apenas quando necessário e com autenticação."
            )
        else:
            nivel  = "INFO"
            alerta = ""

        titulo = f"HTTP — {metodo} {alvo}"

        # ── Nível 1: Análise ─────────────────────────────────────────────────
        if tem_sensiveis:
            exemplos = " · ".join(
                f"{k} = <b style='color:#E74C3C;'>{_escape(str(campos_form[k]))}</b>"
                for k in sensiveis[:3]
            )
            bloco_exp = (
                f"<br><br>Campos sensíveis transmitidos em texto puro:<br>"
                f"<div style='background:#1a0000;border-left:4px solid #E74C3C;"
                f"padding:8px 12px;margin:8px 0;border-radius:4px;"
                f"font-family:Consolas;font-size:11px;'>{exemplos}</div>"
                f"<b style='color:#E74C3C;'>Qualquer capturador na mesma rede "
                f"viu esses dados em tempo real.</b>"
            )
        elif injecao_sql:
            bloco_exp = (
                f"<br><br><div style='background:#2a0a00;border-left:4px solid #E74C3C;"
                f"padding:8px;border-radius:4px;'>"
                f"<b style='color:#E74C3C;'>Padrão de SQL Injection detectado</b> "
                f"na URL ou corpo da requisição.</div>"
            )
        elif injecao_xss:
            bloco_exp = (
                f"<br><br><div style='background:#2a0a00;border-left:4px solid #E74C3C;"
                f"padding:8px;border-radius:4px;'>"
                f"<b style='color:#E74C3C;'>Padrão de XSS detectado</b> "
                f"na requisição.</div>"
            )
        elif tem_cookie_http:
            bloco_exp = (
                f"<br><br><div style='background:#2a1500;border-left:4px solid #E67E22;"
                f"padding:8px;border-radius:4px;'>"
                f"<b style='color:#E67E22;'>Cookie de sessão detectado em HTTP.</b> "
                f"Permite Session Hijacking sem precisar da senha.</div>"
            )
        elif tem_form:
            bloco_exp = (
                f"<br><br>Dados de formulário trafegando sem criptografia: "
                f"{', '.join(list(campos_form.keys())[:5])}."
            )
        else:
            bloco_exp = ""

        n1 = (
            f"O dispositivo <b>{origem}</b> fez uma requisição "
            f"<b>{metodo}</b> para <b style='color:#E74C3C;'>{alvo}</b> "
            f"usando <b style='color:#E74C3C;'>HTTP sem criptografia</b>.<br><br>"
            f"HTTP transmite tudo em texto puro — URL, cabeçalhos e corpo "
            f"são visíveis para qualquer dispositivo na mesma rede."
            + bloco_exp
        )

        # ── Nível 2: Leitura técnica ─────────────────────────────────────────
        ua = headers.get("User-Agent", "")[:70]
        cl = headers.get("Content-Length", "")

        aviso_headers = ""
        checks = [
            ("Strict-Transport-Security", "HSTS ausente"),
            ("Content-Security-Policy",   "CSP ausente — risco de XSS"),
            ("X-Frame-Options",           "X-Frame-Options ausente — clickjacking"),
            ("X-Content-Type-Options",    "X-Content-Type-Options ausente"),
        ]
        faltando = [msg for hdr, msg in checks if hdr not in headers]
        if faltando and headers:
            aviso_headers = (
                f"<br><div style='background:#1a2430;border:1px solid #3498DB;"
                f"border-radius:4px;padding:8px;margin-top:6px;'>"
                f"<b style='color:#3498DB;'>Headers de segurança ausentes:</b><br>"
                + "<br>".join(f"• {h}" for h in faltando)
                + "</div>"
            )

        n2 = (
            f"<b>Requisição:</b> <code style='color:#3498DB;'>"
            f"{metodo} {_escape(caminho)} {versao}</code><br>"
            f"<b>Destino:</b> {alvo}:{porta}<br>"
            f"<b>Tamanho:</b> {tamanho} bytes"
            + (f"<br><b>Content-Length:</b> {cl}" if cl else "")
            + (f"<br><b>User-Agent:</b> {_escape(ua)}" if ua else "")
            + (f"<br><b>TTL:</b> {ttl} → {_estimar_os(ttl)}" if ttl else "")
            + aviso_headers
            + f"<br><br><b>Com HTTPS</b> toda esta requisição seria cifrada — "
            f"URL, headers e corpo ficariam ilegíveis para capturadores."
        )

        # ── Nível 3: Evidência ───────────────────────────────────────────────
        meta = [
            ("IP Origem",     origem),
            ("IP Destino",    destino),
            ("Porta origem",  str(porta_orig) if porta_orig else "—"),
            ("Porta destino", str(porta)),
            ("Versão HTTP",   versao),
            ("Tamanho",       f"{tamanho} bytes"),
            ("TTL",           f"{ttl} — {_estimar_os(ttl)}" if ttl else "—"),
            ("Cifrado",       "Não — texto puro"),
        ]
        n3 = (
            "<b style='color:#3498DB;font-size:11px;'>Metadados do pacote</b><br>"
            + _tabela(meta)
        )

        if headers:
            linhas_h = "".join(
                f"<tr><td style='padding:3px 12px 3px 0;color:#7f8c8d;"
                f"font-size:10px;white-space:nowrap;'>{_escape(k)}</td>"
                f"<td style='padding:3px 0;color:#ecf0f1;font-family:Consolas;"
                f"font-size:10px;word-break:break-all;'>{_escape(str(v))}</td></tr>"
                for k, v in headers.items()
            )
            n3 += (
                f"<br><b style='color:#3498DB;font-size:11px;'>Headers HTTP</b>"
                f"<div style='background:#0a0f1a;border:1px solid #1e2d40;"
                f"border-radius:4px;padding:8px;margin-top:4px;'>"
                f"<table style='border-collapse:collapse;width:100%;'>"
                f"{linhas_h}</table></div>"
            )

        if campos_form:
            linhas_f = []
            for campo, valor in campos_form.items():
                eh_s  = bool(_RE_CAMPO.search(re.sub(r'[_\-]', ' ', campo)))
                cor_c = "#E74C3C" if eh_s else "#3498DB"
                cor_v = "#E74C3C" if eh_s else "#2ECC71"
                badge = (
                    " <span style='background:#5a0000;color:#ff6b6b;"
                    "font-size:9px;padding:1px 5px;border-radius:3px;"
                    "font-weight:bold;'>SENSÍVEL</span>"
                ) if eh_s else ""
                linhas_f.append(
                    f"<tr><td style='padding:5px 14px 5px 4px;font-size:11px;'>"
                    f"<span style='color:{cor_c};font-family:Consolas;'>{_escape(campo)}</span>"
                    f"{badge}</td>"
                    f"<td style='padding:5px 0;font-family:Consolas;font-size:12px;"
                    f"font-weight:bold;color:{cor_v};'>{_escape(str(valor))}</td></tr>"
                )
            n3 += (
                f"<br><b style='color:#E74C3C;font-size:11px;'>Campos do formulário</b>"
                f"<div style='background:#1a0a00;border:1px solid #E74C3C;"
                f"border-radius:6px;padding:10px;margin-top:4px;'>"
                f"<table style='border-collapse:collapse;width:100%;'>"
                + "".join(linhas_f) +
                f"</table></div>"
            )

        # ── Nível 4: Pacote bruto ────────────────────────────────────────────
        if payload_raw:
            hexdump = _hexdump(payload_raw)
            n4 = (
                f"<div style='font-family:Consolas;font-size:10px;'>"
                f"<div style='background:#0a0505;border:1px solid #E74C3C;"
                f"border-radius:6px;padding:12px;margin-bottom:8px;'>"
                f"<b style='color:#E74C3C;'>Requisição (texto puro)</b><br><br>"
                f"<span style='color:#2ECC71;'>{_escape(metodo)}</span> "
                f"<span style='color:#ecf0f1;'>{_escape(caminho)}</span> "
                f"<span style='color:#7f8c8d;'>{_escape(versao)}</span><br>"
                + "".join(
                    f"<span style='color:#9b59b6;'>{_escape(k)}</span>: "
                    f"<span style='color:#ecf0f1;'>{_escape(str(v))}</span><br>"
                    for k, v in headers.items()
                )
                + (f"<br><pre style='color:#ecf0f1;white-space:pre-wrap;margin:6px 0 0 0;"
                   f"font-size:10px;'>{_escape(corpo[:600])}</pre>" if corpo else "")
                + f"</div>"
                f"<div style='background:#000;border:1px solid #1e2d40;"
                f"border-radius:6px;padding:12px;'>"
                f"<b style='color:#2ECC71;'>Hexdump (primeiros 1024 bytes)</b><br><br>"
                f"<pre style='color:#ecf0f1;white-space:pre;font-size:10px;margin:0;'>"
                f"{_escape(hexdump)}</pre></div></div>"
            )
        else:
            n4 = "<i style='color:#7f8c8d;'>Payload bruto não disponível para este pacote.</i>"

        return self._base(e, "🌐", titulo, nivel, n1, n2, n3, n4, fluxo, alerta)

    # ────────────────────────────────────────────────────────────────────────
    # HTTPS
    # ────────────────────────────────────────────────────────────────────────

    def _https(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        sni     = e.get("tls_sni", "")
        porta   = e.get("porta_destino") or 443
        tamanho = e.get("tamanho", 0)
        flags   = e.get("flags_tcp", "")
        alvo    = sni or destino
        titulo  = f"HTTPS — {alvo}"
        fluxo   = self._fluxo(origem, "HTTPS/TLS", f"{alvo}:{porta}")

        fase = ""
        if flags and "S" in flags and "A" not in flags:
            fase = "Início do handshake TCP (SYN)"
        elif sni:
            fase = "TLS ClientHello — SNI extraído"

        n1 = (
            f"O dispositivo <b>{origem}</b> acessa "
            f"<b style='color:#2ECC71;'>{alvo}</b> com <b>HTTPS</b>.<br><br>"
            f"O TLS cifra todo o conteúdo — headers, corpo, cookies e credenciais "
            f"ficam <b>ilegíveis para qualquer capturador</b> na rede. "
            f"O sniffer só enxerga IPs, porta e o SNI (nome do host no certificado)."
        )

        n2 = (
            f"<b>Destino:</b> {alvo}:{porta}<br>"
            + (f"<b>Fase:</b> {fase}<br>" if fase else "")
            + (f"<b>SNI:</b> <code style='color:#2ECC71;'>{sni}</code><br>" if sni else "")
            + f"<b>Tamanho do pacote:</b> {tamanho} bytes<br><br>"
            f"<b>Como o TLS protege:</b> durante o handshake, cliente e servidor "
            f"negociam uma chave de sessão efêmera (ECDHE). Com <b>Perfect Forward "
            f"Secrecy</b>, mesmo que a chave privada do servidor vaze no futuro, "
            f"sessões passadas permanecem protegidas.<br><br>"
            f"<b>O que ainda é visível:</b> endereço IP do servidor, porta (443) "
            f"e o SNI no ClientHello. Para ocultar também o SNI, use "
            f"<b>Encrypted Client Hello (ECH)</b> — suportado em HTTP/3."
        )

        campos = [
            ("IP Origem",    origem),
            ("SNI (host)",   sni or "não extraído neste pacote"),
            ("IP Destino",   destino),
            ("Porta",        str(porta)),
            ("Flags TCP",    flags or "—"),
            ("Tamanho",      f"{tamanho} bytes"),
            ("Cifrado",      "Sim — TLS"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "🔒", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # ARP — sem alerta para tráfego normal
    # ────────────────────────────────────────────────────────────────────────

    def _arp(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        mac_src = e.get("mac_origem", "")
        op      = e.get("arp_op", "request")
        titulo  = f"ARP {'Request' if op == 'request' else 'Reply'} — {origem}"
        fluxo   = self._fluxo(origem, "ARP broadcast", "FF:FF:FF:FF:FF:FF")
        fab     = _fabricante(mac_src)

        if op == "request":
            n1 = (
                f"<b>{origem}</b> enviou um broadcast ARP perguntando: "
                f"<i>'Quem tem o IP <b>{destino}</b>? Me informe seu MAC.'</i><br><br>"
                f"Isso é comportamento normal — ocorre toda vez que um dispositivo "
                f"precisa se comunicar com outro na mesma rede local e ainda não "
                f"conhece seu endereço físico."
            )
        else:
            n1 = (
                f"<b>{origem}</b> respondeu ao ARP: "
                f"<i>'O IP <b>{destino}</b> está em {mac_src}.'</i><br><br>"
                f"Isso é normal quando o dispositivo recebeu um ARP Request "
                f"direcionado ao seu IP."
            )

        n2 = (
            f"<b>Como o ARP funciona:</b> ao iniciar uma comunicação, "
            f"o dispositivo verifica sua tabela ARP local (<code>arp -a</code>). "
            f"Se o IP não estiver mapeado, envia um broadcast para toda a rede.<br><br>"
            f"<b>MAC de origem:</b> <code>{mac_src}</code>"
            + (f" — <b>{fab}</b>" if fab else "")
            + f"<br><b>IP buscado:</b> {destino}<br><br>"
            f"<b>Contexto de segurança:</b> o ARP não possui autenticação. "
            f"Um atacante pode enviar respostas ARP falsas (<i>ARP spoofing</i>) "
            f"para redirecionar tráfego. Em redes domésticas isso raramente ocorre; "
            f"em redes corporativas, switches gerenciados com <b>Dynamic ARP "
            f"Inspection (DAI)</b> previnem esse ataque."
        )

        campos = [
            ("IP Origem",    origem),
            ("MAC Origem",   f"{mac_src}" + (f" ({fab})" if fab else "")),
            ("IP Destino",   destino),
            ("Operação",     "Request (quem tem este IP?)" if op == "request"
                             else "Reply (este IP é meu)"),
            ("Broadcast",    "FF:FF:FF:FF:FF:FF" if op == "request" else "—"),
        ]
        n3 = _tabela(campos)

        # Sem alerta para ARP normal
        return self._base(e, "📡", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # TCP SYN
    # ────────────────────────────────────────────────────────────────────────

    def _tcp_syn(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino", "?")
        ttl     = e.get("ttl")
        tamanho = e.get("tamanho", 0)
        os_info = _estimar_os(ttl)
        titulo  = f"Conexão TCP → {destino}:{porta}"
        fluxo   = self._fluxo(origem, "TCP SYN", f"{destino}:{porta}")

        servico = {
            80:   "HTTP (web)",
            443:  "HTTPS (web seguro)",
            22:   "SSH (acesso remoto seguro)",
            21:   "FTP (transferência de arquivos)",
            25:   "SMTP (e-mail)",
            53:   "DNS",
            3306: "MySQL",
            3389: "RDP (área de trabalho remota)",
            445:  "SMB (compartilhamento de arquivos)",
            8080: "HTTP alternativo",
        }.get(porta, "")

        n1 = (
            f"<b>{origem}</b> está iniciando uma conexão TCP com "
            f"<b>{destino}</b> na porta <b>{porta}</b>"
            + (f" — serviço típico: <b>{servico}</b>" if servico else "")
            + f".<br><br>"
            f"O TCP usa um <b>three-way handshake</b> (3 etapas) antes de "
            f"transmitir qualquer dado, garantindo que ambos os lados estejam "
            f"prontos para comunicar."
        )

        n2 = (
            f"<b>Etapa 1/3 — SYN</b>: {origem} → {destino}:{porta}<br>"
            + (f"<b>OS estimado pelo TTL:</b> {os_info}<br>" if os_info else "")
            + f"<b>Tamanho do pacote:</b> {tamanho} bytes<br><br>"
            f"<b>Próximas etapas:</b> SYN-ACK (servidor responde) → "
            f"ACK (cliente confirma) → conexão estabelecida.<br><br>"
            f"<b>Flags TCP:</b> cada bit tem um papel — SYN inicia, ACK confirma, "
            f"FIN encerra educadamente, RST interrompe abruptamente. "
            f"Um flood de SYNs sem ACK é o ataque <b>SYN Flood</b>, que esgota "
            f"a tabela de conexões do servidor."
        )

        campos = [
            ("IP Origem",     origem),
            ("IP Destino",    f"{destino}:{porta}"),
            ("Serviço",       servico or "—"),
            ("Flags TCP",     "SYN"),
            ("TTL",           f"{ttl} — {os_info}" if ttl and os_info else str(ttl) if ttl else "—"),
            ("Tamanho",       f"{tamanho} bytes"),
            ("Handshake",     "1/3 — SYN enviado"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "🔗", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # TCP FIN
    # ────────────────────────────────────────────────────────────────────────

    def _tcp_fin(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        tamanho = e.get("tamanho", 0)
        titulo  = f"Encerramento TCP — {origem} → {destino}"
        fluxo   = self._fluxo(origem, "TCP FIN", destino)

        n1 = (
            f"<b>{origem}</b> está encerrando a conexão TCP com <b>{destino}</b> "
            f"de forma educada, usando a flag <b>FIN</b>.<br><br>"
            f"O FIN garante que todos os dados pendentes sejam entregues antes "
            f"do fechamento, ao contrário do RST que interrompe imediatamente."
        )

        n2 = (
            f"<b>Encerramento TCP em 4 etapas:</b><br>"
            f"1. FIN (cliente) → 2. ACK (servidor) → "
            f"3. FIN (servidor) → 4. ACK (cliente)<br><br>"
            f"Após o último ACK, o socket permanece em estado "
            f"<b>TIME_WAIT</b> por ~60 segundos para absorver pacotes "
            f"atrasados que possam chegar fora de ordem."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
            ("Flags TCP",  "FIN — encerramento gracioso"),
        ])

        return self._base(e, "🔌", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # TCP RST
    # ────────────────────────────────────────────────────────────────────────

    def _tcp_rst(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino", "?")
        titulo  = f"Conexão recusada (RST) — {destino}:{porta}"
        fluxo   = self._fluxo(origem, "TCP RST", destino)

        n1 = (
            f"A conexão de <b>{origem}</b> com <b>{destino}:{porta}</b> "
            f"foi <b>recusada abruptamente</b> com a flag RST.<br><br>"
            f"Causas comuns: porta fechada no destino, firewall bloqueando "
            f"ou serviço indisponível no momento."
        )

        n2 = (
            f"<b>RST vs FIN:</b> o FIN encerra com negociação, o RST "
            f"interrompe sem entregar dados pendentes.<br><br>"
            f"<b>Quando investigar:</b> RSTs frequentes na mesma porta "
            f"de múltiplas origens podem indicar <b>port scanning</b>. "
            f"Um único RST é comportamento normal de rejeição de conexão."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", f"{destino}:{porta}"),
            ("Flags TCP",  "RST — reset imediato"),
            ("Causa",      "Porta fechada ou firewall"),
        ])

        return self._base(e, "⛔", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # ICMP
    # ────────────────────────────────────────────────────────────────────────

    def _icmp(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        ttl     = e.get("ttl")
        tamanho = e.get("tamanho", 0)
        payload = e.get("payload_resumo", "")
        os_info = _estimar_os(ttl)
        titulo  = f"ICMP Echo (Ping) — {origem} → {destino}"
        fluxo   = self._fluxo(origem, "ICMP", destino)

        saltos = None
        if ttl:
            try:
                t = int(ttl)
                saltos = 128 - t if t >= 120 else 64 - t if t >= 55 else 32 - t
            except Exception:
                pass

        n1 = (
            f"<b>{origem}</b> está testando se <b>{destino}</b> está acessível "
            f"e medindo a latência da conexão via <b>ping</b>.<br><br>"
            f"O ICMP Echo é a ferramenta básica de diagnóstico de rede — "
            f"o equivalente a 'bater na porta e esperar resposta'."
        )

        n2 = (
            f"<b>Protocolo:</b> ICMP Echo Request → Echo Reply<br>"
            + (f"<b>TTL:</b> {ttl} → ~{saltos} salto(s) até o destino<br>" if saltos is not None else "")
            + (f"<b>OS estimado:</b> {os_info}<br>" if os_info else "")
            + f"<b>Tamanho:</b> {tamanho} bytes<br><br>"
            f"<b>O TTL (Time To Live)</b> começa com um valor padrão e é "
            f"decrementado em 1 a cada roteador. Se chegar a 0, o pacote é "
            f"descartado e um ICMP 'Time Exceeded' é enviado de volta — "
            f"é assim que o <b>traceroute</b> funciona."
        )

        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("TTL",        str(ttl) if ttl else "—"),
            ("OS estimado",os_info or "—"),
            ("Saltos",     str(saltos) if saltos is not None else "—"),
            ("Tamanho",    f"{tamanho} bytes"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "📶", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # DHCP
    # ────────────────────────────────────────────────────────────────────────

    def _dhcp(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        tipo    = (e.get("dhcp_tipo", "") or "").upper()
        titulo  = f"DHCP {tipo} — {origem}" if tipo else f"DHCP — {origem}"
        fluxo   = self._fluxo(origem, f"DHCP {tipo}", destino)

        descricoes = {
            "DISCOVER": ("procurando servidor DHCP na rede",
                         "Broadcast enviado ao iniciar a interface de rede."),
            "OFFER":    ("recebeu oferta de IP do servidor DHCP",
                         "O servidor responde com um IP disponível, máscara, gateway e DNS."),
            "REQUEST":  ("solicitando formalmente o IP oferecido",
                         "O cliente confirma que quer o IP da oferta."),
            "ACK":      ("IP concedido com sucesso",
                         "O servidor confirma a concessão — o cliente agora tem IP válido."),
            "NAK":      ("IP recusado pelo servidor DHCP",
                         "O servidor rejeitou a solicitação; o cliente deve reiniciar o processo."),
            "RELEASE":  ("devolvendo o IP ao servidor",
                         "O cliente está liberando o endereço voluntariamente."),
            "INFORM":   ("solicitando configurações adicionais",
                         "O cliente já tem IP mas precisa de outras configurações (DNS, etc.)."),
        }
        desc, detalhe = descricoes.get(tipo, ("mensagem DHCP", ""))

        n1 = (
            f"<b>{origem}</b> {desc}.<br><br>"
            f"O processo completo de obtenção de IP é chamado <b>DORA</b>: "
            f"<b>D</b>iscover → <b>O</b>ffer → <b>R</b>equest → <b>A</b>ck."
            + (f"<br><br>{detalhe}" if detalhe else "")
        )

        n2 = (
            f"<b>Tipo:</b> DHCP {tipo}<br>"
            f"<b>Origem:</b> {origem} → <b>Destino:</b> {destino}<br><br>"
            f"<b>O que o DHCP distribui:</b> endereço IP, máscara de sub-rede, "
            f"gateway padrão, servidores DNS e tempo de concessão (lease time).<br><br>"
            f"<b>Contexto de segurança:</b> o DHCP não autentica clientes nem servidores. "
            f"Um <i>rogue DHCP server</i> pode distribuir gateway e DNS falsos, "
            f"redirecionando o tráfego. Em ambientes corporativos, "
            f"<b>DHCP Snooping</b> em switches gerenciados previne esse ataque."
        )

        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tipo DHCP",  tipo or "—"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "🏠", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # SSH — protocolo seguro, sem alerta
    # ────────────────────────────────────────────────────────────────────────

    def _ssh(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 22
        titulo  = f"SSH — Acesso remoto seguro a {destino}"
        fluxo   = self._fluxo(origem, "SSH (cifrado)", f"{destino}:{porta}")

        n1 = (
            f"<b>{origem}</b> está acessando o terminal de <b>{destino}</b> "
            f"via <b style='color:#2ECC71;'>SSH — protocolo totalmente cifrado</b>.<br><br>"
            f"Todo o tráfego SSH é protegido por criptografia: comandos, "
            f"respostas e até mesmo a autenticação são ilegíveis para "
            f"qualquer capturador na rede."
        )

        n2 = (
            f"<b>Porta:</b> {porta}<br>"
            f"<b>Criptografia:</b> negociada no handshake (AES, ChaCha20 etc.)<br>"
            f"<b>Autenticação:</b> senha ou par de chaves pública/privada<br><br>"
            f"<b>Boas práticas:</b> preferir autenticação por chave (mais seguro "
            f"que senha), desabilitar login root direto e mudar a porta padrão "
            f"em servidores expostos à internet reduz ruído de bots."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", f"{destino}:{porta}"),
            ("Cifrado",    "Sim — SSH"),
        ])

        return self._base(e, "🖥️", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # FTP — protocolo inseguro, AVISO justificado
    # ────────────────────────────────────────────────────────────────────────

    def _ftp(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 21
        titulo  = f"FTP sem criptografia — {destino}"
        fluxo   = self._fluxo(origem, "FTP (texto puro)", destino)
        alerta  = f"FTP transmite usuário e senha em texto puro para {destino}."

        n1 = (
            f"<b>{origem}</b> está transferindo arquivos para <b>{destino}</b> "
            f"via <b style='color:#E67E22;'>FTP — sem nenhuma criptografia</b>.<br><br>"
            f"Usuário, senha e todo o conteúdo dos arquivos trafegam em texto puro. "
            f"Qualquer capturador na rede pode interceptar credenciais e arquivos."
        )

        n2 = (
            f"<b>Porta de controle:</b> {porta} (texto puro)<br>"
            f"<b>Porta de dados:</b> 20 (ativa) ou negociada (passiva)<br><br>"
            f"<b>Alternativas seguras:</b><br>"
            f"• <b>SFTP</b> — FTP sobre SSH, porta 22, completamente cifrado<br>"
            f"• <b>FTPS</b> — FTP sobre TLS, porta 990 (implícito) ou 21 (explícito)<br><br>"
            f"<b>Por que isso importa:</b> diferente do HTTP onde só dados de formulário "
            f"são sensíveis, no FTP as credenciais aparecem nos primeiros pacotes de "
            f"controle — visíveis em qualquer captura de rede."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", f"{destino}:{porta}"),
            ("Cifrado",    "Não — texto puro"),
            ("Risco",      "Credenciais e arquivos visíveis na rede"),
        ])

        return self._base(e, "📁", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    # ────────────────────────────────────────────────────────────────────────
    # SMB
    # ────────────────────────────────────────────────────────────────────────

    def _smb(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 445
        titulo  = f"SMB — Compartilhamento de arquivos {destino}"
        fluxo   = self._fluxo(origem, "SMB", destino)
        alerta  = f"Tráfego SMB detectado — verifique se SMBv1 está desativado em {destino}."

        n1 = (
            f"<b>{origem}</b> está acessando arquivos compartilhados em "
            f"<b>{destino}</b> via <b>SMB (porta {porta})</b>.<br><br>"
            f"SMB é o protocolo padrão de compartilhamento de arquivos no Windows, "
            f"usado também em servidores Linux com Samba."
        )

        n2 = (
            f"<b>Porta:</b> {porta}<br><br>"
            f"<b>Histórico de vulnerabilidades:</b> o SMBv1 continha a falha "
            f"<b>EternalBlue (MS17-010)</b>, explorada pelo ransomware WannaCry "
            f"em 2017 para se propagar por redes inteiras sem interação do usuário.<br><br>"
            f"<b>Como verificar se SMBv1 está ativo:</b><br>"
            f"<code>Get-SmbServerConfiguration | Select EnableSMB1Protocol</code><br><br>"
            f"<b>Boas práticas:</b> desabilitar SMBv1, exigir assinatura de pacotes "
            f"(SMB Signing) e limitar o acesso por firewall."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      str(porta)),
            ("Protocolo",  "SMB (Server Message Block)"),
        ])

        return self._base(e, "📂", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    # ────────────────────────────────────────────────────────────────────────
    # RDP
    # ────────────────────────────────────────────────────────────────────────

    def _rdp(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 3389
        titulo  = f"RDP — Área de Trabalho Remota {destino}"
        fluxo   = self._fluxo(origem, "RDP", destino)
        alerta  = f"Sessão RDP detectada — verifique se o acesso a {destino} é autorizado."

        n1 = (
            f"<b>{origem}</b> está controlando remotamente a tela de "
            f"<b>{destino}</b> via <b>RDP (porta {porta})</b>.<br><br>"
            f"O RDP permite acesso completo ao desktop Windows remotamente. "
            f"É uma ferramenta legítima de administração, mas também um vetor "
            f"de ataque muito explorado quando exposto à internet."
        )

        n2 = (
            f"<b>Porta:</b> {porta}<br><br>"
            f"<b>Riscos quando exposto à internet:</b><br>"
            f"• Bots varrem a porta 3389 continuamente buscando credenciais fracas<br>"
            f"• Vulnerabilidade <b>BlueKeep (CVE-2019-0708)</b> permite execução "
            f"remota sem autenticação em versões antigas<br>"
            f"• Ataques de força bruta são frequentes<br><br>"
            f"<b>Boas práticas:</b> usar RDP somente via VPN, habilitar "
            f"<b>NLA (Network Level Authentication)</b>, monitorar eventos "
            f"de logon (ID 4625 — falha, 4624 — sucesso) e usar MFA."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      str(porta)),
            ("Protocolo",  "RDP (Remote Desktop Protocol)"),
        ])

        return self._base(e, "🖥️", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    # ────────────────────────────────────────────────────────────────────────
    # Novo dispositivo
    # ────────────────────────────────────────────────────────────────────────

    def _novo_dispositivo(self, e: dict) -> dict:
        ip  = e.get("ip_origem", "?")
        mac = e.get("mac_origem", "")
        fab = _fabricante(mac) if mac else ""
        titulo = f"Novo dispositivo — {ip}"
        fluxo  = self._fluxo("Rede local", "ARP/DHCP", ip)

        n1 = (
            f"Um novo dispositivo foi detectado na rede com o IP <b>{ip}</b>."
            + (f"<br>Fabricante identificado pelo MAC: <b style='color:#3498DB;'>{fab}</b>." if fab else "")
            + f"<br><br>Ele recebeu (ou já possuía) este IP via DHCP ou configuração manual."
        )

        n2 = (
            f"<b>IP:</b> {ip}<br>"
            + (f"<b>MAC:</b> <code>{mac}</code>" + (f" — {fab}" if fab else "") + "<br>" if mac else "")
            + f"<br><b>Identificação pelo MAC:</b> os primeiros 3 bytes (OUI) identificam "
            f"o fabricante do adaptador de rede. Consulte macvendors.com para verificar "
            f"dispositivos desconhecidos em sua rede."
        )

        campos = [
            ("IP detectado", ip),
            ("MAC",          f"{mac}" + (f" ({fab})" if fab else "") if mac else "não identificado"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "📱", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # HTTP Credentials (evento específico de credenciais capturadas)
    # ────────────────────────────────────────────────────────────────────────

    def _http_credenciais(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        creds   = e.get("credenciais", [])
        payload = e.get("payload_resumo", "") or e.get("http_corpo", "")

        linhas_creds = "<br>".join(
            f"• <code style='color:#E74C3C;'>{_escape(k)}</code> = "
            f"<b style='color:#E74C3C;'>{_escape(str(v))}</b>"
            for k, v in creds
        )

        titulo = "Credenciais capturadas via HTTP"
        alerta = f"Credenciais em texto puro: {', '.join(k for k, _ in creds[:4])}."
        fluxo  = self._fluxo(origem, "HTTP (sem criptografia)", destino)

        n1 = (
            f"<b style='color:#E74C3C;'>DADOS DE AUTENTICAÇÃO EM TEXTO PURO</b><br><br>"
            f"O dispositivo <b>{origem}</b> enviou credenciais para "
            f"<b>{destino}</b> via HTTP sem nenhuma proteção:<br><br>"
            f"{linhas_creds}<br><br>"
            f"Qualquer capturador ativo na mesma rede Wi-Fi ou segmento de rede "
            f"tem acesso imediato a esses dados."
        )

        n2 = (
            f"<b>Por que isso é crítico:</b> diferente do HTTPS onde o TLS cifra "
            f"o payload antes de sair do socket, o HTTP envia tudo como texto ASCII. "
            f"O ataque é passivo — basta capturar pacotes, sem precisar invadir "
            f"nenhum sistema.<br><br>"
            f"<b>Solução:</b> migrar para HTTPS com certificado válido e habilitar "
            f"HSTS para impedir downgrade para HTTP."
        )

        n3 = _tabela([
            ("IP Origem",   origem),
            ("IP Destino",  destino),
            ("Protocolo",   "HTTP — texto puro"),
            ("Credenciais", ", ".join(k for k, _ in creds)),
        ])

        if payload:
            hexdump = _hexdump(payload)
            n4 = (
                f"<pre style='color:#ecf0f1;font-size:10px;background:#000;"
                f"padding:12px;border-radius:6px;white-space:pre;'>"
                f"{_escape(hexdump)}</pre>"
            )
        else:
            n4 = ""

        return self._base(e, "🚨", titulo, "CRITICO", n1, n2, n3, n4, fluxo, alerta)

    # ────────────────────────────────────────────────────────────────────────
    # HTTP Request genérico
    # ────────────────────────────────────────────────────────────────────────

    def _http_request(self, e: dict) -> dict:
        origem  = e.get("ip_origem",  "?")
        destino = e.get("ip_destino", "?")
        metodo  = (e.get("http_metodo", "") or "GET").upper()
        caminho = e.get("http_caminho", "") or "/"
        return self._http({**e, "tipo": "HTTP",
                           "http_metodo": metodo, "http_caminho": caminho})

    # ────────────────────────────────────────────────────────────────────────
    # Genérico
    # ────────────────────────────────────────────────────────────────────────

    def _generico(self, e: dict) -> dict:
        protocolo = e.get("protocolo", "Desconhecido")
        origem    = e.get("ip_origem",  "?")
        destino   = e.get("ip_destino", "?")
        tamanho   = e.get("tamanho", 0)
        titulo    = f"{protocolo} — {origem} → {destino}"
        fluxo     = self._fluxo(origem, protocolo, destino)

        n1 = (
            f"Pacote <b>{protocolo}</b> capturado de <b>{origem}</b> "
            f"para <b>{destino}</b> ({tamanho} bytes)."
        )
        n2 = f"Protocolo <b>{protocolo}</b> — sem análise específica disponível."
        n3 = _tabela([
            ("Protocolo",  protocolo),
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
        ])

        return self._base(e, "📦", titulo, "INFO", n1, n2, n3, "", fluxo)

    # ────────────────────────────────────────────────────────────────────────
    # Resumo de sessão
    # ────────────────────────────────────────────────────────────────────────

    def gerar_resumo_sessao(self, total_pacotes: int, total_bytes: int,
                             protocolos: list, total_dispositivos: int) -> str:
        mb = total_bytes / (1024 * 1024)
        linhas = [
            "RESUMO DA SESSÃO", "-" * 36,
            f"Pacotes capturados:  {total_pacotes:>10,}",
            f"Volume transmitido:  {mb:>9.2f} MB",
            f"Dispositivos ativos: {total_dispositivos:>10}", "",
            "TOP PROTOCOLOS:",
        ]
        for item in protocolos[:6]:
            kb = item["bytes"] / 1024
            linhas.append(
                f"  {item['protocolo']:<12} {item['pacotes']:>6} pcts "
                f"({kb:.1f} KB)"
            )
        return "\n".join(linhas)