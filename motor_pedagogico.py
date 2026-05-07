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
            f"O dispositivo <b>{origem}</b> consulta o servidor DNS "
            f"<b>{destino}</b> para descobrir o endereço IP de "
            f"<b style='color:#3498DB;'>{dominio or 'um domínio'}</b>.<br><br>"
            f"Esta consulta precede qualquer conexão de rede: antes de alcançar "
            f"um servidor, o sistema operacional precisa converter o nome de domínio "
            f"em um endereço IP roteável. Sem essa resposta, o pacote não tem destino. "
            f"É a primeira coisa que acontece quando você digita uma URL no navegador "
            f"ou qualquer aplicação tenta alcançar um host pela internet."
        )

        n2 = (
            f"<b>Protocolo:</b> DNS sobre UDP porta {porta} — pacote de {tamanho} bytes.<br>"
            f"<b>Servidor consultado:</b> <code>{destino}</code><br>"
            f"<b>Domínio:</b> <code style='color:#3498DB;'>{dominio or '—'}</code><br><br>"
            f"<b>Por que UDP e não TCP?</b> Consultas DNS são pequenas (geralmente abaixo "
            f"de 512 bytes) e velocidade importa mais que confiabilidade — se a resposta "
            f"se perder, o sistema tenta de novo. UDP elimina o overhead do handshake TCP.<br><br>"
            f"<b>Hierarquia da resolução:</b> se o servidor local não souber, consulta "
            f"um <b>servidor raiz</b> → o <b>servidor TLD</b> (.com, .br, .org) "
            f"→ o <b>servidor autoritativo</b> do domínio. O resultado fica em cache "
            f"pelo tempo definido no campo TTL do registro DNS.<br><br>"
            f"<b>Visibilidade no tráfego:</b> a consulta trafega em texto puro e sem "
            f"autenticação. Qualquer dispositivo no caminho entre {origem} e {destino} "
            f"— incluindo outros hosts no mesmo segmento Wi-Fi — pode registrar "
            f"exatamente quais domínios este host está acessando, sem precisar "
            f"invadir nenhum sistema.<br><br>"
            f"<b>Alternativas que cifram:</b> <b>DNS over HTTPS (DoH)</b> porta 443 e "
            f"<b>DNS over TLS (DoT)</b> porta 853 ocultam os nomes consultados do "
            f"tráfego observável. O DNS convencional é vulnerável a "
            f"<b>DNS spoofing</b> e <b>cache poisoning</b>; o <b>DNSSEC</b> adiciona "
            f"assinaturas digitais nos registros para validar autenticidade, "
            f"mas não cifra a consulta em si."
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

        return self._base(e, "", titulo, "INFO", n1, n2, n3, n4, fluxo)

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
            f"O dispositivo <b>{origem}</b> enviou uma requisição "
            f"<b>{metodo}</b> para <b style='color:#E74C3C;'>{alvo}</b> "
            f"usando <b style='color:#E74C3C;'>HTTP — protocolo sem criptografia</b>.<br><br>"
            f"Em HTTP, todos os dados transitam em texto ASCII legível: a URL completa, "
            f"os cabeçalhos, os cookies e o corpo da requisição são capturáveis por "
            f"qualquer dispositivo presente no caminho entre cliente e servidor — "
            f"roteadores, switches, pontos de acesso Wi-Fi ou outros hosts no mesmo "
            f"segmento de rede. Não é necessário nenhum ataque ativo; "
            f"captura passiva com Wireshark já é suficiente para ler tudo."
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
            + f"<br><br><b>O que muda com HTTPS:</b> toda esta requisição — "
            f"incluindo a URL <code>{_escape(caminho)}</code>, os cabeçalhos e o corpo — "
            f"seria cifrada com AES antes de sair do socket. "
            f"Um capturador na rede veria apenas bytes aleatórios sem nenhuma informação utilizável. "
            f"Com HTTP, cada campo desta requisição está disponível em texto puro "
            f"para qualquer dispositivo no caminho de {origem} até {alvo}."
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

        return self._base(e, "", titulo, nivel, n1, n2, n3, n4, fluxo, alerta)

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
            f"O dispositivo <b>{origem}</b> estabelece conexão com "
            f"<b style='color:#2ECC71;'>{alvo}</b> utilizando <b>HTTPS</b>.<br><br>"
            f"O HTTPS não é um protocolo separado — é HTTP transportado sobre "
            f"<b>TLS (Transport Layer Security)</b>. Antes de qualquer dado HTTP "
            f"trafegar, cliente e servidor executam um <b>handshake TLS</b>: "
            f"trocam certificados, negociam algoritmos criptográficos e derivam "
            f"chaves de sessão simétricas. A partir daí, tudo — URL completa, "
            f"headers, corpo, cookies e credenciais — flui cifrado. "
            f"Um capturador na rede enxerga apenas IPs, porta 443 e, durante o "
            f"ClientHello, o <b>SNI</b> (Server Name Indication) — que revela "
            f"o nome do host, mas não o que está sendo acessado nele."
        )

        n2 = (
            f"<b>Destino:</b> {alvo}:{porta}<br>"
            + (f"<b>Fase:</b> {fase}<br>" if fase else "")
            + (f"<b>SNI:</b> <code style='color:#2ECC71;'>{sni}</code><br>" if sni else "")
            + f"<b>Tamanho do pacote:</b> {tamanho} bytes<br><br>"
            f"<b>Como o handshake TLS funciona na prática:</b><br>"
            f"1. <b>ClientHello</b>: o cliente anuncia versões TLS suportadas e conjuntos de cifras<br>"
            f"2. <b>ServerHello + Certificado</b>: o servidor escolhe os algoritmos "
            f"e envia seu certificado X.509 para autenticação<br>"
            f"3. <b>Troca de chaves (ECDHE)</b>: cliente e servidor derivam "
            f"uma chave de sessão compartilhada sem jamais transmiti-la diretamente<br>"
            f"4. <b>Canal cifrado</b>: toda a comunicação HTTP passa dentro do túnel TLS<br><br>"
            f"<b>Perfect Forward Secrecy:</b> com ECDHE, cada sessão usa uma chave "
            f"efêmera e independente. Se a chave privada do servidor vazar no futuro, "
            f"sessões passadas gravadas permanecem completamente indecifráveis — "
            f"ao contrário de cifras RSA estáticas, onde uma única chave comprometida "
            f"poderia desfazer todo o histórico de sessões capturadas.<br><br>"
            f"<b>O que ainda é visível para um capturador:</b> endereço IP de "
            f"destino, porta 443 e o SNI no ClientHello. Para ocultar também o SNI, "
            f"o padrão <b>Encrypted Client Hello (ECH)</b> cifra essa informação "
            f"— disponível em HTTP/3 com QUIC."
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

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
                f"<b>{origem}</b> envia um <b>broadcast ARP Request</b> para toda a "
                f"rede local perguntando: <i>'Quem possui o IP <b>{destino}</b>? "
                f"Envie-me seu endereço MAC.'</i><br><br>"
                f"O broadcast vai para <code>FF:FF:FF:FF:FF:FF</code> — todos os "
                f"dispositivos na rede o recebem, mas apenas o dono do IP responde. "
                f"Isso ocorre porque a comunicação na camada Ethernet (Camada 2) "
                f"exige o endereço físico do destino — o IP sozinho não é suficiente "
                f"para montar um quadro Ethernet e entregá-lo ao próximo hop."
            )
        else:
            n1 = (
                f"<b>{origem}</b> responde ao ARP Request declarando: "
                f"<i>'O IP <b>{destino}</b> pertence a <code>{mac_src}</code> — sou eu.'</i><br><br>"
                f"Esta resposta unicast é entregue diretamente ao host que fez a "
                f"pergunta, que armazena o mapeamento IP→MAC em sua <b>tabela ARP</b> "
                f"local (<code>arp -a</code>) para não precisar repetir a consulta "
                f"a cada pacote enviado para este destino."
            )

        n2 = (
            f"<b>Por que o ARP existe:</b> o protocolo IP opera na Camada 3 com "
            f"endereços lógicos. A Ethernet (Camada 2) usa endereços físicos (MAC). "
            f"Quando a pilha IP precisa entregar um pacote, precisa descobrir qual "
            f"MAC corresponde ao IP destino no segmento local — o ARP faz essa "
            f"tradução dinâmica, mantendo um cache que expira em 60–120 segundos.<br><br>"
            f"<b>MAC de origem:</b> <code>{mac_src}</code>"
            + (f" — <b>{fab}</b>" if fab else "")
            + f"<br><b>IP mapeado:</b> {destino}<br><br>"
            f"<b>ARP Spoofing — o ataque Man-in-the-Middle local:</b> como o ARP "
            f"não possui nenhuma autenticação, qualquer dispositivo pode enviar "
            f"respostas ARP não solicitadas (<i>gratuitous ARP</i>), "
            f"envenenando a tabela de outros hosts. O resultado: o tráfego "
            f"destinado a {destino} pode ser desviado para o host do atacante — "
            f"que o repassa ao destino real sem que nenhuma das partes perceba. "
            f"Esta é a base técnica de ataques MitM em redes locais.<br><br>"
            f"<b>Mitigação:</b> <b>Dynamic ARP Inspection (DAI)</b> em switches "
            f"gerenciados valida cada resposta ARP contra a tabela de concessões "
            f"DHCP confiáveis, descartando respostas que não correspondam ao par "
            f"IP/MAC registrado — bloqueando o spoofing na origem."
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
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"<b>{origem}</b> dispara o primeiro passo do "
            f"<b>three-way handshake TCP</b> em direção a "
            f"<b>{destino}</b>, porta <b>{porta}</b>"
            + (f" — serviço esperado: <b>{servico}</b>" if servico else "")
            + f".<br><br>"
            f"O pacote SYN (synchronize) não transfere dados — sua função é "
            f"anunciar ao servidor: <i>'quero me conectar, e este é meu número "
            f"de sequência inicial (ISN)'</i>. O servidor ainda não abriu sessão "
            f"alguma; apenas enfileirou esta requisição em sua tabela de "
            f"conexões TCP incompletas aguardando o passo seguinte."
        )

        n2 = (
            f"<b>Etapa 1/3 — SYN</b>: {origem} → {destino}:{porta}<br>"
            + (f"<b>OS estimado pelo TTL ({ttl}):</b> {os_info}<br>" if os_info and ttl else "")
            + f"<b>Tamanho do pacote:</b> {tamanho} bytes<br><br>"
            f"<b>O three-way handshake completo:</b><br>"
            f"→ <b>SYN</b>: cliente envia número de sequência inicial aleatório (ISN)<br>"
            f"→ <b>SYN-ACK</b>: servidor responde com seu próprio ISN "
            f"e confirma o ISN do cliente<br>"
            f"→ <b>ACK</b>: cliente confirma o ISN do servidor; "
            f"conexão bidirecional estabelecida<br><br>"
            f"<b>Por que três vias?</b> Para que ambos os lados confirmem "
            f"seus números de sequência e capacidades antes de transmitir dados — "
            f"garantindo entrega ordenada, sem duplicatas e com controle de fluxo.<br><br>"
            f"<b>Estimativa de SO pelo TTL:</b> sistemas operacionais definem "
            f"valores padrão de TTL ao originar pacotes (Windows: 128, Linux/macOS: 64). "
            f"Subtraindo o TTL observado ({ttl or '?'}) do padrão mais provável, "
            f"estima-se quantos roteadores o pacote atravessou até ser capturado.<br><br>"
            f"<b>Vetor de ataque — SYN Flood:</b> um atacante envia milhares de SYNs "
            f"com IPs de origem forjados. O servidor aloca recursos para cada conexão "
            f"incompleta e nunca recebe o ACK final, esgotando sua tabela de "
            f"half-open connections. <b>SYN cookies</b> resolvem isso codificando "
            f"o estado da conexão no ISN do SYN-ACK, sem alocar recursos "
            f"antes do ACK chegar."
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

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"<b>{origem}</b> sinaliza o encerramento ordenado da sessão TCP "
            f"com <b>{destino}</b> enviando a flag <b>FIN</b> (finish).<br><br>"
            f"Diferente de um corte abrupto, o FIN inicia um processo negociado "
            f"de quatro vias: garante que todos os dados em trânsito sejam "
            f"entregues antes de liberar os recursos da conexão. "
            f"O host que envia o FIN indica que não tem mais dados a transmitir — "
            f"mas ainda pode receber dados do outro lado até que este também envie seu FIN."
        )

        n2 = (
            f"<b>Encerramento TCP em 4 etapas:</b><br>"
            f"1. <b>FIN</b> ({origem} → {destino}): 'não tenho mais dados a enviar'<br>"
            f"2. <b>ACK</b> ({destino} → {origem}): 'recebi seu FIN'<br>"
            f"3. <b>FIN</b> ({destino} → {origem}): 'eu também terminei'<br>"
            f"4. <b>ACK</b> ({origem} → {destino}): 'confirmado — conexão encerrada'<br><br>"
            f"<b>Estado TIME_WAIT:</b> após o último ACK, o socket permanece em "
            f"TIME_WAIT por aproximadamente 2×MSL (Maximum Segment Lifetime, ~60s). "
            f"O objetivo: garantir que pacotes atrasados da sessão encerrada não "
            f"contaminem uma nova conexão com o mesmo par IP:porta. "
            f"Em servidores de alto volume, TIME_WAIT excessivo pode esgotar "
            f"as portas efêmeras disponíveis — ajustável via "
            f"<code>tcp_tw_reuse</code> no Linux.<br><br>"
            f"<b>FIN vs RST:</b> o FIN negocia o encerramento garantindo entrega "
            f"dos dados pendentes. O RST é um corte imediato — qualquer dado "
            f"não confirmado é descartado sem entrega."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
            ("Flags TCP",  "FIN — encerramento gracioso"),
        ])

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"foi encerrada abruptamente pela flag <b>RST</b> (reset).<br><br>"
            f"O RST não negocia — ele termina a conexão imediatamente, "
            f"descartando qualquer dado em trânsito. "
            f"É enviado quando o destinatário não reconhece a conexão, "
            f"quando não há serviço ouvindo na porta solicitada, "
            f"ou quando uma aplicação decide rejeitar a sessão sem aguardar."
        )

        n2 = (
            f"<b>Causas mais comuns de um RST:</b><br>"
            f"• Porta <b>{porta}</b> fechada em {destino} — "
            f"o kernel rejeita automaticamente com RST<br>"
            f"• Firewall com regra REJECT (diferente de DROP, "
            f"que simplesmente descarta sem responder)<br>"
            f"• Serviço encerrado enquanto havia sessão ativa<br>"
            f"• Aplicação detectou estado inválido e decidiu abortar<br><br>"
            f"<b>RST vs FIN:</b> o FIN negocia o encerramento em 4 etapas, "
            f"garantindo entrega dos dados pendentes. "
            f"O RST é um corte imediato — dados não confirmados são perdidos.<br><br>"
            f"<b>RST como indicador de varredura de portas:</b> se {origem} "
            f"recebe múltiplos RSTs em sequência rápida, cada um de uma porta "
            f"diferente de {destino}, isso revela que as portas estão fechadas — "
            f"exatamente o padrão que ferramentas como Nmap observam ao mapear "
            f"um host. Um único RST é comportamento normal de rejeição; "
            f"dezenas em poucos segundos indicam varredura ativa."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", f"{destino}:{porta}"),
            ("Flags TCP",  "RST — reset imediato"),
            ("Causa",      "Porta fechada ou firewall"),
        ])

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"<b>{origem}</b> envia um <b>ICMP Echo Request</b> para "
            f"<b>{destino}</b> — o clássico comando <code>ping</code>.<br><br>"
            f"O ICMP (Internet Control Message Protocol) não é um protocolo "
            f"de transporte de dados: é a <b>camada de diagnóstico e controle "
            f"do protocolo IP</b>. O Echo Request/Reply testa alcançabilidade e "
            f"mede latência, mas o ICMP também carrega mensagens críticas como "
            f"'destino inacessível', 'TTL expirado' e 'fragmentação necessária' — "
            f"informações que os próprios roteadores usam para reportar "
            f"problemas na rede."
        )

        n2 = (
            f"<b>Protocolo:</b> ICMP tipo 8 (Echo Request) / tipo 0 (Echo Reply)<br>"
            + (f"<b>TTL observado:</b> {ttl} → ~{saltos} salto(s) percorrido(s)<br>" if saltos is not None else "")
            + (f"<b>OS estimado:</b> {os_info}<br>" if os_info else "")
            + f"<b>Tamanho:</b> {tamanho} bytes<br><br>"
            f"<b>Como o TTL revela a topologia:</b> o TTL começa com um valor "
            f"padrão definido pelo sistema operacional e é decrementado em 1 "
            f"por cada roteador. Se o padrão é 64 e o valor observado é "
            f"{ttl or '?'}, o pacote percorreu ~{saltos or '?'} salto(s). "
            f"O <b>traceroute</b> explora exatamente isso: envia ICMPs com TTL=1, "
            f"depois TTL=2 etc., forçando cada roteador a enviar "
            f"'ICMP Time Exceeded' de volta — mapeando toda a rota hop a hop.<br><br>"
            f"<b>Outros tipos ICMP relevantes:</b> tipo 3 (Destination Unreachable) "
            f"informa que um host ou porta não pode ser alcançado; "
            f"tipo 11 (Time Exceeded) é gerado ao descartar pacotes com TTL=0; "
            f"tipo 5 (Redirect) instrui o host a usar uma rota diferente.<br><br>"
            f"<b>ICMP em contexto de segurança:</b> varreduras ICMP "
            f"(<i>ping sweep</i>) identificam quais hosts estão ativos antes "
            f"de um ataque mais direcionado. Por isso, muitos administradores "
            f"bloqueiam ICMP no perímetro — mas isso também prejudica diagnósticos "
            f"legítimos de conectividade e rota."
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

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"O <b>protocolo DHCP</b> automatiza a atribuição de configurações IP "
            f"em uma rede: endereço IP, máscara de sub-rede, gateway padrão, "
            f"servidores DNS e tempo de concessão (<i>lease time</i>). "
            f"Sem DHCP, cada dispositivo precisaria de configuração manual "
            f"— inviável em redes com dezenas ou centenas de hosts.<br><br>"
            f"<b>O fluxo DORA completo:</b><br>"
            f"→ <b>Discover</b>: broadcast — o cliente grita 'tem servidor DHCP nessa rede?'<br>"
            f"→ <b>Offer</b>: o servidor propõe um IP disponível com parâmetros<br>"
            f"→ <b>Request</b>: o cliente confirma formalmente que quer aquele IP<br>"
            f"→ <b>Ack</b>: o servidor concede — o cliente agora tem IP válido"
            + (f"<br><br><b>Esta mensagem — DHCP {tipo}:</b> {detalhe}" if detalhe else "")
        )

        n2 = (
            f"<b>Tipo:</b> DHCP {tipo}<br>"
            f"<b>Origem:</b> {origem} → <b>Destino:</b> {destino}<br><br>"
            f"<b>O que o servidor DHCP distribui além do IP:</b><br>"
            f"• <b>Máscara de sub-rede</b>: define o tamanho do segmento local<br>"
            f"• <b>Gateway padrão</b>: endereço do roteador para tráfego externo<br>"
            f"• <b>Servidores DNS</b>: para resolução de nomes<br>"
            f"• <b>Lease time</b>: quanto tempo o cliente pode manter o IP sem renovar<br><br>"
            f"<b>Rogue DHCP Server — o ataque silencioso:</b> como o DHCP não "
            f"autentica clientes nem servidores, um dispositivo malicioso pode "
            f"responder ao Discover de {origem} antes do servidor legítimo "
            f"e distribuir gateway e DNS falsos — redirecionando "
            f"silenciosamente todo o tráfego do host para um servidor "
            f"controlado pelo atacante, sem que o usuário perceba nada.<br><br>"
            f"<b>Mitigação:</b> <b>DHCP Snooping</b> em switches gerenciados "
            f"designa apenas portas específicas como confiáveis para responder "
            f"mensagens DHCP Offer, bloqueando servidores não autorizados."
        )

        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tipo DHCP",  tipo or "—"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"<b>{origem}</b> estabelece uma sessão <b>SSH</b> com "
            f"<b>{destino}</b> na porta <b>{porta}</b>.<br><br>"
            f"SSH (Secure Shell) é o substituto seguro de protocolos legados "
            f"como Telnet e rsh, que transmitiam tudo — incluindo senhas — "
            f"em texto puro. No SSH, o canal é completamente cifrado desde o "
            f"primeiro byte após o handshake: comandos digitados, saídas do "
            f"terminal, senhas e até redirecionamento de portas "
            f"(<i>port forwarding</i>) transitam ilegíveis para qualquer "
            f"capturador na rede."
        )

        n2 = (
            f"<b>Porta:</b> {porta}<br>"
            f"<b>Cifras de transporte comuns:</b> AES-256-GCM, ChaCha20-Poly1305<br>"
            f"<b>Autenticação:</b> por senha ou par de chaves pública/privada<br><br>"
            f"<b>Como o SSH protege passo a passo:</b><br>"
            f"1. Handshake: cliente e servidor trocam chaves e negociam cifras<br>"
            f"2. Autenticação do servidor: o cliente verifica a chave pública "
            f"do servidor em <code>~/.ssh/known_hosts</code> — "
            f"impedindo que um host falso se apresente como o servidor real<br>"
            f"3. Autenticação do cliente: por senha ou par Ed25519/RSA<br>"
            f"4. Canal cifrado: toda a sessão de terminal flui protegida<br><br>"
            f"<b>Chave vs senha:</b> chaves são imunes a brute-force se geradas "
            f"com entropia adequada. Para qualquer servidor exposto à internet, "
            f"desabilitar autenticação por senha "
            f"(<code>PasswordAuthentication no</code> no sshd_config) "
            f"elimina ataques de dicionário automatizados que tentam "
            f"credenciais continuamente em escala global.<br><br>"
            f"<b>Boas práticas adicionais:</b> alterar a porta padrão reduz "
            f"ruído de bots; <code>fail2ban</code> bloqueia IPs com múltiplas "
            f"tentativas falhas; autenticação multifator (MFA) com OTP "
            f"adiciona uma segunda camada mesmo para acesso por chave."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", f"{destino}:{porta}"),
            ("Cifrado",    "Sim — SSH"),
        ])

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"<b>{origem}</b> acessa o servidor <b>{destino}</b> via "
            f"<b style='color:#E67E22;'>FTP — protocolo sem nenhuma criptografia</b>.<br><br>"
            f"O FTP foi projetado em 1971, numa época em que a internet era uma "
            f"rede acadêmica fechada e segurança não era uma preocupação. "
            f"Toda a sessão de controle — incluindo usuário e senha — trafega "
            f"em <b>texto ASCII puro na porta 21</b>. "
            f"No Wireshark, basta filtrar por <code>ftp</code> e abrir "
            f"<i>Follow TCP Stream</i> para ler as credenciais completas "
            f"exatamente como foram digitadas."
        )

        n2 = (
            f"<b>Porta de controle:</b> {porta} (comandos em texto puro)<br>"
            f"<b>Porta de dados:</b> 20 (modo ativo) ou negociada (modo passivo)<br><br>"
            f"<b>Por que dois canais separados?</b> O FTP divide a sessão: "
            f"a conexão de controle (porta 21) recebe comandos como "
            f"<code>USER</code>, <code>PASS</code>, <code>LIST</code>, <code>RETR</code>; "
            f"a conexão de dados transfere os arquivos em si. "
            f"Credenciais aparecem <i>antes</i> de qualquer arquivo ser enviado — "
            f"nos primeiros pacotes da sessão, visíveis em texto puro.<br><br>"
            f"<b>Modo ativo vs passivo:</b> no modo ativo, o servidor abre "
            f"uma conexão de volta ao cliente (porta 20) — problemático com "
            f"NAT e firewalls. No modo passivo (PASV), o cliente inicia ambas "
            f"as conexões, mais compatível com redes modernas.<br><br>"
            f"<b>Alternativas obrigatórias para qualquer uso atual:</b><br>"
            f"• <b>SFTP</b> (SSH File Transfer Protocol) — usa o canal SSH, "
            f"porta 22, completamente cifrado; não tem relação técnica com FTP<br>"
            f"• <b>FTPS</b> (FTP sobre TLS) — adiciona camada TLS ao FTP, "
            f"porta 990 (implícito) ou 21 com STARTTLS (explícito)<br>"
            f"• <b>SCP</b> — cópia segura via SSH, simples e amplamente disponível"
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", f"{destino}:{porta}"),
            ("Cifrado",    "Não — texto puro"),
            ("Risco",      "Credenciais e arquivos visíveis na rede"),
        ])

        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

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
            f"<b>{origem}</b> acessa recursos compartilhados em <b>{destino}</b> "
            f"via <b>SMB (Server Message Block)</b>, porta <b>{porta}</b>.<br><br>"
            f"SMB é o protocolo nativo do Windows para compartilhamento de "
            f"arquivos, impressoras e comunicação entre processos na rede local. "
            f"O Linux acessa compartilhamentos Windows via implementação compatível "
            f"chamada <b>Samba</b>. Quando você navega em um caminho de rede como "
            f"<code>\\\\servidor\\pasta</code> no Windows Explorer, "
            f"é o SMB que opera nos bastidores."
        )

        n2 = (
            f"<b>Porta:</b> {porta} (SMB sobre TCP, versões 2 e 3)<br>"
            f"<b>Porta histórica:</b> 139 (NetBIOS — SMBv1)<br><br>"
            f"<b>O caso EternalBlue / WannaCry:</b> em 2017, uma falha crítica "
            f"no SMBv1 (MS17-010, codinome EternalBlue) foi explorada pelo "
            f"ransomware WannaCry e pelo worm NotPetya para se propagar "
            f"automaticamente por redes inteiras — sem interação do usuário, "
            f"apenas uma porta 445 acessível era suficiente para comprometer "
            f"um sistema Windows não atualizado.<br><br>"
            f"<b>Verificar e desabilitar SMBv1:</b><br>"
            f"<code>Get-SmbServerConfiguration | Select EnableSMB1Protocol</code><br>"
            f"<code>Set-SmbServerConfiguration -EnableSMB1Protocol $false</code><br><br>"
            f"<b>Proteções do SMBv3:</b> versões modernas suportam "
            f"<b>criptografia nativa</b> (SMB 3.0+) e <b>assinatura de pacotes "
            f"(SMB Signing)</b> — que impede adulteração dos dados em trânsito "
            f"e ataques de relay NTLM. Ambos devem ser obrigatórios em "
            f"ambientes corporativos, com acesso limitado por firewall "
            f"apenas aos hosts que necessitam do compartilhamento."
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      str(porta)),
            ("Protocolo",  "SMB (Server Message Block)"),
        ])

        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

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
            f"<b>{origem}</b> controla remotamente a área de trabalho de "
            f"<b>{destino}</b> via <b>RDP (Remote Desktop Protocol)</b>, "
            f"porta <b>{porta}</b>.<br><br>"
            f"O RDP é o protocolo proprietário da Microsoft para acesso remoto "
            f"gráfico ao Windows: transmite a tela do servidor comprimida ao "
            f"cliente e recebe de volta as entradas de teclado e mouse. "
            f"Internamente usa TLS para cifrar a sessão, mas seu histórico "
            f"de vulnerabilidades severas e a exposição frequente à internet "
            f"fazem dele um dos vetores de ataque mais ativos em ambientes corporativos."
        )

        n2 = (
            f"<b>Porta:</b> {porta}<br><br>"
            f"<b>Vulnerabilidades críticas de referência:</b><br>"
            f"• <b>BlueKeep (CVE-2019-0708):</b> execução remota de código "
            f"sem autenticação em Windows XP, 7 e Server 2008 — "
            f"um único pacote malicioso era suficiente para comprometer o sistema<br>"
            f"• <b>DejaBlue (CVE-2019-1181/1182):</b> variante que afetou "
            f"também o Windows 10<br><br>"
            f"<b>Ameaça contínua:</b> bots varrem a internet ininterruptamente "
            f"buscando a porta 3389 aberta. Logs de Eventos em servidores expostos "
            f"(ID 4625 — falha de login) frequentemente registram centenas de "
            f"tentativas por hora provenientes de IPs automatizados globais.<br><br>"
            f"<b>Proteções obrigatórias para uso seguro:</b><br>"
            f"• Nunca expor RDP diretamente à internet — acesse somente via VPN<br>"
            f"• Habilitar <b>NLA (Network Level Authentication)</b>: "
            f"autentica o usuário antes de renderizar a sessão gráfica<br>"
            f"• Habilitar <b>MFA</b> no acesso RDP<br>"
            f"• Monitorar Eventos 4625 (falha) e 4624 (sucesso) no Visualizador<br>"
            f"• Usar <b>RD Gateway</b> para tunelamento seguro via HTTPS em corporativo"
        )

        n3 = _tabela([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      str(porta)),
            ("Protocolo",  "RDP (Remote Desktop Protocol)"),
        ])

        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

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
            f"Um novo endereço IP foi detectado na rede: <b>{ip}</b>."
            + (f"<br>O endereço MAC aponta para fabricante: <b style='color:#3498DB;'>{fab}</b>." if fab else "")
            + f"<br><br>O dispositivo tornou-se visível no tráfego — "
            f"provavelmente após receber um IP via DHCP, ao enviar um ARP Request "
            f"ou ao iniciar qualquer comunicação na rede. "
            f"Em redes bem administradas, todo host novo deve ser identificado "
            f"e verificado se é um dispositivo autorizado."
        )

        n2 = (
            f"<b>IP detectado:</b> {ip}<br>"
            + (f"<b>MAC:</b> <code>{mac}</code>" + (f" — {fab}" if fab else "") + "<br>" if mac else "")
            + f"<br><b>OUI — Como o fabricante é identificado pelo MAC:</b> "
            f"os primeiros 3 bytes do endereço MAC (OUI — Organizationally Unique "
            f"Identifier) são registrados pela IEEE e identificam o fabricante "
            f"do adaptador de rede. Consulte <b>macvendors.com</b> para verificar "
            f"MACs desconhecidos que aparecerem na sua rede.<br><br>"
            f"<b>Limitação importante:</b> o endereço MAC pode ser falsificado "
            f"(<i>MAC spoofing</i>) com um simples comando no sistema operacional "
            f"— basta uma linha no Linux ou Windows. "
            f"Soluções de controle de acesso baseadas apenas em MAC filtering "
            f"oferecem proteção superficial: um atacante pode clonar o MAC "
            f"de um dispositivo autorizado em segundos.<br><br>"
            f"<b>O que investigar:</b> verifique se {ip} consta na tabela de "
            f"concessões DHCP do servidor, se o MAC está no inventário da rede "
            f"e se o padrão de tráfego gerado é condizente com um host legítimo. "
            f"Dispositivos não reconhecidos devem ser isolados até identificação."
        )

        campos = [
            ("IP detectado", ip),
            ("MAC",          f"{mac}" + (f" ({fab})" if fab else "") if mac else "não identificado"),
        ]
        n3 = _tabela(campos)

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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
            f"<b style='color:#E74C3C;'>CREDENCIAIS DE AUTENTICAÇÃO EXPOSTAS EM TEXTO PURO</b><br><br>"
            f"O dispositivo <b>{origem}</b> enviou dados de login para "
            f"<b>{destino}</b> via HTTP sem qualquer proteção criptográfica:<br><br>"
            f"{linhas_creds}<br><br>"
            f"Estes dados estavam legíveis em cada salto de rede entre "
            f"{origem} e {destino}. Qualquer dispositivo no caminho — "
            f"roteadores, switches gerenciados, pontos de acesso Wi-Fi "
            f"ou outro host no mesmo segmento — poderia ter capturado "
            f"estas credenciais com um simples <code>tcpdump</code> ou Wireshark, "
            f"sem precisar atacar ativamente nenhum sistema."
        )

        n2 = (
            f"<b>Por que HTTP expõe credenciais completamente:</b> o payload "
            f"de uma requisição POST em HTTP é enviado como texto ASCII na sequência: "
            f"linha de requisição, headers, linha em branco, corpo com os campos "
            f"no formato <code>campo=valor&campo2=valor2</code>. "
            f"Não existe ofuscação, codificação de segurança ou chave — "
            f"a codificação URL (<code>%XX</code>) não é criptografia, "
            f"é apenas representação de caracteres especiais.<br><br>"
            f"<b>Como o HTTPS resolve isso:</b> com TLS, o payload HTTP inteiro "
            f"— incluindo a URL, os headers e o corpo com as credenciais — "
            f"é cifrado com AES antes de sair do socket. "
            f"Um capturador na rede enxerga apenas bytes cifrados aleatórios, "
            f"sem nenhuma informação utilizável.<br><br>"
            f"<b>HSTS — bloqueando downgrade para HTTP:</b> mesmo com HTTPS "
            f"disponível, um atacante MitM pode forçar o cliente a usar HTTP "
            f"em vez de HTTPS. O <b>HTTP Strict Transport Security (HSTS)</b> "
            f"instrui o navegador a nunca mais aceitar HTTP para este domínio "
            f"— bloqueando o downgrade a nível de cliente.<br><br>"
            f"<b>Impacto prático:</b> com estas credenciais, um atacante pode "
            f"autenticar-se como a vítima, alterar senha, exfiltrar dados "
            f"ou usar a conta como ponto de entrada para movimentação lateral "
            f"na rede interna."
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

        return self._base(e, "", titulo, "CRITICO", n1, n2, n3, n4, fluxo, alerta)

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

        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

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