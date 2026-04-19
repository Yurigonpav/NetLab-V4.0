# painel_servidor.py
# Servidor HTTP educacional para demonstrações de segurança em sala de aula.
# Exibe APENAS o modo vulnerável (sem criptografia de senha, sem bloqueio).

import socket
import threading
import time
import re
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Callable
from urllib.parse import parse_qs

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter,
    QTextEdit, QCheckBox, QGroupBox, QGridLayout,
    QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor


# ─────────────────────────────────────────────────────────────────────────────
# Sinais para comunicação thread-safe entre servidor e UI
# ─────────────────────────────────────────────────────────────────────────────

class SinaisServidor(QObject):
    """Sinais emitidos pelo servidor HTTP para atualizar a interface."""
    requisicao_recebida = pyqtSignal(dict)  # dados de cada requisição
    status_alterado     = pyqtSignal(str)   # mensagem de status geral
    alerta_emitido      = pyqtSignal(str)   # alerta didático educacional


sinais_servidor = SinaisServidor()


# ─────────────────────────────────────────────────────────────────────────────
# Handler HTTP — modo vulnerável (sem proteções)
# ─────────────────────────────────────────────────────────────────────────────

class HandlerLabEducacional(BaseHTTPRequestHandler):
    """
    Handler HTTP que registra todas as requisições e serve páginas didáticas.

    Funciona APENAS no modo vulnerável:
      - Senhas armazenadas e trafegadas em texto puro
      - Sem bloqueio por falhas de login
      - Sem rate limiting no login
      - Ideal para demonstrar em sala de aula como capturas de pacotes
        revelam credenciais quando HTTP é usado no lugar de HTTPS
    """

    # ── Controle de volume de requisições (proteção didática contra DoS) ──
    _contagem_por_ip:     dict = defaultdict(int)
    _timestamps_por_ip:   dict = defaultdict(list)
    _ips_bloqueados:      set  = set()
    _ip_bloqueado_ate:    dict = {}
    _limite_req_por_seg:  int  = 10   # 0 = sem limite
    _tempo_bloqueio:      int  = 30   # segundos de bloqueio por volume
    _protecao_ativa:      bool = False
    _callback_requisicao: Optional[Callable] = None
    _lock                = threading.Lock()

    # ── Banco de usuários (texto puro — propositalmente vulnerável) ────────
    _usuarios_vuln: dict = {"admin": "123456"}

    # ─────────────────────────────────────────────────────────────────────
    # Páginas HTML servidas pelo servidor educacional
    # ─────────────────────────────────────────────────────────────────────

    PAGINA_INICIAL = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetLab — Servidor de Laboratório</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family:'Segoe UI',Roboto,system-ui,sans-serif;
            background:linear-gradient(145deg,#0a0f1e 0%,#0f1423 100%);
            color:#e0e4f0; min-height:100vh;
            display:flex; flex-direction:column;
            align-items:center; padding:1.5rem;
        }
        h1 { font-size:clamp(1.8rem,6vw,2.5rem); color:#5a9eff;
             margin-bottom:.25rem; font-weight:600; }
        .subtitle { color:#7f8fa3; font-size:clamp(.9rem,4vw,1rem);
                    margin-bottom:2rem; text-align:center; }
        .nav { display:flex; flex-wrap:wrap; justify-content:center;
               gap:.75rem; margin-bottom:2.5rem; max-width:600px; }
        .nav a {
            color:#cbd5e6; text-decoration:none;
            padding:.6rem 1.2rem;
            background:rgba(18,26,40,.8); border:1px solid #1e3a5f;
            border-radius:40px; font-size:.95rem; font-weight:500;
            transition:all .2s ease;
        }
        .nav a:hover { background:#1e3a5f; color:#fff; }
        .card {
            background:rgba(18,26,40,.9); border:1px solid #2a4a70;
            border-radius:28px; padding:2rem 1.8rem;
            max-width:600px; width:100%;
            box-shadow:0 20px 40px -10px rgba(0,0,0,.7);
        }
        .card h2 { font-size:1.8rem; color:#3fe0a0; margin-bottom:1rem; }
        .card p { line-height:1.6; margin-bottom:1.2rem; color:#b0c2d9; }
        .info-footer {
            color:#6f7e95; font-size:.85rem; text-align:center;
            margin-top:1rem; border-top:1px solid #1e3a5f; padding-top:1.2rem;
        }
    </style>
</head>
<body>
    <h1>🌐 NetLab</h1>
    <div class="subtitle">Servidor educacional HTTP</div>
    <div class="nav">
        <a href="/">Início</a>
        <a href="/login">Login</a>
        <a href="/formulario">Formulário</a>
    </div>
    <div class="card">
        <h2>✅ Servidor ativo</h2>
        <p>Este ambiente simula um servidor web real para fins didáticos.
           Todas as requisições são monitoradas em tempo real no painel do NetLab.</p>
        <p>Utilize os links acima para gerar tráfego HTTP e visualize os dados
           sendo capturados.</p>
        <div class="info-footer">
            Acesse de outros dispositivos usando o IP exibido no painel do NetLab.
        </div>
    </div>
</body>
</html>"""

    PAGINA_FORMULARIO = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulário — NetLab</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family:'Segoe UI',Roboto,sans-serif;
            background:linear-gradient(145deg,#0a0f1e 0%,#0f1423 100%);
            color:#e0e4f0; min-height:100vh;
            display:flex; align-items:center; justify-content:center; padding:1.5rem;
        }
        .card {
            background:rgba(18,26,40,.95); border:1px solid #3b6ea0;
            border-radius:36px; padding:2.5rem 2rem; max-width:520px; width:100%;
            box-shadow:0 30px 50px -15px #0a1a2a;
        }
        h2 { color:#6ab0ff; font-size:2rem; font-weight:500;
             margin-bottom:1.5rem; text-align:center; }
        .aviso {
            background:#1a2a3a; border:1px solid #e77; border-radius:40px;
            padding:1rem; color:#ffbcbc; font-size:.9rem;
            text-align:center; margin-bottom:2rem;
        }
        form { display:flex; flex-direction:column; gap:1.2rem; }
        label { color:#a0b8d0; font-size:.85rem; font-weight:600;
                margin-left:.5rem; margin-bottom:-.5rem; }
        input {
            width:100%; padding:1rem 1.2rem; border-radius:40px;
            border:1px solid #2a4a70; background:#0d1a2a; color:#ecf0f1;
            font-size:1rem;
        }
        button {
            background:#2563EB; color:#fff; border:none; border-radius:40px;
            padding:1rem; font-size:1.2rem; font-weight:600; cursor:pointer;
            margin-top:.8rem;
        }
        button:hover { background:#3b82f6; }
        .voltar { display:block; text-align:center; margin-top:1.8rem;
                  color:#7f9fcf; text-decoration:none; font-size:.95rem; }
    </style>
</head>
<body>
    <div class="card">
        <h2>📋 Formulário</h2>
        <div class="aviso">⚠️ Dados enviados via HTTP — sem criptografia!</div>
        <form method="POST" action="/formulario">
            <label>Nome completo</label>
            <input type="text" name="nome" placeholder="Nome">
            <label>Telefone</label>
            <input type="text" name="telefone" placeholder="(00) 00000-0000">
            <label>Senha</label>
            <input type="password" name="senha" placeholder="Sua senha">
            <button type="submit">Enviar</button>
        </form>
        <a class="voltar" href="/">← Voltar ao início</a>
    </div>
</body>
</html>"""

    # ─────────────────────────────────────────────────────────────────────
    # Configuração do servidor
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def configurar_protecao(cls, ativar: bool, limite_req: int, tempo_bloqueio: int):
        """Ajusta os limites de proteção contra sobrecarga (DoS educacional)."""
        cls._protecao_ativa       = ativar
        cls._limite_req_por_seg   = limite_req
        cls._tempo_bloqueio       = tempo_bloqueio
        cls._contagem_por_ip.clear()
        cls._timestamps_por_ip.clear()
        cls._ips_bloqueados.clear()
        cls._ip_bloqueado_ate.clear()

    # ─────────────────────────────────────────────────────────────────────
    # Handlers de requisição
    # ─────────────────────────────────────────────────────────────────────

    def do_GET(self):
        """Serve as páginas HTML via GET e registra a requisição."""
        inicio = time.time()
        ip_cliente = self.client_address[0]

        permitido, ttl, reqs_atual = self._verificar_limite(ip_cliente)
        if not permitido:
            self._servir_bloqueado()
            self._registrar(ip_cliente, "GET", self.path, 0, inicio,
                            bloqueado=True, reqs_por_seg=reqs_atual)
            return

        if self.path == "/":
            corpo = self.PAGINA_INICIAL.encode("utf-8")
        elif self.path.startswith("/login"):
            corpo = self._html_login(ip_cliente).encode("utf-8")
        elif self.path.startswith("/signup"):
            corpo = self._html_signup().encode("utf-8")
        elif self.path == "/formulario":
            corpo = self.PAGINA_FORMULARIO.encode("utf-8")
        elif self.path == "/api/dados":
            corpo = b'{"status":"ok","servidor":"NetLab","protocolo":"HTTP","criptografado":false}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)
            self._registrar(ip_cliente, "GET", self.path, len(corpo), inicio)
            return
        elif self.path == "/ping":
            corpo = b'{"pong": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)
            self._registrar(ip_cliente, "GET", self.path, len(corpo), inicio)
            return
        else:
            corpo = b"<h1>404 - Pagina nao encontrada</h1>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)
            self._registrar(ip_cliente, "GET", self.path, len(corpo), inicio)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)
        self._registrar(ip_cliente, "GET", self.path, len(corpo), inicio)

    def do_POST(self):
        """Processa requisições POST e registra os dados enviados."""
        inicio     = time.time()
        ip_cliente = self.client_address[0]

        permitido, ttl, reqs_atual = self._verificar_limite(ip_cliente)
        if not permitido:
            self._servir_bloqueado()
            self._registrar(ip_cliente, "POST", self.path, 0, inicio,
                            bloqueado=True, reqs_por_seg=reqs_atual)
            return

        tamanho     = int(self.headers.get("Content-Length", 0))
        corpo_bytes = self.rfile.read(tamanho)

        if self.path.startswith("/login"):
            status, resposta, bloqueado = self._processar_login(corpo_bytes, ip_cliente)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(resposta)))
            self.end_headers()
            self.wfile.write(resposta)
            self._registrar(ip_cliente, "POST", self.path, tamanho, inicio,
                            corpo=corpo_bytes.decode("utf-8", errors="replace"),
                            bloqueado=bloqueado)
            return

        if self.path.startswith("/signup"):
            status, resposta, bloqueado = self._processar_cadastro(corpo_bytes, ip_cliente)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(resposta)))
            self.end_headers()
            self.wfile.write(resposta)
            self._registrar(ip_cliente, "POST", self.path, tamanho, inicio,
                            corpo=corpo_bytes.decode("utf-8", errors="replace"),
                            bloqueado=bloqueado)
            return

        # Formulário genérico
        resposta = (
            "<html><body style='background:#0f1423;color:#ecf0f1;"
            "font-family:Arial;padding:40px;'>"
            "<h2 style='color:#2ECC71;'>Dados recebidos pelo servidor!</h2>"
            "<p>O NetLab capturou este envio em tempo real.</p>"
            "<p style='color:#E74C3C;'>⚠️ Estes dados foram transmitidos "
            "via HTTP — visíveis para qualquer capturador na rede.</p>"
            "<a href='/' style='color:#3498DB;'>← Voltar</a>"
            "</body></html>"
        ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(resposta)))
        self.end_headers()
        self.wfile.write(resposta)
        self._registrar(ip_cliente, "POST", self.path, tamanho, inicio,
                        corpo=corpo_bytes.decode("utf-8", errors="replace"))

    # ─────────────────────────────────────────────────────────────────────
    # Login — apenas modo vulnerável (sem hash, sem bloqueio)
    # ─────────────────────────────────────────────────────────────────────

    def _html_login(self, ip: str) -> str:
        """Gera a página de login vulnerável com aviso didático visível."""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login — NetLab</title>
  <style>
    body {{
      font-family:'Segoe UI',Roboto,system-ui,sans-serif;
      background:linear-gradient(145deg,#0a0f1e 0%,#0f1423 100%);
      color:#e0e4f0; display:flex; justify-content:center; align-items:center;
      min-height:100vh; padding:16px;
    }}
    .card {{
      background:rgba(18,26,40,.95); border:1px solid #c03c3c;
      border-radius:28px; padding:28px 24px; max-width:440px; width:100%;
      box-shadow:0 20px 40px -10px rgba(0,0,0,.7);
    }}
    h1 {{ margin:0 0 8px; color:#ff8a8a; font-size:24px; }}
    .aviso {{
      margin-bottom:12px; color:#e74c3c; font-weight:600; font-size:13px;
      background:#2a1212; border:1px solid #b33; border-radius:8px;
      padding:8px 12px;
    }}
    form {{ display:flex; flex-direction:column; gap:10px; margin-top:12px; }}
    input {{ padding:10px 12px; border-radius:10px; border:1px solid #2a4a70;
             background:#0f1423; color:#e0e4f0; font-size:1rem; }}
    button {{ padding:12px; border:none; border-radius:12px;
              background:#e74c3c; color:#0f1423; font-weight:700; cursor:pointer; }}
    ul {{ color:#9fb2c8; font-size:13px; line-height:1.5; margin:8px 0 0 16px; }}
    .ip {{ color:#7f8fa3; font-size:12px; margin-top:8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Login educacional</h1>
    <div class="aviso">
      ⚠️ Modo vulnerável — senha em texto puro, sem proteção
    </div>
    <ul>
      <li>Senha armazenada sem criptografia</li>
      <li>Sem bloqueio por tentativas inválidas</li>
      <li>Credenciais visíveis na captura de pacotes</li>
    </ul>
    <form method="POST" action="/login">
      <input type="text" name="usuario" placeholder="Usuário" required>
      <input type="password" name="senha" placeholder="Senha numérica">
      <button type="submit">Entrar</button>
    </form>
    <div class="ip">Seu IP visto pelo servidor: {ip}</div>
    <div style="margin-top:12px;">
      <a style="color:#3498DB;" href="/signup">Criar conta</a>
    </div>
  </div>
</body>
</html>"""

    def _processar_login(self, corpo_bytes: bytes, ip: str):
        """
        Processa tentativa de login no modo vulnerável.
        Compara senhas diretamente em texto puro — sem qualquer proteção.
        Isso é intencional para fins educacionais: demonstra o perigo do HTTP.
        """
        dados   = parse_qs(corpo_bytes.decode("utf-8", errors="ignore"))
        usuario = dados.get("usuario", [""])[0]
        senha   = dados.get("senha",   [""])[0]

        senha_salva = self.__class__._usuarios_vuln.get(usuario, "")
        login_ok    = bool(senha) and senha == senha_salva

        resposta = self._html_resposta_login(
            sucesso=login_ok,
            mensagem="" if login_ok else "Usuário ou senha incorretos."
        )
        return (200 if login_ok else 401), resposta, False

    def _processar_cadastro(self, corpo_bytes: bytes, ip: str):
        """
        Cadastra novo usuário armazenando a senha em texto puro.
        Propositalmente vulnerável para demonstração educacional.
        """
        cls   = self.__class__
        dados = parse_qs(corpo_bytes.decode("utf-8", errors="ignore"))
        nome  = dados.get("usuario", [""])[0].strip()
        senha = dados.get("senha",   [""])[0].strip()

        if not re.fullmatch(r"[A-Za-zÀ-ÿ ]+", nome):
            resposta = self._html_resposta_login(
                False, mensagem="Nome deve conter apenas letras e espaços."
            )
            return 400, resposta, False

        if not senha.isdigit():
            resposta = self._html_resposta_login(
                False, mensagem="Senha deve conter apenas números."
            )
            return 400, resposta, False

        if nome in cls._usuarios_vuln:
            resposta = self._html_resposta_login(
                False, mensagem="Usuário já existe."
            )
            return 409, resposta, False

        # Armazena senha em texto puro (intencional — modo vulnerável)
        cls._usuarios_vuln[nome] = senha

        resposta = self._html_resposta_login(
            True, mensagem=f"Conta '{nome}' criada. Faça login em /login."
        )
        return 201, resposta, False

    def _html_resposta_login(self, sucesso: bool, mensagem: str = "") -> bytes:
        """Retorna HTML de resposta ao login/cadastro."""
        cor    = "#2ecc71" if sucesso else "#e74c3c"
        titulo = "Login permitido" if sucesso else "Acesso negado"
        detalhe = mensagem or ("Bem-vindo!" if sucesso else "Tente novamente.")
        html = f"""
        <html><body style='background:#0f1423;color:#ecf0f1;
                           font-family:Arial;padding:32px;'>
        <h2 style='color:{cor};'>{titulo}</h2>
        <p>{detalhe}</p>
        <a href='/login' style='color:#3498DB;'>← Voltar ao login</a>
        &nbsp;·&nbsp;
        <a href='/signup' style='color:#3498DB;'>Criar conta</a>
        </body></html>
        """
        return html.encode("utf-8")

    def _html_signup(self) -> str:
        """Gera a página de cadastro vulnerável com aviso didático."""
        return """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Criar conta — NetLab</title>
  <style>
    body {
      font-family:'Segoe UI',Roboto,system-ui,sans-serif;
      background:linear-gradient(145deg,#0a0f1e 0%,#0f1423 100%);
      color:#e0e4f0; display:flex; justify-content:center; align-items:center;
      min-height:100vh; padding:16px;
    }
    .card {
      background:rgba(18,26,40,.95); border:1px solid #1e3a5f;
      border-radius:28px; padding:28px 24px; max-width:440px; width:100%;
      box-shadow:0 20px 40px -10px rgba(0,0,0,.7);
    }
    h1 { margin:0 0 8px; color:#5a9eff; font-size:24px; }
    .aviso { margin-bottom:12px; color:#e74c3c; font-weight:600; }
    form { display:flex; flex-direction:column; gap:10px; margin-top:12px; }
    input { padding:10px 12px; border-radius:10px; border:1px solid #2a4a70;
            background:#0f1423; color:#e0e4f0; }
    button { padding:12px; border:none; border-radius:12px;
             background:#e74c3c; color:#0f1423; font-weight:700; cursor:pointer; }
    .tip { color:#9fb2c8; font-size:12px; margin-top:4px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Criar conta</h1>
    <div class="aviso">⚠️ Senha armazenada em texto puro</div>
    <form method="POST" action="/signup">
      <input type="text" name="usuario" placeholder="Nome (letras e espaço)"
             pattern="[A-Za-zÀ-ÿ ]+" required>
      <input type="password" name="senha" placeholder="Senha numérica"
             pattern="\\d+" required>
      <div class="tip">Nome: apenas letras e espaço. Senha: apenas números.</div>
      <button type="submit">Criar</button>
    </form>
    <div style="margin-top:12px;">
      <a style="color:#3498DB;" href="/login">Voltar ao login</a>
    </div>
  </div>
</body>
</html>"""

    # ─────────────────────────────────────────────────────────────────────
    # Rate limiting didático contra DoS (independente do login)
    # ─────────────────────────────────────────────────────────────────────

    def _verificar_limite(self, ip: str):
        """
        Aplica rate limit por IP (proteção didática opcional contra sobrecarga).
        Retorna (permitido, ttl_bloqueio, reqs_atual).
        """
        cls = self.__class__
        if not cls._protecao_ativa or cls._limite_req_por_seg <= 0:
            return True, 0, 0

        agora = time.time()
        with cls._lock:
            # Verifica bloqueio ativo
            expira = cls._ip_bloqueado_ate.get(ip, 0)
            if expira and expira > agora:
                return False, int(expira - agora), len(cls._timestamps_por_ip[ip])
            if expira and expira <= agora:
                cls._ips_bloqueados.discard(ip)
                cls._ip_bloqueado_ate.pop(ip, None)

            # Janela deslizante de 1 segundo
            cls._timestamps_por_ip[ip] = [
                t for t in cls._timestamps_por_ip[ip]
                if agora - t < 1.0
            ]
            cls._timestamps_por_ip[ip].append(agora)
            reqs_por_seg = len(cls._timestamps_por_ip[ip])

            if reqs_por_seg > cls._limite_req_por_seg:
                cls._ips_bloqueados.add(ip)
                cls._ip_bloqueado_ate[ip] = agora + cls._tempo_bloqueio
                sinais_servidor.alerta_emitido.emit(
                    f"🚫 IP {ip} bloqueado por {cls._tempo_bloqueio}s após "
                    f"{reqs_por_seg} req/s (limite: {cls._limite_req_por_seg} req/s)"
                )
                return False, cls._tempo_bloqueio, reqs_por_seg

        return True, 0, reqs_por_seg

    def _servir_bloqueado(self):
        """Retorna HTTP 429 quando o IP está bloqueado por excesso de requisições."""
        corpo = (
            b"<html><body style='background:#0f1423;color:#E74C3C;"
            b"font-family:Arial;padding:40px;text-align:center;'>"
            b"<h2>Acesso Bloqueado</h2>"
            b"<p>Seu IP foi temporariamente bloqueado por excesso de requisicoes.</p>"
            b"<p style='color:#7f8c8d;'>Esta e uma demonstracao educacional de "
            b"protecao contra DoS.</p>"
            b"</body></html>"
        )
        self.send_response(429)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Retry-After", str(self.__class__._tempo_bloqueio))
        self.end_headers()
        self.wfile.write(corpo)

    def _registrar(self, ip: str, metodo: str, path: str,
                   tamanho: int, inicio: float,
                   corpo: str = "", bloqueado: bool = False,
                   reqs_por_seg: Optional[int] = None):
        """Registra a requisição e emite sinal para a UI."""
        tempo_ms = int((time.time() - inicio) * 1000)
        agora    = time.time()
        cls      = self.__class__

        if reqs_por_seg is None:
            reqs_por_seg = len([
                t for t in cls._timestamps_por_ip[ip]
                if agora - t < 1.0
            ])

        cls._contagem_por_ip[ip] += 1

        # Alerta educacional quando há sobrecarga
        if reqs_por_seg >= 10:
            sinais_servidor.alerta_emitido.emit(
                f"⚠️ ALERTA: {ip} enviou {reqs_por_seg} requisições/segundo! "
                f"Possível teste de carga ou ataque DoS."
            )

        sinais_servidor.requisicao_recebida.emit({
            "timestamp":    datetime.now().strftime("%H:%M:%S"),
            "ip_cliente":   ip,
            "metodo":       metodo,
            "endpoint":     path,
            "tamanho":      tamanho,
            "user_agent":   self.headers.get("User-Agent", "—")[:50],
            "tempo_ms":     tempo_ms,
            "reqs_por_seg": reqs_por_seg,
            "bloqueado":    bloqueado,
            "corpo":        corpo[:500] if corpo else "",
        })

    def log_message(self, formato, *args):
        """Suprime saída padrão do HTTPServer no terminal."""
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Servidor HTTP multi-thread
# ─────────────────────────────────────────────────────────────────────────────

class ServidorHTTPThreaded(ThreadingMixIn, HTTPServer):
    """Servidor com suporte a múltiplas conexões simultâneas."""
    daemon_threads     = True
    request_queue_size = 64

    def handle_error(self, request, client_address):
        """Silencia erros esperados de conexões abruptas em testes de carga."""
        import sys
        exc_type, _, _ = sys.exc_info()
        if exc_type and issubclass(
            exc_type,
            (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)
        ):
            return
        return super().handle_error(request, client_address)


class ThreadServidor(threading.Thread):
    """Thread dedicada ao servidor HTTP — não bloqueia a interface Qt."""

    def __init__(self, porta: int):
        super().__init__(daemon=True)
        self.porta    = porta
        self._servidor: Optional[HTTPServer] = None

    def run(self):
        try:
            self._servidor = ServidorHTTPThreaded(
                ("0.0.0.0", self.porta),
                HandlerLabEducacional
            )
            sinais_servidor.status_alterado.emit(
                f"✅ Servidor iniciado na porta {self.porta}"
            )
            self._servidor.serve_forever()
        except Exception as erro:
            sinais_servidor.status_alterado.emit(
                f"❌ Erro ao iniciar servidor: {erro}"
            )

    def parar(self):
        if self._servidor:
            threading.Thread(
                target=self._servidor.shutdown,
                daemon=True
            ).start()


# ─────────────────────────────────────────────────────────────────────────────
# Painel da aba "Servidor de Laboratório"
# ─────────────────────────────────────────────────────────────────────────────

class PainelServidor(QWidget):
    """
    Aba 'Servidor de Laboratório' do NetLab Educacional.

    Permite ao professor:
    - Iniciar e parar um servidor HTTP de teste (sempre em modo vulnerável)
    - Monitorar requisições HTTP em tempo real
    - Ativar proteção didática contra DoS para demonstração de sobrecarga
    - Visualizar alertas de comportamento anômalo
    """

    # Sinal para a janela principal quando um cliente se conecta
    cliente_detectado = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread_servidor: Optional[ThreadServidor] = None
        self._servidor_ativo   = False
        self._total_requisicoes = 0
        self._total_bytes       = 0
        self._reqs_por_segundo  = 0
        self._contador_segundo  = 0
        self._clientes_unicos   = set()

        # Valores padrão dos controles
        self._porta_atual  = 8080
        self._limite_atual = 10
        self._tempo_atual  = 30

        # Timer para contar req/s
        self._timer_metricas = QTimer()
        self._timer_metricas.timeout.connect(self._atualizar_metricas_por_segundo)

        # Conecta sinais do servidor à interface
        sinais_servidor.requisicao_recebida.connect(self._ao_receber_requisicao)
        sinais_servidor.status_alterado.connect(self._ao_mudar_status)
        sinais_servidor.alerta_emitido.connect(self._ao_emitir_alerta)

        self._montar_layout()

    # ─────────────────────────────────────────────────────────────────────
    # Montagem da interface
    # ─────────────────────────────────────────────────────────────────────

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 4)
        layout.setSpacing(4)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        splitter.addWidget(self._criar_painel_controles())
        splitter.addWidget(self._criar_painel_requisicoes())
        splitter.setSizes([380, 700])

    def _criar_painel_controles(self) -> QWidget:
        """Painel esquerdo: controles, status, métricas e proteção DoS."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)

        layout.addWidget(self._criar_grupo_configuracao())
        layout.addWidget(self._criar_grupo_status())
        layout.addWidget(self._criar_grupo_metricas())
        layout.addWidget(self._criar_grupo_protecao_dos())
        layout.addStretch()

        return widget

    def _criar_grupo_configuracao(self) -> QGroupBox:
        grp = QGroupBox("⚙️ Configuração")
        grp.setStyleSheet(self._estilo_grupo())
        layout = QGridLayout(grp)

        lbl_porta = QLabel("Porta:")
        lbl_porta.setStyleSheet("color:#ecf0f1; font-size:11px;")
        layout.addWidget(lbl_porta, 0, 0)

        # Controle de porta
        container_porta = QWidget()
        container_porta.setFixedHeight(30)
        hbox = QHBoxLayout(container_porta)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(2)

        btn_menos = self._criar_botao_controle("−", "#3498db", 18, 18)
        btn_menos.clicked.connect(lambda: self._ajustar_valor("porta", -1))
        hbox.addWidget(btn_menos)

        self.lbl_porta = QLabel(str(self._porta_atual))
        self.lbl_porta.setFixedSize(50, 25)
        self.lbl_porta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_porta.setStyleSheet(
            "background:#0d1a2a; color:#ecf0f1; border:1px solid #3498db;"
            "border-radius:4px; font-size:12px; font-weight:bold;"
        )
        hbox.addWidget(self.lbl_porta)

        btn_mais = self._criar_botao_controle("+", "#3498db", 18, 18)
        btn_mais.clicked.connect(lambda: self._ajustar_valor("porta", 1))
        hbox.addWidget(btn_mais)

        layout.addWidget(container_porta, 0, 1)

        self.btn_iniciar = QPushButton("▶  Iniciar Servidor")
        self.btn_iniciar.setObjectName("botao_captura")
        self.btn_iniciar.setMinimumHeight(32)
        self.btn_iniciar.clicked.connect(self._alternar_servidor)
        layout.addWidget(self.btn_iniciar, 1, 0, 1, 2)

        return grp

    def _criar_grupo_status(self) -> QGroupBox:
        grp = QGroupBox("📡 Status do Servidor")
        grp.setStyleSheet(self._estilo_grupo())
        layout = QVBoxLayout(grp)

        self.lbl_status = QLabel("⏹️  Servidor parado")
        self.lbl_status.setStyleSheet("color:#E74C3C; font-weight:bold; font-size:11px;")
        layout.addWidget(self.lbl_status)

        self.lbl_endereco = QTextEdit()
        self.lbl_endereco.setReadOnly(True)
        self.lbl_endereco.setMaximumHeight(50)
        self.lbl_endereco.setStyleSheet(
            "color:#3498DB; font-family:Consolas; font-size:11px;"
            "background:#0d1a2a; border:1px solid #1e3a5f; border-radius:4px; padding:6px;"
        )
        self.lbl_endereco.setText("—")
        layout.addWidget(self.lbl_endereco)

        instrucao = QLabel(
            "Após iniciar, acesse o endereço acima\n"
            "de qualquer dispositivo na mesma rede Wi-Fi."
        )
        instrucao.setStyleSheet("color:#7f8c8d; font-size:10px;")
        instrucao.setWordWrap(True)
        layout.addWidget(instrucao)

        return grp

    def _criar_grupo_metricas(self) -> QGroupBox:
        grp = QGroupBox("📊 Métricas em Tempo Real")
        grp.setStyleSheet(self._estilo_grupo())
        layout = QGridLayout(grp)

        def _card(rotulo: str, valor: str, cor: str):
            lbl_r = QLabel(rotulo)
            lbl_r.setStyleSheet(f"color:{cor}; font-size:9px; font-weight:bold;")
            lbl_v = QLabel(valor)
            lbl_v.setStyleSheet("color:#ecf0f1; font-size:16px; font-weight:bold;")
            lbl_v.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_r.setAlignment(Qt.AlignmentFlag.AlignCenter)
            return lbl_r, lbl_v

        lbl_r1, self.lbl_total_reqs  = _card("TOTAL REQS", "0",   "#3498DB")
        lbl_r2, self.lbl_reqs_seg    = _card("REQS/SEG",   "0",   "#E74C3C")
        lbl_r3, self.lbl_total_bytes = _card("DADOS",      "0 B", "#2ECC71")
        lbl_r4, self.lbl_clientes    = _card("CLIENTES",   "0",   "#9B59B6")

        for col, (lr, lv) in enumerate([
            (lbl_r1, self.lbl_total_reqs),
            (lbl_r2, self.lbl_reqs_seg),
            (lbl_r3, self.lbl_total_bytes),
            (lbl_r4, self.lbl_clientes),
        ]):
            frame = QFrame()
            frame.setStyleSheet(
                "QFrame { background:#0d1a2a; border:1px solid #1e3a5f; border-radius:6px; }"
            )
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(4, 4, 4, 4)
            fl.addWidget(lr)
            fl.addWidget(lv)
            layout.addWidget(frame, 0, col)

        # Barra de carga visual
        self.barra_carga = QProgressBar()
        self.barra_carga.setRange(0, 50)
        self.barra_carga.setValue(0)
        self.barra_carga.setTextVisible(False)
        self.barra_carga.setStyleSheet("""
            QProgressBar { background:#0d1a2a; border:1px solid #1e3a5f;
                           border-radius:4px; height:12px; }
            QProgressBar::chunk { background:#3498DB; border-radius:3px; }
        """)
        layout.addWidget(QLabel("Carga do servidor:"), 1, 0, 1, 2)
        layout.addWidget(self.barra_carga, 1, 2, 1, 2)

        return grp

    def _criar_grupo_protecao_dos(self) -> QGroupBox:
        """Grupo de proteção didática contra DoS (independente do login)."""
        grp = QGroupBox("🛡️ Proteção Didática (Demo DoS)")
        grp.setStyleSheet(
            "QGroupBox { border:1px solid #E67E22; border-radius:6px;"
            " margin-top:3px; font-weight:bold; color:#E67E22; }"
            "QGroupBox::title { subcontrol-origin:margin; padding:0 3px; }"
        )
        layout = QVBoxLayout(grp)
        layout.setSpacing(8)

        # Checkbox de ativação
        self.chk_protecao = QCheckBox("Ativar proteção rate limiting")
        self.chk_protecao.setStyleSheet("color:#ecf0f1; font-size:11px;")
        self.chk_protecao.stateChanged.connect(self._ao_mudar_protecao)
        layout.addWidget(self.chk_protecao)

        # Grid de controles
        container = QWidget()
        grid = QGridLayout(container)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setVerticalSpacing(6)
        grid.setHorizontalSpacing(8)

        # Limite req/s
        lbl_limite = QLabel("Limite req/s por IP:")
        lbl_limite.setStyleSheet("color:#ecf0f1; font-size:11px;")
        grid.addWidget(lbl_limite, 0, 0, Qt.AlignmentFlag.AlignVCenter)

        container_limite = QWidget()
        hbox_limite = QHBoxLayout(container_limite)
        hbox_limite.setContentsMargins(0, 0, 0, 0)
        hbox_limite.setSpacing(2)

        self.btn_limite_menos = self._criar_botao_controle("−", "#E67E22", 16, 16)
        self.btn_limite_menos.setEnabled(False)
        self.btn_limite_menos.clicked.connect(lambda: self._ajustar_valor("limite", -1))
        hbox_limite.addWidget(self.btn_limite_menos)

        self.lbl_limite = QLabel(str(self._limite_atual))
        self.lbl_limite.setFixedSize(35, 18)
        self.lbl_limite.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_limite.setStyleSheet(
            "background:#0d1a2a; color:#ecf0f1; border:1px solid #E67E22;"
            "border-radius:4px; font-size:11px; font-weight:bold; padding:3px;"
        )
        hbox_limite.addWidget(self.lbl_limite)

        self.btn_limite_mais = self._criar_botao_controle("+", "#E67E22", 16, 16)
        self.btn_limite_mais.setEnabled(False)
        self.btn_limite_mais.clicked.connect(lambda: self._ajustar_valor("limite", 1))
        hbox_limite.addWidget(self.btn_limite_mais)

        grid.addWidget(container_limite, 0, 1, Qt.AlignmentFlag.AlignLeft)

        # Tempo de bloqueio
        lbl_tempo = QLabel("Tempo de bloqueio (s):")
        lbl_tempo.setStyleSheet("color:#ecf0f1; font-size:11px;")
        grid.addWidget(lbl_tempo, 1, 0, Qt.AlignmentFlag.AlignVCenter)

        container_tempo = QWidget()
        hbox_tempo = QHBoxLayout(container_tempo)
        hbox_tempo.setContentsMargins(0, 0, 0, 0)
        hbox_tempo.setSpacing(2)

        self.btn_tempo_menos = self._criar_botao_controle("−", "#E67E22", 16, 16)
        self.btn_tempo_menos.setEnabled(False)
        self.btn_tempo_menos.clicked.connect(lambda: self._ajustar_valor("tempo", -1))
        hbox_tempo.addWidget(self.btn_tempo_menos)

        self.lbl_tempo = QLabel(str(self._tempo_atual))
        self.lbl_tempo.setFixedSize(35, 18)
        self.lbl_tempo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_tempo.setStyleSheet(
            "background:#0d1a2a; color:#ecf0f1; border:1px solid #E67E22;"
            "border-radius:4px; font-size:11px; font-weight:bold; padding:3px;"
        )
        hbox_tempo.addWidget(self.lbl_tempo)

        self.btn_tempo_mais = self._criar_botao_controle("+", "#E67E22", 16, 16)
        self.btn_tempo_mais.setEnabled(False)
        self.btn_tempo_mais.clicked.connect(lambda: self._ajustar_valor("tempo", 1))
        hbox_tempo.addWidget(self.btn_tempo_mais)

        grid.addWidget(container_tempo, 1, 1, Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(container)

        # Botão desbloquear IPs
        self.btn_desbloquear = QPushButton("🔓 Desbloquear todos os IPs")
        self.btn_desbloquear.setFixedHeight(20)
        self.btn_desbloquear.setStyleSheet(
            "QPushButton { background:#1e3a5f; color:#ecf0f1; border:none;"
            " border-radius:4px; padding:0; font-size:11px; }"
            "QPushButton:hover { background:#2a5080; }"
        )
        self.btn_desbloquear.clicked.connect(self._desbloquear_ips)
        layout.addWidget(self.btn_desbloquear)

        return grp

    def _criar_painel_requisicoes(self) -> QWidget:
        """Painel direito: tabela de requisições e log de alertas."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(6)

        splitter_v = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter_v)

        # Tabela de requisições
        w_tab = QWidget()
        l_tab = QVBoxLayout(w_tab)
        l_tab.setContentsMargins(0, 0, 0, 0)

        lbl = QLabel("  📋 Requisições Recebidas em Tempo Real")
        fonte = QFont("Arial", 10)
        fonte.setBold(True)
        lbl.setFont(fonte)
        lbl.setStyleSheet("color:#bdc3c7;")
        l_tab.addWidget(lbl)

        self.tabela_reqs = QTableWidget(0, 8)
        self.tabela_reqs.setHorizontalHeaderLabels([
            "Hora", "IP", "Método", "Endpoint",
            "Tamanho", "User-Agent", "Tempo(ms)", "Req/s",
        ])
        self.tabela_reqs.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_reqs.horizontalHeader().setStretchLastSection(True)
        self.tabela_reqs.verticalHeader().setVisible(False)
        self.tabela_reqs.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tabela_reqs.setAlternatingRowColors(True)
        l_tab.addWidget(self.tabela_reqs)
        splitter_v.addWidget(w_tab)

        # Área de alertas educacionais
        w_alertas = QWidget()
        l_alertas = QVBoxLayout(w_alertas)
        l_alertas.setContentsMargins(0, 0, 0, 0)

        lbl_alerta = QLabel("⚠️  Alertas Didáticos")
        lbl_alerta.setStyleSheet("color:#E67E22; font-weight:bold; font-size:10px;")
        l_alertas.addWidget(lbl_alerta)

        self.texto_alertas = QTextEdit()
        self.texto_alertas.setReadOnly(True)
        self.texto_alertas.setMaximumHeight(140)
        self.texto_alertas.setStyleSheet(
            "QTextEdit { background:#0a0f1a; color:#ecf0f1;"
            " border:1px solid #1e3a5f; border-radius:4px; padding:6px;"
            " font-family:Consolas; font-size:10px; }"
        )
        self.texto_alertas.setPlaceholderText(
            "Alertas sobre comportamento do tráfego aparecerão aqui…"
        )
        l_alertas.addWidget(self.texto_alertas)
        splitter_v.addWidget(w_alertas)
        splitter_v.setSizes([500, 140])

        return widget

    # ─────────────────────────────────────────────────────────────────────
    # Controle do servidor
    # ─────────────────────────────────────────────────────────────────────

    def _alternar_servidor(self):
        if self._servidor_ativo:
            self._parar_servidor()
        else:
            self._iniciar_servidor()

    def _iniciar_servidor(self):
        porta = self._porta_atual

        # Reinicia contadores e estado do handler
        HandlerLabEducacional._contagem_por_ip.clear()
        HandlerLabEducacional._timestamps_por_ip.clear()
        HandlerLabEducacional._ips_bloqueados.clear()
        HandlerLabEducacional._ip_bloqueado_ate.clear()
        HandlerLabEducacional._limite_req_por_seg = self._limite_atual
        HandlerLabEducacional._tempo_bloqueio     = self._tempo_atual

        self._total_requisicoes = 0
        self._total_bytes       = 0
        self._clientes_unicos   = set()

        self._thread_servidor = ThreadServidor(porta)
        self._thread_servidor.start()

        self._servidor_ativo = True
        self.btn_iniciar.setText("⏹  Parar Servidor")
        self.btn_iniciar.setObjectName("botao_parar")
        self._repolir(self.btn_iniciar)

        ip_local = self._obter_ip_local()
        self.lbl_status.setText("✅  Servidor ativo")
        self.lbl_status.setStyleSheet("color:#2ECC71; font-weight:bold; font-size:11px;")
        self.lbl_endereco.setText(f"http://{ip_local}:{porta}/login")

        self._timer_metricas.start(1000)
        self._adicionar_alerta("INFO",
            f"Servidor iniciado em http://{ip_local}:{porta}. "
            f"Aguardando requisições…"
        )

    def _parar_servidor(self):
        self._timer_metricas.stop()
        if self._thread_servidor:
            self._thread_servidor.parar()

        self._servidor_ativo = False
        self.btn_iniciar.setText("▶  Iniciar Servidor")
        self.btn_iniciar.setObjectName("botao_captura")
        self._repolir(self.btn_iniciar)

        self.lbl_status.setText("⏹️  Servidor parado")
        self.lbl_status.setStyleSheet("color:#E74C3C; font-weight:bold; font-size:11px;")
        self.lbl_endereco.setText("—")
        self.barra_carga.setValue(0)
        self.lbl_reqs_seg.setText("0")

        self._adicionar_alerta("INFO", "Servidor parado.")

    # ─────────────────────────────────────────────────────────────────────
    # Slots de dados
    # ─────────────────────────────────────────────────────────────────────

    def _ajustar_valor(self, tipo: str, delta: int):
        """Ajusta os controles numéricos (porta, limite, tempo)."""
        if tipo == "porta":
            novo = self._porta_atual + delta
            if 1024 <= novo <= 65535:
                self._porta_atual = novo
                self.lbl_porta.setText(str(novo))

        elif tipo == "limite" and self.chk_protecao.isChecked():
            novo = self._limite_atual + delta
            if 1 <= novo <= 100:
                self._limite_atual = novo
                self.lbl_limite.setText(str(novo))
                HandlerLabEducacional._limite_req_por_seg = novo

        elif tipo == "tempo" and self.chk_protecao.isChecked():
            novo = self._tempo_atual + delta
            if 5 <= novo <= 300:
                self._tempo_atual = novo
                self.lbl_tempo.setText(str(novo))
                HandlerLabEducacional._tempo_bloqueio = novo

    def _ao_receber_requisicao(self, dados: dict):
        """Adiciona linha na tabela para cada requisição recebida."""
        self._total_requisicoes += 1
        self._total_bytes       += dados.get("tamanho", 0)
        self._contador_segundo  += 1

        ip = dados.get("ip_cliente", "")
        self._clientes_unicos.add(ip)
        if ip:
            self.cliente_detectado.emit(ip)

        # Insere no topo da tabela
        self.tabela_reqs.insertRow(0)
        reqs_seg = dados.get("reqs_por_seg", 0)
        itens = [
            dados.get("timestamp", ""),
            ip,
            dados.get("metodo", ""),
            dados.get("endpoint", ""),
            f"{dados.get('tamanho', 0)} bytes",
            dados.get("user_agent", "—")[:20],
            f"{dados.get('tempo_ms', 0)}",
            str(reqs_seg),
        ]
        for col, texto in enumerate(itens):
            item = QTableWidgetItem(texto)
            if dados.get("bloqueado"):
                item.setForeground(QColor("#E74C3C"))
                item.setBackground(QColor("#1a0a00"))
            elif reqs_seg >= 10:
                item.setForeground(QColor("#E67E22"))
            self.tabela_reqs.setItem(0, col, item)

        # Limita a 100 linhas visíveis
        while self.tabela_reqs.rowCount() > 100:
            self.tabela_reqs.removeRow(100)

        # Atualiza métricas
        self.lbl_total_reqs.setText(f"{self._total_requisicoes:,}")
        kb = self._total_bytes / 1024
        self.lbl_total_bytes.setText(
            f"{kb/1024:.1f} MB" if kb > 1024 else f"{kb:.1f} KB"
        )
        self.lbl_clientes.setText(str(len(self._clientes_unicos)))

        # Alerta quando dados sensíveis são enviados via POST
        corpo = dados.get("corpo", "")
        if corpo and dados.get("metodo") == "POST":
            self._adicionar_alerta("AVISO", f"POST de {ip}: {corpo[:80]}")

    def _ao_mudar_status(self, mensagem: str):
        self.lbl_status.setText(mensagem)

    def _ao_emitir_alerta(self, mensagem: str):
        tipo = (
            "CRÍTICO"
            if "bloqueado" in mensagem.lower() or "ataque" in mensagem.lower()
            else "AVISO"
        )
        self._adicionar_alerta(tipo, mensagem)

    def _adicionar_alerta(self, tipo: str, mensagem: str):
        """Exibe alerta colorido no log educacional."""
        cores = {"INFO": "#3498DB", "AVISO": "#E67E22", "CRÍTICO": "#E74C3C"}
        hora  = datetime.now().strftime("%H:%M:%S")
        cor   = cores.get(tipo, "#ecf0f1")
        html  = (
            f"<span style='color:{cor};font-size:10px;'>"
            f"[{hora}] [{tipo}] {mensagem}</span><br>"
        )
        self.texto_alertas.insertHtml(html)

        # Limita o log a 50 linhas
        if self.texto_alertas.document().lineCount() > 50:
            cursor = self.texto_alertas.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.movePosition(
                cursor.MoveOperation.Down,
                cursor.MoveMode.KeepAnchor,
                10
            )
            cursor.removeSelectedText()

    def _ao_mudar_protecao(self, estado):
        """Ativa ou desativa o rate limiting educacional."""
        ativo = (estado == Qt.CheckState.Checked.value)
        HandlerLabEducacional._protecao_ativa = ativo

        self.btn_limite_menos.setEnabled(ativo)
        self.btn_limite_mais.setEnabled(ativo)
        self.btn_tempo_menos.setEnabled(ativo)
        self.btn_tempo_mais.setEnabled(ativo)

        if ativo:
            HandlerLabEducacional._limite_req_por_seg = self._limite_atual
            HandlerLabEducacional._tempo_bloqueio     = self._tempo_atual
        else:
            self._desbloquear_ips()

    def _desbloquear_ips(self):
        """Remove todos os bloqueios de IP ativos."""
        HandlerLabEducacional._ips_bloqueados.clear()
        HandlerLabEducacional._ip_bloqueado_ate.clear()
        self._adicionar_alerta("INFO", "Todos os IPs foram desbloqueados.")

    # ─────────────────────────────────────────────────────────────────────
    # Utilitários internos
    # ─────────────────────────────────────────────────────────────────────

    @staticmethod
    def _obter_ip_local() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def _estilo_grupo() -> str:
        return (
            "QGroupBox { border:1px solid #1e3a5f; border-radius:6px;"
            " margin-top:8px; font-weight:bold; color:#bdc3c7; }"
            "QGroupBox::title { subcontrol-origin:margin; padding:0 6px; }"
        )

    @staticmethod
    def _criar_botao_controle(
        texto: str, cor: str, largura: int, altura: int
    ) -> QPushButton:
        """Cria botão +/− padronizado para os controles numéricos."""
        btn = QPushButton(texto)
        btn.setFixedSize(largura, altura)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:#2c3e50; color:white;
                border:1px solid {cor}; border-radius:4px;
                font-size:14px; font-weight:bold; padding:0;
            }}
            QPushButton:hover  {{ background:#34495e; border:2px solid {cor}; }}
            QPushButton:pressed {{ background:#1e2b3a; }}
            QPushButton:disabled {{ background:#2c3e50; color:#7f8c8d;
                                    border:1px solid #7f8c8d; }}
        """)
        return btn

    @staticmethod
    def _repolir(widget):
        """Força o Qt a reaplicar o estilo visual do widget."""
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def _atualizar_metricas_por_segundo(self):
        """Atualiza contador de req/s e barra de carga."""
        self.lbl_reqs_seg.setText(str(self._contador_segundo))
        self.barra_carga.setValue(min(self._contador_segundo, 50))
        self._contador_segundo = 0