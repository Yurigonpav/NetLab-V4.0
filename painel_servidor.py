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
    :root {
        color-scheme: dark;
        --bg: #07111c;
        --bg-alt: #0c1b2b;
        --panel: rgba(10, 20, 33, 0.88);
        --panel-strong: rgba(15, 31, 48, 0.96);
        --line: rgba(112, 178, 255, 0.16);
        --line-strong: rgba(112, 178, 255, 0.32);
        --text: #edf4ff;
        --muted: #9cb5d1;
        --accent: #5ec6ff;
        --accent-strong: #1492df;
        --accent-soft: rgba(94, 198, 255, 0.14);
        --success: #42d392;
        --danger: #ff8d8d;
        --warning: #ffd36a;
        --shadow: 0 24px 60px rgba(0, 0, 0, 0.34);
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: "Segoe UI", "Trebuchet MS", sans-serif;
        background:
            radial-gradient(circle at top left, rgba(94, 198, 255, 0.15), transparent 32%),
            radial-gradient(circle at top right, rgba(66, 211, 146, 0.10), transparent 28%),
            linear-gradient(180deg, #06101a 0%, #091522 45%, #050d15 100%);
        color: var(--text);
        min-height: 100vh;
        padding: 24px;
    }
    body::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background:
            linear-gradient(120deg, rgba(94, 198, 255, 0.04), transparent 44%),
            linear-gradient(300deg, rgba(66, 211, 146, 0.03), transparent 38%);
    }
    .page-shell {
        position: relative;
        z-index: 1;
        width: min(1120px, 100%);
        margin: 0 auto;
    }
    .topbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 16px;
        justify-content: space-between;
        padding: 18px 22px;
        margin-bottom: 24px;
        border: 1px solid var(--line);
        border-radius: 22px;
        background: rgba(8, 18, 29, 0.84);
        backdrop-filter: blur(18px);
        box-shadow: var(--shadow);
    }
    .brand-block {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .brand-mark {
        width: 48px;
        height: 48px;
        border-radius: 14px;
        display: grid;
        place-items: center;
        font-weight: 700;
        letter-spacing: 0.08em;
        color: #f7fbff;
        background: linear-gradient(135deg, #1fb0ec 0%, #0d5f94 100%);
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.18);
    }
    .brand-copy {
        display: flex;
        flex-direction: column;
        gap: 3px;
    }
    .brand-kicker {
        font-size: 11px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.14em;
    }
    .brand-copy strong {
        font-size: 18px;
        font-weight: 600;
        color: var(--text);
    }
    .nav-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
    }
    .nav-link {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 10px 14px;
        border-radius: 999px;
        border: 1px solid transparent;
        background: rgba(255, 255, 255, 0.03);
        color: var(--muted);
        text-decoration: none;
        font-size: 13px;
        transition: 0.2s ease;
    }
    .nav-link:hover {
        color: var(--text);
        border-color: var(--line-strong);
        background: rgba(255, 255, 255, 0.08);
        text-decoration: none;
    }
    .nav-link.active {
        color: var(--text);
        border-color: rgba(94, 198, 255, 0.42);
        background: linear-gradient(180deg, rgba(94, 198, 255, 0.22), rgba(20, 146, 223, 0.10));
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.10);
    }
    .nav-session {
        margin-left: auto;
        padding: 10px 14px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: rgba(255, 255, 255, 0.04);
        color: var(--muted);
        font-size: 13px;
    }
    .nav-session strong { color: var(--text); }
    .nav-session a { color: var(--accent); }
    .page-content {
        display: flex;
        flex-direction: column;
        gap: 22px;
    }
    .hero {
        display: grid;
        grid-template-columns: minmax(0, 1.3fr) minmax(300px, 0.9fr);
        gap: 20px;
        padding: 30px;
        border-radius: 26px;
        border: 1px solid var(--line);
        background: linear-gradient(180deg, rgba(16, 34, 53, 0.92), rgba(8, 18, 29, 0.92));
        box-shadow: var(--shadow);
    }
    .hero-panel,
    .card {
        border-radius: 22px;
        border: 1px solid var(--line);
        background: var(--panel);
        box-shadow: var(--shadow);
    }
    .hero-panel {
        padding: 22px;
    }
    .card {
        padding: 24px;
    }
    .eyebrow {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 16px;
        color: var(--accent);
        font-size: 11px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
    }
    .eyebrow::before {
        content: "";
        width: 26px;
        height: 1px;
        background: currentColor;
        opacity: 0.85;
    }
    h1 {
        color: var(--text);
        font-size: clamp(30px, 4vw, 44px);
        line-height: 1.06;
        margin-bottom: 14px;
    }
    h2 {
        color: var(--text);
        font-size: 22px;
        margin-bottom: 12px;
    }
    h3 {
        color: var(--muted);
        font-size: 13px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 10px;
    }
    p, li {
        color: var(--muted);
        line-height: 1.65;
    }
    .lead {
        max-width: 60ch;
        font-size: 16px;
    }
    .compact-lead {
        font-size: 15px;
    }
    .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 22px;
    }
    .primary-link,
    .ghost-link,
    button,
    input[type=submit] {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 44px;
        padding: 11px 18px;
        border-radius: 999px;
        border: 1px solid transparent;
        text-decoration: none;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: 0.2s ease;
    }
    .primary-link,
    input[type=submit] {
        color: #07111c;
        background: linear-gradient(135deg, #76d6ff 0%, #3eb7ff 100%);
        border-color: rgba(255, 255, 255, 0.08);
    }
    .ghost-link,
    button {
        color: var(--text);
        background: rgba(255, 255, 255, 0.05);
        border-color: var(--line);
    }
    .primary-link:hover,
    input[type=submit]:hover {
        transform: translateY(-1px);
        box-shadow: 0 12px 28px rgba(62, 183, 255, 0.26);
        text-decoration: none;
    }
    .ghost-link:hover,
    button:hover {
        background: rgba(255, 255, 255, 0.09);
        border-color: var(--line-strong);
        text-decoration: none;
    }
    .grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 20px;
    }
    .auth-grid {
        display: grid;
        grid-template-columns: minmax(260px, 0.95fr) minmax(0, 1.05fr);
        gap: 20px;
    }
    .comment-layout {
        display: grid;
        grid-template-columns: minmax(320px, 0.95fr) minmax(0, 1.15fr);
        gap: 20px;
    }
    .feature-list,
    .meta-list {
        list-style: none;
        display: flex;
        flex-direction: column;
        gap: 12px;
    }
    .feature-list li,
    .meta-list li {
        padding: 12px 14px;
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: rgba(255, 255, 255, 0.03);
    }
    .stat-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 12px;
        margin-top: 18px;
    }
    .stat {
        padding: 14px;
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: rgba(255, 255, 255, 0.04);
    }
    .stat strong {
        display: block;
        color: var(--text);
        font-size: 20px;
        margin-bottom: 6px;
    }
    .stat span {
        color: var(--muted);
        font-size: 12px;
    }
    .aviso,
    .info,
    .sucesso {
        padding: 12px 14px;
        border-radius: 16px;
        margin-bottom: 16px;
        border: 1px solid transparent;
        font-size: 13px;
    }
    .aviso {
        background: rgba(255, 141, 141, 0.10);
        border-color: rgba(255, 141, 141, 0.24);
        color: #ffb1b1;
    }
    .info {
        background: rgba(94, 198, 255, 0.11);
        border-color: rgba(94, 198, 255, 0.22);
        color: #a7ddff;
    }
    .sucesso {
        background: rgba(66, 211, 146, 0.10);
        border-color: rgba(66, 211, 146, 0.24);
        color: #9ff0c6;
    }
    form {
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 100%;
    }
    label {
        color: var(--muted);
        font-size: 12px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    input[type=text], input[type=password], input[type=email], textarea {
        width: 100%;
        padding: 13px 14px;
        border-radius: 16px;
        border: 1px solid rgba(130, 185, 255, 0.18);
        background: rgba(4, 10, 16, 0.42);
        color: var(--text);
        font-size: 14px;
        font-family: inherit;
        outline: none;
        transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
    }
    input[type=text]:focus, input[type=password]:focus, input[type=email]:focus, textarea:focus {
        border-color: rgba(94, 198, 255, 0.48);
        box-shadow: 0 0 0 4px rgba(94, 198, 255, 0.10);
        background: rgba(4, 10, 16, 0.56);
    }
    textarea {
        min-height: 180px;
        resize: vertical;
    }
    .helper-line {
        margin-top: 14px;
        font-size: 13px;
        color: var(--muted);
    }
    .section-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 16px;
    }
    .pill {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 7px 11px;
        border-radius: 999px;
        border: 1px solid rgba(94, 198, 255, 0.22);
        background: rgba(94, 198, 255, 0.10);
        color: var(--accent);
        font-size: 12px;
        white-space: nowrap;
    }
    .comment-feed {
        display: flex;
        flex-direction: column;
        gap: 14px;
        max-height: 620px;
        overflow-y: auto;
        padding-right: 4px;
    }
    .comentario-item {
        padding: 16px;
        border-radius: 18px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: rgba(255, 255, 255, 0.03);
    }
    .comentario-autor {
        color: var(--muted);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .empty-state {
        padding: 18px;
        border-radius: 18px;
        border: 1px dashed rgba(156, 181, 209, 0.24);
        background: rgba(255, 255, 255, 0.02);
        color: var(--muted);
        text-align: center;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
        overflow: hidden;
        border-radius: 18px;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }
    th {
        background: rgba(255, 255, 255, 0.06);
        color: var(--muted);
        padding: 10px 12px;
        text-align: left;
    }
    td {
        padding: 10px 12px;
        border-top: 1px solid rgba(255, 255, 255, 0.05);
        color: var(--text);
    }
    tr:hover td {
        background: rgba(255, 255, 255, 0.03);
    }
    code, pre {
        border-radius: 14px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: rgba(0, 0, 0, 0.28);
    }
    code {
        padding: 3px 7px;
        color: var(--accent);
        font-family: Consolas, monospace;
        font-size: 12px;
    }
    pre {
        padding: 14px;
        color: #b7ffcf;
        font-family: Consolas, monospace;
        font-size: 12px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-word;
    }
    .badge {
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        padding: 5px 9px;
        font-size: 11px;
        font-weight: 700;
        border: 1px solid transparent;
    }
    .badge-sqli  { background: rgba(230, 126, 34, 0.10); color: #ffb16c; border-color: rgba(230, 126, 34, 0.30); }
    .badge-xss   { background: rgba(39, 174, 96, 0.10); color: #8aefb2; border-color: rgba(39, 174, 96, 0.30); }
    .badge-idor  { background: rgba(155, 89, 182, 0.10); color: #d0a8ef; border-color: rgba(155, 89, 182, 0.30); }
    .badge-csrf  { background: rgba(241, 196, 15, 0.10); color: #ffe48f; border-color: rgba(241, 196, 15, 0.30); }
    .badge-brute { background: rgba(149, 165, 166, 0.10); color: #d5dcdd; border-color: rgba(149, 165, 166, 0.30); }
    .badge-info  { background: rgba(52, 152, 219, 0.10); color: #9bdcff; border-color: rgba(52, 152, 219, 0.30); }
    a {
        color: var(--accent);
        text-decoration: none;
    }
    a:hover { text-decoration: underline; }
    @media (max-width: 920px) {
        body { padding: 16px; }
        .hero,
        .grid,
        .auth-grid,
        .comment-layout {
            grid-template-columns: 1fr;
        }
        .nav-session {
            width: 100%;
            margin-left: 0;
        }
    }
    @media (max-width: 640px) {
        .topbar,
        .hero,
        .card,
        .hero-panel {
            padding: 18px;
        }
        .nav-strip {
            width: 100%;
        }
        .nav-link {
            flex: 1 1 calc(50% - 10px);
        }
        .actions {
            flex-direction: column;
        }
        .stat-grid {
            grid-template-columns: 1fr;
        }
        h1 {
            font-size: 30px;
        }
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

    def _pagina_base(self, titulo: str, conteudo: str) -> str:
        """Gera a estrutura HTML base com navegacao e estilos compartilhados."""
        caminho_atual = self.path.split("?", 1)[0]
        usuario = self._usuario_logado()
        links = (
            ("/", "In&iacute;cio"),
            ("/login", "Login"),
            ("/register", "Registrar"),
            ("/comentarios", "Coment&aacute;rios"),
        )
        nav_links = "".join(
            f'<a class="nav-link{" active" if caminho_atual == href else ""}" '
            f'href="{href}">{rotulo}</a>'
            for href, rotulo in links
        )
        sessao_html = (
            f'<div class="nav-session">Sess&atilde;o ativa: <strong>{usuario}</strong> '
            f'<a href="/logout">Sair</a></div>'
            if usuario else
            '<div class="nav-session">Servidor local pronto para uso</div>'
        )
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetLab - {titulo}</title>
    <style>{_CSS_PAGINAS}</style>
</head>
<body>
    <div class="page-shell">
        <header class="topbar">
            <div class="brand-block">
                <div class="brand-mark">NL</div>
                <div class="brand-copy">
                    <span class="brand-kicker">NetLab Educacional</span>
                    <strong>Servidor Web Local</strong>
                </div>
            </div>
            <nav class="nav-strip">
                {nav_links}
            </nav>
            {sessao_html}
        </header>
        <main class="page-content">
            {conteudo}
        </main>
    </div>
</body>
</html>"""

    def _usuario_logado(self) -> str:
        """Retorna o usuario da sessao atual se ele ainda existir no banco."""
        usuario = _usuario_da_sessao(self.headers.get("Cookie", ""))
        if not usuario:
            return ""

        linhas, _, _ = banco_servidor.consultar_seguro(
            "SELECT username FROM users WHERE username = ?",
            (usuario,),
        )
        return linhas[0][0] if linhas else ""

    # -----------------------------------------------------------------------
    # Roteamento de requisicoes GET
    # -----------------------------------------------------------------------

    def do_GET(self):
        """Processa todas as requisicoes HTTP GET e roteia para os handlers."""
        ts_inicio  = time.time()
        ip_cliente = self.client_address[0]
        cookies    = self.headers.get("Cookie", "")
        usuario    = self._usuario_logado()

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
        
        elif caminho == "/register":
            corpo = self._rota_registro()
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
            corpo = self._rota_comentarios(usuario=usuario)
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

        elif caminho == "/register":
            corpo = self._processar_registro(params, ip_cliente)
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
        bloco_sessao = (
            f'<div class="sucesso">Sess&atilde;o iniciada como <strong>{usuario}</strong>. '
            f'<a href="/logout">Encerrar sess&atilde;o</a></div>'
            if usuario else
            '<div class="info">Escolha um fluxo no menu para navegar pelo servidor local.</div>'
        )

        conteudo = f"""
        <section class="hero">
            <div>
                <span class="eyebrow">NetLab Educacional</span>
                <h1>Servidor web local pronto para uso.</h1>
                <p class="lead">
                    Entre com uma conta, registre novos usu&aacute;rios e acompanhe o
                    mural de coment&aacute;rios com um fluxo mais coerente.
                </p>
                <div class="actions">
                    <a class="primary-link" href="/login">Abrir login</a>
                    <a class="ghost-link" href="/register">Criar conta</a>
                    <a class="ghost-link" href="/comentarios">Ver coment&aacute;rios</a>
                </div>
            </div>
            <aside class="hero-panel">
                <h3>Estado atual</h3>
                {bloco_sessao}
                <div class="stat-grid">
                    <div class="stat">
                        <strong>4</strong>
                        <span>rotas em destaque</span>
                    </div>
                    <div class="stat">
                        <strong>HTTP</strong>
                        <span>acesso local direto</span>
                    </div>
                    <div class="stat">
                        <strong>RAM</strong>
                        <span>dados reiniciam ao parar</span>
                    </div>
                </div>
            </aside>
        </section>
        """
        return self._pagina_base("Inicio", conteudo)

    def _rota_formulario_login(self, mensagem: str = "", tipo_msg: str = "") -> str:
        bloco_msg = ""
        if mensagem:
            classe = "aviso" if tipo_msg == "erro" else "sucesso"
            bloco_msg = f'<div class="{classe}">{mensagem}</div>'

        conteudo = f"""
        <section class="auth-grid">
            <div class="card">
                <span class="eyebrow">Acesso local</span>
                <h1>Login</h1>
                <p class="lead compact-lead">
                    Entre para iniciar uma sess&atilde;o e voltar rapidamente ao
                    painel principal do servidor.
                </p>
                <div class="stat-grid">
                    <div class="stat">
                        <strong>1</strong>
                        <span>formul&aacute;rio direto</span>
                    </div>
                    <div class="stat">
                        <strong>Local</strong>
                        <span>sem etapas extras</span>
                    </div>
                    <div class="stat">
                        <strong>Web</strong>
                        <span>fluxo integrado ao NetLab</span>
                    </div>
                </div>
            </div>
            <div class="card">
                <span class="eyebrow">Entrar</span>
                <h2>Use sua conta</h2>
                <p class="helper-line" style="margin-top:0; margin-bottom:16px;">
                    Informe usu&aacute;rio e senha para abrir a sess&atilde;o.
                </p>
                {bloco_msg}
                <form method="POST" action="/login">
                    <label>Usu&aacute;rio</label>
                    <input type="text" name="usuario" autocomplete="off" placeholder="Digite seu usu&aacute;rio">
                    <label>Senha</label>
                    <input type="password" name="senha" placeholder="Digite sua senha">
                    <input type="submit" value="Entrar">
                </form>
                <p class="helper-line">
                    N&atilde;o tem conta? <a href="/register">Registrar agora</a>
                </p>
            </div>
        </section>
        """
        return self._pagina_base("Login", conteudo)

    def _processar_login(self, params: dict, ip_cliente: str) -> tuple:
        usuario = params.get("usuario", [""])[0]
        senha   = params.get("senha",   [""])[0]

        if not usuario:
            return self._rota_formulario_login("Informe o usuário.", "erro"), None

        if _detectar_sqli(usuario) or _detectar_sqli(senha):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] {ip_cliente} — payload no login: "
                f"usuario='{usuario[:60]}'"
            )

        # VULNERABILIDADE REAL: concatenação direta sem parametrização
        query_vulneravel = (
            f"SELECT id, username, role FROM users "
            f"WHERE username = '{usuario}' AND password = '{senha}'"
        )

        linhas, _, erro = banco_servidor.consultar_vulneravel(query_vulneravel)

        if erro:
            conteudo = f"""
            <div class="card">
                <h1>Erro interno</h1>
                <div class="aviso">Ocorreu um erro ao processar sua solicitação. Tente novamente.</div>
                <a href="/login">Voltar</a>
            </div>
            """
            return self._pagina_base("Erro", conteudo), None

        if linhas:
            _, nome_usuario, _ = linhas[0]
            token = _criar_sessao(nome_usuario)
            return self._rota_inicial(nome_usuario), f"sessao={token}; Path=/"

        return self._rota_formulario_login("Usuário ou senha incorretos.", "erro"), None

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
        produto_id = params.get("id", [""])[0].strip()

        if not produto_id:
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
                <h1>Catálogo de Produtos</h1>
                <table>
                    <thead>
                        <tr><th>ID</th><th>Nome</th><th>Preço</th><th>Ação</th></tr>
                    </thead>
                    <tbody>{linhas_html}</tbody>
                </table>
            </div>
            """
            return self._pagina_base("Produtos", conteudo)

        if _detectar_sqli(produto_id):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] /produtos?id=: '{produto_id[:80]}'"
            )

        # VULNERABILIDADE REAL: concatenação direta
        query_vulneravel = (
            f"SELECT id, name, price FROM products WHERE id = {produto_id}"
        )

        linhas, descricao, erro = banco_servidor.consultar_vulneravel(query_vulneravel)

        if erro:
            conteudo = """
            <div class="card">
                <h1>Erro interno</h1>
                <div class="aviso">Ocorreu um erro ao processar sua solicitação.</div>
                <a href="/produtos">Voltar ao catálogo</a>
            </div>
            """
            return self._pagina_base("Erro", conteudo)

        if not linhas:
            conteudo = f"""
            <div class="card">
                <h1>Produto não encontrado</h1>
                <a href="/produtos">Ver todos os produtos</a>
            </div>
            """
            return self._pagina_base("Produto", conteudo)

        nomes_colunas = [d[0] for d in descricao] if descricao else ["col1", "col2", "col3"]
        cab_html   = "".join(f"<th>{c}</th>" for c in nomes_colunas)
        corpo_html = ""
        for linha in linhas:
            corpo_html += "<tr>" + "".join(f"<td>{v}</td>" for v in linha) + "</tr>"

        conteudo = f"""
        <div class="card">
            <h1>Detalhes do Produto</h1>
            <table>
                <thead><tr>{cab_html}</tr></thead>
                <tbody>{corpo_html}</tbody>
            </table>
            <br>
            <a href="/produtos">Voltar ao catálogo</a>
        </div>
        """
        return self._pagina_base("Produto", conteudo)

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
        termo_bruto = params.get("q", [""])[0]

        if _detectar_xss(termo_bruto):
            sinais_servidor.alerta_emitido.emit(
                f"[XSS REFLETIDO] /busca?q=: '{termo_bruto[:80]}'"
            )

        bloco_resultado = ""
        if termo_bruto:
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
                    f"<table><thead><tr><th>ID</th><th>Nome</th><th>Preço</th></tr></thead>"
                    f"<tbody>{linhas_html}</tbody></table>"
                )
            else:
                tabela = "<p style='color:#7f8c8d;'>Nenhum produto encontrado.</p>"

            # XSS REAL: termo_bruto refletido sem escape
            bloco_resultado = f"<p>Resultados para: <strong>{termo_bruto}</strong></p><br>{tabela}"

        conteudo = f"""
        <div class="card">
            <h1>Busca de Produtos</h1>
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

    def _rota_comentarios(self, usuario: str = "", mensagem: str = "", tipo_msg: str = "") -> str:
        linhas, _, _ = banco_servidor.consultar_seguro(
            "SELECT id, author, content, created_at FROM comments ORDER BY id DESC"
        )

        bloco_msg = ""
        if mensagem:
            classe = "aviso" if tipo_msg == "erro" else "sucesso"
            bloco_msg = f'<div class="{classe}">{mensagem}</div>'

        comentarios_html = ""
        for linha in linhas:
            _, autor, conteudo_comentario, criado_em = linha
            comentarios_html += f"""
            <div class="comentario-item">
                <div class="comentario-autor">{autor or "an&ocirc;nimo"} - {criado_em or ""}</div>
                <div>{conteudo_comentario}</div>
            </div>
            """

        if not comentarios_html:
            comentarios_html = (
                '<div class="empty-state">Nenhum coment&aacute;rio publicado at&eacute; agora.</div>'
            )

        formulario_html = ""
        if usuario:
            formulario_html = f"""
                <div class="section-head">
                    <h2>Publicar mensagem</h2>
                    <span class="pill">Conectado como {usuario}</span>
                </div>
                <div class="info">Seu coment&aacute;rio ser&aacute; publicado com o nome do perfil logado.</div>
                {bloco_msg}
                <form method="POST" action="/comentarios">
                    <label>Perfil ativo</label>
                    <input type="text" value="{usuario}" disabled>
                    <label>Coment&aacute;rio</label>
                    <textarea name="conteudo" placeholder="Escreva sua mensagem aqui..."></textarea>
                    <input type="submit" value="Publicar">
                </form>
            """
        else:
            aviso_login = bloco_msg or (
                '<div class="info">Fa&ccedil;a login para publicar coment&aacute;rios com o nome da sua conta.</div>'
            )
            formulario_html = f"""
                <div class="section-head">
                    <h2>Publicar mensagem</h2>
                    <span class="pill">Login obrigat&oacute;rio</span>
                </div>
                {aviso_login}
                <div class="actions">
                    <a class="primary-link" href="/login">Entrar</a>
                    <a class="ghost-link" href="/register">Criar conta</a>
                </div>
            """

        conteudo = f"""
        <section class="hero">
            <div>
                <span class="eyebrow">Mural local</span>
                <h1>Coment&aacute;rios</h1>
                <p class="lead">
                    Um mural simples para publicar mensagens e acompanhar tudo o
                    que j&aacute; foi enviado nesta sess&atilde;o do servidor.
                </p>
            </div>
            <aside class="hero-panel">
                <h3>Resumo do mural</h3>
                <div class="stat-grid">
                    <div class="stat">
                        <strong>{len(linhas)}</strong>
                        <span>mensagens vis&iacute;veis</span>
                    </div>
                    <div class="stat">
                        <strong>POST</strong>
                        <span>envio imediato</span>
                    </div>
                    <div class="stat">
                        <strong>Live</strong>
                        <span>feed atualizado na hora</span>
                    </div>
                </div>
            </aside>
        </section>
        <section class="comment-layout">
            <div class="card">
                {formulario_html}
            </div>
            <div class="card">
                <div class="section-head">
                    <h2>Mural</h2>
                    <span class="pill">{len(linhas)} registro(s)</span>
                </div>
                <div class="comment-feed">
                    {comentarios_html}
                </div>
            </div>
        </section>
        """
        return self._pagina_base("Comentarios", conteudo)

    def _processar_comentario(self, params: dict, ip_cliente: str) -> str:
        autor    = self._usuario_logado()[:100]
        conteudo = params.get("conteudo", [""])[0]

        if not autor:
            return self._rota_comentarios(
                mensagem="Fa&ccedil;a login para publicar coment&aacute;rios.",
                tipo_msg="erro",
            )

        if not conteudo.strip():
            return self._rota_comentarios(
                usuario=autor,
                mensagem="Digite um coment&aacute;rio antes de publicar.",
                tipo_msg="erro",
            )

        if _detectar_xss(conteudo) or _detectar_xss(autor):
            sinais_servidor.alerta_emitido.emit(
                f"[XSS ARMAZENADO] {ip_cliente} — payload em comentário: "
                f"'{conteudo[:80]}'"
            )

        if _detectar_sqli(conteudo) or _detectar_sqli(autor):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] {ip_cliente} — payload em INSERT de comentário: "
                f"'{conteudo[:80]}'"
            )

        agora = datetime.now().strftime("%H:%M:%S")

        # VULNERABILIDADE REAL: INSERT com concatenação direta
        query_vulneravel = (
            f"INSERT INTO comments (author, content, created_at) "
            f"VALUES ('{autor}', '{conteudo}', '{agora}')"
        )
        sucesso, _ = banco_servidor.modificar_vulneravel(query_vulneravel)

        if not sucesso:
            conteudo_html = """
            <div class="card">
                <h1>Erro interno</h1>
                <div class="aviso">Não foi possível publicar o comentário. Tente novamente.</div>
                <a href="/comentarios">Voltar</a>
            </div>
            """
            return self._pagina_base("Erro", conteudo_html)

        return self._rota_comentarios(
            usuario=autor,
            mensagem="Coment&aacute;rio publicado com sucesso.",
            tipo_msg="sucesso",
        )
    def _rota_pedidos(self, params: dict) -> str:
        try:
            pedido_id = int(params.get("id", ["1"])[0].strip())
        except (ValueError, IndexError):
            pedido_id = 1

        # IDOR REAL: sem verificação de autorização
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
                <h1>Pedido #{pedido_id}</h1>
                <p>Pedido não encontrado.</p>
                <p>Ver outros pedidos: {navegacao}</p>
            </div>
            """
            return self._pagina_base("Pedido", conteudo)

        r = linhas[0]
        pid, dono_usuario, dono_papel, produto, preco, qtd, total = r

        sinais_servidor.alerta_emitido.emit(
            f"[IDOR] Pedido #{pid} acessado sem autorização. "
            f"Dono: {dono_usuario} ({dono_papel})"
        )

        conteudo = f"""
        <div class="card">
            <h1>Pedido #{pid}</h1>
            <table>
                <tbody>
                    <tr><td><strong>Usuário</strong></td><td>{dono_usuario}</td></tr>
                    <tr><td><strong>Produto</strong></td><td>{produto}</td></tr>
                    <tr><td><strong>Preço unitário</strong></td><td>R$ {preco:.2f}</td></tr>
                    <tr><td><strong>Quantidade</strong></td><td>{qtd}</td></tr>
                    <tr><td><strong>Total</strong></td><td><strong>R$ {total:.2f}</strong></td></tr>
                </tbody>
            </table>
            <br>
            <p>Ver outros pedidos: {navegacao}</p>
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
        linhas, _, _ = banco_servidor.consultar_seguro(
            "SELECT id, username, password, role FROM users ORDER BY id"
        )

        linhas_html = "".join(
            f"<tr><td>{r[0]}</td><td>{r[1]}</td>"
            f"<td style='font-family:Consolas;'>{r[2]}</td>"
            f"<td>{r[3]}</td></tr>"
            for r in linhas
        )

        sinais_servidor.alerta_emitido.emit(
            f"[DIVULGAÇÃO] /usuarios acessado — {len(linhas)} usuários expostos sem autenticação"
        )

        conteudo = f"""
        <div class="card">
            <h1>Usuários cadastrados</h1>
            <table>
                <thead>
                    <tr><th>ID</th><th>Usuário</th><th>Senha</th><th>Papel</th></tr>
                </thead>
                <tbody>{linhas_html}</tbody>
            </table>
        </div>
        """
        return self._pagina_base("Usuários", conteudo)

    def _rota_perfil(self, params: dict) -> str:
        nome_bruto = params.get("nome", [""])[0]

        if _detectar_xss(nome_bruto):
            sinais_servidor.alerta_emitido.emit(
                f"[XSS REFLETIDO] /perfil?nome=: '{nome_bruto[:80]}'"
            )

        # XSS REAL: nome_bruto sem escape
        bloco_nome = (
            f"<h2>Perfil de: {nome_bruto}</h2>"
            if nome_bruto else "<h2>Perfil</h2>"
        )

        conteudo = f"""
        <div class="card">
            <h1>Perfil</h1>
            {bloco_nome}
            <br>
            <form method="GET" action="/perfil">
                <label>Nome do usuário</label>
                <input type="text" name="nome" placeholder="Digite um nome">
                <button type="submit">Ver perfil</button>
            </form>
        </div>
        """
        return self._pagina_base("Perfil", conteudo)

    def _rota_registro(self, erro: str = "") -> str:
        bloco_erro = f'<div class="aviso">{erro}</div>' if erro else ""
        conteudo = f"""
        <section class="auth-grid">
            <div class="card">
                <span class="eyebrow">Novo acesso</span>
                <h1>Registrar</h1>
                <p class="lead compact-lead">
                    Crie uma conta no banco em mem&oacute;ria para testar o fluxo de
                    cadastro e seguir direto para o login.
                </p>
                <ul class="meta-list" style="margin-top:18px;">
                    <li>Usu&aacute;rios ficam dispon&iacute;veis enquanto o servidor estiver ativo.</li>
                    <li>O cadastro valida confirma&ccedil;&atilde;o de senha e unicidade de usu&aacute;rio.</li>
                    <li>Ao concluir, o sistema j&aacute; devolve voc&ecirc; ao login com mensagem de sucesso.</li>
                </ul>
            </div>
            <div class="card">
                <span class="eyebrow">Cadastro</span>
                <h2>Criar conta</h2>
                <p class="helper-line" style="margin-top:0; margin-bottom:16px;">
                    Preencha os campos para registrar um novo usu&aacute;rio.
                </p>
                {bloco_erro}
                <form method="POST" action="/register">
                    <label>Usu&aacute;rio</label>
                    <input type="text" name="usuario" required autocomplete="off" placeholder="Escolha um usu&aacute;rio">
                    <label>Senha (apenas n&uacute;meros)</label>
                    <input type="password" name="senha" required placeholder="Use ao menos 4 d&iacute;gitos">
                    <label>Confirmar senha</label>
                    <input type="password" name="confirmar" required placeholder="Repita a senha">
                    <input type="submit" value="Registrar">
                </form>
                <p class="helper-line">
                    J&aacute; tem conta? <a href="/login">Entrar</a>
                </p>
            </div>
        </section>
        """
        return self._pagina_base("Registrar", conteudo)

    def _processar_registro(self, params: dict, ip_cliente: str) -> str:
        usuario = params.get("usuario", [""])[0]
        senha   = params.get("senha",   [""])[0]
        confirm = params.get("confirmar", [""])[0]

        if not usuario or not senha:
            return self._rota_registro(erro="Preencha todos os campos.")
        if not senha.isdigit():
            return self._rota_registro(erro="A senha deve conter apenas números.")
        if len(senha) < 4:
            return self._rota_registro(erro="A senha deve ter pelo menos 4 dígitos.")
        if senha != confirm:
            return self._rota_registro(erro="As senhas não conferem.")

        if _detectar_sqli(usuario):
            sinais_servidor.alerta_emitido.emit(
                f"[SQL INJECTION] /register de {ip_cliente}: usuario='{usuario[:60]}'"
            )

        # VULNERABILIDADE REAL: INSERT com concatenação direta
        query_vulneravel = (
            f"INSERT INTO users (username, password, role) "
            f"VALUES ('{usuario}', '{senha}', 'user')"
        )
        sucesso, erro_sql = banco_servidor.modificar_vulneravel(query_vulneravel)

        if sucesso:
            return self._rota_formulario_login(
                mensagem="Conta criada com sucesso! Faça login.",
                tipo_msg="sucesso"
            )
        if erro_sql and "UNIQUE" in str(erro_sql):
            return self._rota_registro(erro="Este usuário já existe.")
        return self._rota_registro(erro="Erro ao criar conta. Tente novamente.")

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
