import os
import hmac
import hashlib
import secrets
import sqlite3
import smtplib
import time

from email.message import EmailMessage

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


PASTA = os.path.dirname(os.path.abspath(__file__))


# ---------------- CLASSE PRINCIPAL ----------------

class ServicoLogin:
    """Cadastro, confirmação por e-mail e login de usuários."""

    def __init__(
            self,
            banco=os.path.join(PASTA, "usuarios.db"),
            tempo_codigo=10 * 60,        # 10 minutos
            intervalo_reenvio=60,        # 60 segundos
            iteracoes_senha=300_000,
            max_tentativas=5,
    ):
        self.banco = banco
        self.tempo_codigo = tempo_codigo
        self.intervalo_reenvio = intervalo_reenvio
        self.iteracoes_senha = iteracoes_senha
        self.max_tentativas = max_tentativas

        self._preparar_banco()

    # ---------- banco de dados ----------

    def _conectar(self):
        conexao = sqlite3.connect(self.banco, timeout=10)
        conexao.row_factory = sqlite3.Row
        return conexao

    def _preparar_banco(self):
        with self._conectar() as db:
            db.execute("""
                       CREATE TABLE IF NOT EXISTS usuarios (
                                                               id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                               email TEXT UNIQUE NOT NULL,
                                                               salt TEXT NOT NULL,
                                                               senha_hash TEXT NOT NULL,
                                                               verificado INTEGER NOT NULL DEFAULT 0,
                                                               codigo_hash TEXT,
                                                               codigo_expira REAL,
                                                               ultimo_envio REAL NOT NULL DEFAULT 0,
                                                               tentativas INTEGER NOT NULL DEFAULT 0
                       )
                       """)

            colunas = [
                linha["name"]
                for linha in db.execute("PRAGMA table_info(usuarios)")
            ]
            if "tentativas" not in colunas:
                db.execute(
                    "ALTER TABLE usuarios "
                    "ADD COLUMN tentativas INTEGER NOT NULL DEFAULT 0"
                )

    def _buscar_usuario(self, db, email):
        return db.execute(
            "SELECT * FROM usuarios WHERE email = ?",
            (email,)
        ).fetchone()

    # ---------- utilitários ----------

    @staticmethod
    def normalizar_email(email):
        return email.strip().lower()

    def _hash_senha(self, senha, salt):
        resultado = hashlib.pbkdf2_hmac(
            "sha256",
            senha.encode("utf-8"),
            bytes.fromhex(salt),
            self.iteracoes_senha
        )
        return resultado.hex()

    @staticmethod
    def _hash_codigo(codigo):
        return hashlib.sha256(codigo.encode("utf-8")).hexdigest()

    # ---------- envio de e-mail ----------

    def _enviar_email(self, destinatario, codigo):
        remetente = os.getenv("GMAIL_EMAIL")
        senha_app = os.getenv("GMAIL_APP_PASSWORD")

        if not remetente or not senha_app:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Gmail não configurado. Defina GMAIL_EMAIL "
                    "e GMAIL_APP_PASSWORD no PowerShell."
                )
            )

        mensagem = EmailMessage()
        mensagem["Subject"] = "Código de verificação"
        mensagem["From"] = remetente
        mensagem["To"] = destinatario
        mensagem.set_content(
            f"""Olá!

Seu código de verificação é: {codigo}

Ele expira em 10 minutos.

Se você não solicitou esse código, ignore este e-mail.
"""
        )

        try:
            with smtplib.SMTP_SSL(
                    "smtp.gmail.com", 465, timeout=20
            ) as servidor:
                servidor.login(remetente, senha_app)
                servidor.send_message(mensagem)
        except Exception as erro:
            print("Erro ao enviar e-mail:", repr(erro))
            raise HTTPException(
                status_code=502,
                detail=(
                    "Não foi possível enviar o e-mail. "
                    "Confira a configuração do Gmail."
                )
            )

    # ---------- ações públicas ----------

    def cadastrar(self, email, senha):
        email = self.normalizar_email(email)

        if "@" not in email or "." not in email.split("@")[-1]:
            raise HTTPException(
                status_code=400,
                detail="Informe um e-mail válido."
            )

        if len(senha) < 8:
            raise HTTPException(
                status_code=400,
                detail="A senha deve ter pelo menos 8 caracteres."
            )

        salt = secrets.token_hex(16)
        senha_criptografada = self._hash_senha(senha, salt)

        try:
            with self._conectar() as db:
                db.execute(
                    """
                    INSERT INTO usuarios (email, salt, senha_hash)
                    VALUES (?, ?, ?)
                    """,
                    (email, salt, senha_criptografada)
                )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="Este e-mail já está cadastrado."
            )

        self.reenviar(email)

        return {
            "mensagem": (
                "Cadastro criado! Confira seu e-mail para obter o código."
            )
        }

    def reenviar(self, email):
        email = self.normalizar_email(email)
        agora = time.time()

        with self._conectar() as db:
            usuario = self._buscar_usuario(db, email)

            if usuario is None:
                raise HTTPException(
                    status_code=404,
                    detail="E-mail não cadastrado."
                )

            if usuario["verificado"]:
                raise HTTPException(
                    status_code=400,
                    detail="Este e-mail já foi verificado."
                )

            if agora - usuario["ultimo_envio"] < self.intervalo_reenvio:
                raise HTTPException(
                    status_code=429,
                    detail="Aguarde 60 segundos antes de pedir outro código."
                )

        codigo = f"{secrets.randbelow(1_000_000):06d}"

        # Envia antes de guardar o novo código.
        self._enviar_email(email, codigo)

        with self._conectar() as db:
            db.execute(
                """
                UPDATE usuarios
                SET codigo_hash = ?,
                    codigo_expira = ?,
                    ultimo_envio = ?,
                    tentativas = 0
                WHERE email = ?
                """,
                (
                    self._hash_codigo(codigo),
                    agora + self.tempo_codigo,
                    agora,
                    email
                )
            )

        return {"mensagem": "Novo código enviado para seu e-mail."}

    def confirmar(self, email, codigo):
        email = self.normalizar_email(email)
        codigo = codigo.strip()

        if len(codigo) != 6 or not codigo.isdigit():
            raise HTTPException(
                status_code=400,
                detail="Digite o código de 6 números."
            )

        with self._conectar() as db:
            usuario = self._buscar_usuario(db, email)

            if usuario is None:
                raise HTTPException(
                    status_code=404,
                    detail="E-mail não cadastrado."
                )

            if usuario["verificado"]:
                return {"mensagem": "E-mail já verificado. Você pode entrar."}

            if (
                    not usuario["codigo_hash"]
                    or not usuario["codigo_expira"]
                    or time.time() > usuario["codigo_expira"]
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Código expirado. Solicite outro."
                )

            if usuario["tentativas"] >= self.max_tentativas:
                raise HTTPException(
                    status_code=429,
                    detail="Muitas tentativas erradas. Solicite um novo código."
                )

            if not hmac.compare_digest(
                    self._hash_codigo(codigo),
                    usuario["codigo_hash"]
            ):
                db.execute(
                    """
                    UPDATE usuarios
                    SET tentativas = tentativas + 1
                    WHERE email = ?
                    """,
                    (email,)
                )
                # Commit explícito: o raise abaixo desfaria o incremento.
                db.commit()
                raise HTTPException(
                    status_code=400,
                    detail="Código incorreto."
                )

            db.execute(
                """
                UPDATE usuarios
                SET verificado = 1,
                    codigo_hash = NULL,
                    codigo_expira = NULL,
                    tentativas = 0
                WHERE email = ?
                """,
                (email,)
            )

        return {"mensagem": "E-mail verificado com sucesso!"}

    def login(self, email, senha):
        email = self.normalizar_email(email)

        with self._conectar() as db:
            usuario = self._buscar_usuario(db, email)

        if usuario is None:
            raise HTTPException(
                status_code=401,
                detail="E-mail ou senha incorretos."
            )

        senha_informada = self._hash_senha(senha, usuario["salt"])

        if not hmac.compare_digest(
                senha_informada,
                usuario["senha_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="E-mail ou senha incorretos."
            )

        if not usuario["verificado"]:
            raise HTTPException(
                status_code=403,
                detail="Confirme seu e-mail antes de entrar."
            )

        return {"mensagem": "Login realizado com sucesso!"}


# ---------------- API (rotas finas) ----------------

app = FastAPI(title="Servidor de Login")
servico = ServicoLogin()


class DadosCadastro(BaseModel):
    email: str
    senha: str


class DadosConfirmacao(BaseModel):
    email: str
    codigo: str


class DadosEmail(BaseModel):
    email: str


class DadosLogin(BaseModel):
    email: str
    senha: str


@app.get("/")
def inicio():
    return {"mensagem": "Servidor de login funcionando!"}


@app.post("/cadastro")
def cadastro(dados: DadosCadastro):
    return servico.cadastrar(dados.email, dados.senha)


@app.post("/confirmar")
def confirmar(dados: DadosConfirmacao):
    return servico.confirmar(dados.email, dados.codigo)


@app.post("/reenviar")
def reenviar(dados: DadosEmail):
    return servico.reenviar(dados.email)


@app.post("/login")
def login(dados: DadosLogin):
    return servico.login(dados.email, dados.senha)
