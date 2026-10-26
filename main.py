# main.py
from fastapi import FastAPI
from servico_login import ServicoLogin

app = FastAPI()
servico = ServicoLogin()

@app.post("/login")
def login(dados: DadosLogin):
    return servico.login(dados.email, dados.senha)