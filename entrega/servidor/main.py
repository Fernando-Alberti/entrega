"""Servidor FastAPI - protocolo cliente-servidor v1.4.0 (usuários, sessões e produtos).

Rotas (todas sob /api/v1):
  POST   /sessions        login
  DELETE /sessions/{id}   logout
  GET    /users           listar usuários (ADM)
  POST   /users           cadastro
  GET    /users/{id}      buscar (dono do token ou ADM)
  PUT    /users/{id}      atualizar todos os campos (dono ou ADM)
  PATCH  /users/{id}      atualizar parcialmente (dono ou ADM)
  DELETE /users/{id}      remover (dono ou ADM)
  GET    /products        listar produtos (qualquer usuário logado)
  POST   /products        cadastrar produto (ADM)
  GET    /products/{id}   consultar produto/estoque (qualquer usuário logado)
  PUT    /products/{id}   atualizar produto (ADM)
  PATCH  /products/{id}   atualizar parcialmente produto (ADM)
  DELETE /products/{id}   remover produto (ADM)

ADM padrão criado na inicialização: admin@admin.com / admin123.
Execução:  python main.py   (pergunta a porta)
Armazenamento em memória (dados somem ao reiniciar).
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import logging
import os
import re
import secrets
import time
import uuid
from typing import Any, Optional

import jwt  # PyJWT
from fastapi import APIRouter, FastAPI, Request, Response, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("api")

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
TOKEN_TTL_SECONDS = 24 * 3600

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


# --------------------------------------------------------------------------
# Erros
# --------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, status: int, mensagem: str):
        self.status = status
        self.mensagem = mensagem


def erro(status: int, mensagem: str, headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse({"mensagem": mensagem}, status_code=status, headers=headers)


# --------------------------------------------------------------------------
# "Banco" em memória
# --------------------------------------------------------------------------
users: dict[int, dict[str, Any]] = {}      # id -> {id, nome, email, salt, hash}
sessions: dict[str, int] = {}              # whitelist: session_id -> user_id
_next_user_id = itertools.count(1)


def hash_senha(senha: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", senha.encode(), salt, 100_000)


def usuario_publico(u: dict) -> dict:
    return {"id": u["id"], "nome": u["nome"], "email": u["email"], "admin": u["admin"]}  # nunca a senha


def email_em_uso(email: str, ignorar_id: Optional[int] = None) -> bool:
    alvo = email.lower()
    return any(u["email"].lower() == alvo and u["id"] != ignorar_id for u in users.values())


ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@admin.com")
ADMIN_SENHA = os.environ.get("ADMIN_SENHA", "admin123")


def criar_admin_padrao() -> None:
    """Como cada servidor cria seus ADMs fica fora do protocolo: aqui, um ADM padrão na inicialização."""
    uid = next(_next_user_id)
    salt = os.urandom(16)
    users[uid] = {"id": uid, "nome": "Administrador", "email": ADMIN_EMAIL, "admin": True,
                  "salt": salt, "hash": hash_senha(ADMIN_SENHA, salt)}


criar_admin_padrao()


def mostrar_logados() -> None:
    """Lista de usuários logados, reimpressa a cada login, logout ou remoção."""
    ativos: dict = {}
    for owner in sessions.values():
        ativos[owner] = ativos.get(owner, 0) + 1
    print(f"\n=== Usuários logados ({len(ativos)}) ===")
    for uid, n in sorted(ativos.items()):
        u = users[uid]
        print(f"  [{uid}] {u['nome']} <{u['email']}>{' (ADM)' if u['admin'] else ''} - {n} sessão(ões)")
    if not ativos:
        print("  (nenhum)")
    print(flush=True)


# --------------------------------------------------------------------------
# Validação
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")  # mesmo padrão do YAML
SENHA_RE = re.compile(r"[A-Za-z0-9]+")
USER_ID_RE = re.compile(r"[+-]?[0-9]{1,100}")  # qualquer inteiro


def validar_nome(v: Any) -> str:
    if not isinstance(v, str):
        raise ApiError(400, "O campo 'nome' deve ser um texto.")
    v = v.strip()
    if not 3 <= len(v) <= 50:
        raise ApiError(400, "O campo 'nome' deve ter entre 3 e 50 caracteres.")
    return v


def validar_email(v: Any) -> str:
    if not isinstance(v, str):
        raise ApiError(400, "O campo 'email' deve ser um texto.")
    if not 5 <= len(v) <= 30 or not EMAIL_RE.fullmatch(v):
        raise ApiError(400, "O campo 'email' é inválido (5 a 30 caracteres, com @ e domínio válido).")
    return v


def validar_senha(v: Any) -> str:
    if not isinstance(v, str):
        raise ApiError(400, "O campo 'senha' deve ser um texto.")
    if not 6 <= len(v) <= 20 or not SENHA_RE.fullmatch(v):
        raise ApiError(400, "O campo 'senha' deve ter 6 a 20 caracteres alfanuméricos, sem especiais.")
    return v


VALIDADORES = {"nome": validar_nome, "email": validar_email, "senha": validar_senha}


def validar_campos(corpo: dict, obrigatorios: list[str], parcial: bool = False) -> dict:
    """Valida só os campos conhecidos (os demais são ignorados). null/tipo errado => 400."""
    dados: dict[str, str] = {}
    for campo, fn in VALIDADORES.items():
        if campo in corpo:
            dados[campo] = fn(corpo[campo])
        elif not parcial and campo in obrigatorios:
            raise ApiError(400, f"O campo '{campo}' é obrigatório.")
    if parcial and not dados:
        raise ApiError(400, "Envie ao menos um campo para atualizar (nome, email ou senha).")
    return dados


async def ler_corpo(request: Request) -> dict:
    raw = await request.body()
    try:
        corpo = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiError(400, "Corpo da requisição não é um JSON válido.")
    if not isinstance(corpo, dict):
        raise ApiError(400, "O corpo da requisição deve ser um objeto JSON.")
    return corpo


# --------------------------------------------------------------------------
# Autenticação
# --------------------------------------------------------------------------
def autenticar(request: Request) -> tuple[int, str]:
    """Devolve (user_id, session_id) ou levanta 401."""
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) <= 7:
        raise ApiError(401, "Token ausente ou inválido.")
    try:
        payload = jwt.decode(header[7:], SECRET_KEY, algorithms=["HS256"])
        uid, sid = int(payload["sub"]), str(payload["sid"])
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        raise ApiError(401, "Token ausente ou inválido.")
    if sessions.get(sid) != uid or uid not in users:
        raise ApiError(401, "Sessão encerrada ou inválida.")
    return uid, sid


def exigir_admin(request: Request) -> int:
    uid, _ = autenticar(request)
    if not users[uid]["admin"]:
        raise ApiError(403, "Apenas administradores podem acessar este recurso.")
    return uid


def usuario_alvo(request: Request, id_str: str) -> dict:
    """Ordem: 401 -> 400 (id) -> 403 -> 404. Acessa o dono do token ou um ADM."""
    uid, _ = autenticar(request)
    if not USER_ID_RE.fullmatch(id_str):
        raise ApiError(400, "O id do usuário na URL está mal formatado.")
    alvo = int(id_str)
    if alvo != uid and not users[uid]["admin"]:
        raise ApiError(403, "Você não tem permissão para acessar este usuário.")
    u = users.get(alvo)
    if u is None:
        raise ApiError(404, "Usuário não encontrado.")
    return u


# --------------------------------------------------------------------------
# Rotas
# --------------------------------------------------------------------------
router = APIRouter(prefix="/api/v1")

# --- Só para a documentação (/docs): botão "Authorize" e corpos de exemplo ---
# A validação real é feita manualmente nos handlers.
AUTH = [Security(HTTPBearer(auto_error=False))]
_NOME = {"type": "string", "minLength": 3, "maxLength": 50}
_EMAIL = {"type": "string", "minLength": 5, "maxLength": 30, "format": "email"}
_SENHA = {"type": "string", "minLength": 6, "maxLength": 20, "pattern": "^[A-Za-z0-9]+$"}


def corpo_doc(props: dict, required: list, exemplo: dict) -> dict:
    return {"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"type": "object", "properties": props, "required": required},
        "example": exemplo,
    }}}}


DOC_LOGIN = corpo_doc({"email": _EMAIL, "senha": _SENHA}, ["email", "senha"],
                      {"email": "ana@x.com", "senha": "abc123"})
DOC_USER = corpo_doc({"nome": _NOME, "email": _EMAIL, "senha": _SENHA}, ["nome", "email", "senha"],
                     {"nome": "Ana Silva", "email": "ana@x.com", "senha": "abc123"})
DOC_PATCH = corpo_doc({"nome": _NOME, "email": _EMAIL, "senha": _SENHA}, [],
                      {"nome": "Ana Souza"})


@router.post("/sessions", status_code=201, openapi_extra=DOC_LOGIN)
async def login(request: Request):
    corpo = await ler_corpo(request)
    dados = validar_campos(corpo, obrigatorios=["email", "senha"])
    alvo = dados["email"].lower()
    u = next((x for x in users.values() if x["email"].lower() == alvo), None)
    if u is None or not hmac.compare_digest(hash_senha(dados["senha"], u["salt"]), u["hash"]):
        raise ApiError(401, "E-mail ou senha incorretos.")

    sid = str(uuid.uuid4())
    agora = int(time.time())
    token = jwt.encode(
        {"sub": str(u["id"]), "sid": sid, "iat": agora, "exp": agora + TOKEN_TTL_SECONDS},
        SECRET_KEY,
        algorithm="HS256",
    )
    sessions[sid] = u["id"]  # whitelist
    mostrar_logados()
    return {"id": sid, "token": token, "usuario": usuario_publico(u)}


@router.delete("/sessions/{id}", dependencies=AUTH)
async def logout(id: str, request: Request):
    uid, _ = autenticar(request)
    try:
        sid = str(uuid.UUID(id))
    except ValueError:
        raise ApiError(400, "O id da sessão na URL está mal formatado.")
    # 403 vem antes do 404: sessão de outro usuário (exista ou não) => 403.
    if sessions.get(sid) != uid:
        raise ApiError(403, "Você não tem permissão para encerrar esta sessão.")
    del sessions[sid]
    mostrar_logados()
    return Response(status_code=204)


@router.get("/users", dependencies=AUTH)
async def listar_usuarios(request: Request):
    exigir_admin(request)
    return [usuario_publico(u) for u in sorted(users.values(), key=lambda x: x["id"])]


@router.post("/users", status_code=201, openapi_extra=DOC_USER)
async def criar_usuario(request: Request):
    corpo = await ler_corpo(request)
    dados = validar_campos(corpo, obrigatorios=["nome", "email", "senha"])
    if email_em_uso(dados["email"]):
        raise ApiError(409, "E-mail já cadastrado.")
    uid = next(_next_user_id)
    salt = os.urandom(16)
    users[uid] = {
        "id": uid, "nome": dados["nome"], "email": dados["email"], "admin": False,
        "salt": salt, "hash": hash_senha(dados["senha"], salt),
    }
    return usuario_publico(users[uid])


@router.get("/users/{id}", dependencies=AUTH)
async def buscar_usuario(id: str, request: Request):
    return usuario_publico(usuario_alvo(request, id))


async def _atualizar(id: str, request: Request, parcial: bool):
    u = usuario_alvo(request, id)
    corpo = await ler_corpo(request)  # um "id" no corpo é ignorado
    dados = validar_campos(corpo, obrigatorios=["nome", "email", "senha"], parcial=parcial)
    if "email" in dados and email_em_uso(dados["email"], ignorar_id=u["id"]):
        raise ApiError(409, "E-mail já cadastrado.")
    if "senha" in dados:
        u["salt"] = os.urandom(16)
        u["hash"] = hash_senha(dados.pop("senha"), u["salt"])
    u.update(dados)
    return usuario_publico(u)


@router.put("/users/{id}", dependencies=AUTH, openapi_extra=DOC_USER)
async def atualizar_usuario(id: str, request: Request):
    return await _atualizar(id, request, parcial=False)


@router.patch("/users/{id}", dependencies=AUTH, openapi_extra=DOC_PATCH)
async def atualizar_parcial(id: str, request: Request):
    return await _atualizar(id, request, parcial=True)


@router.delete("/users/{id}", dependencies=AUTH)
async def remover_usuario(id: str, request: Request):
    u = usuario_alvo(request, id)
    for sid in [s for s, owner in sessions.items() if owner == u["id"]]:
        del sessions[sid]
    del users[u["id"]]
    mostrar_logados()
    return Response(status_code=204)


# --------------------------------------------------------------------------
# Produtos (leitura: qualquer usuário autenticado; escrita: só ADM)
# --------------------------------------------------------------------------
products: dict = {}
_next_product_id = itertools.count(1)

_P_NOME = {"type": "string", "minLength": 2, "maxLength": 100}
_P_DESC = {"type": "string", "maxLength": 500}
_P_QTD = {"type": "integer", "minimum": 0, "maximum": 1000000}
_P_EX = {"nome": "Teclado mecânico", "descricao": "Teclado ABNT2 com switch azul", "quantidade": 15}
DOC_PRODUCT = corpo_doc({"nome": _P_NOME, "descricao": _P_DESC, "quantidade": _P_QTD},
                        ["nome", "descricao", "quantidade"], _P_EX)
DOC_PRODUCT_PATCH = corpo_doc({"nome": _P_NOME, "descricao": _P_DESC, "quantidade": _P_QTD}, [],
                              {"quantidade": 20})


def validar_nome_produto(v: Any) -> str:
    if not isinstance(v, str):
        raise ApiError(400, "O campo 'nome' deve ser um texto.")
    v = v.strip()
    if not 2 <= len(v) <= 100:
        raise ApiError(400, "O campo 'nome' deve ter entre 2 e 100 caracteres.")
    return v


def validar_descricao(v: Any) -> str:
    if not isinstance(v, str):
        raise ApiError(400, "O campo 'descricao' deve ser um texto.")
    v = v.strip()
    if len(v) > 500:
        raise ApiError(400, "O campo 'descricao' deve ter no máximo 500 caracteres.")
    return v


def validar_quantidade(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ApiError(400, "O campo 'quantidade' deve ser um número inteiro.")
    if not 0 <= v <= 1_000_000:
        raise ApiError(400, "O campo 'quantidade' deve estar entre 0 e 1.000.000.")
    return v


VALIDADORES_PRODUTO = {"nome": validar_nome_produto, "descricao": validar_descricao,
                       "quantidade": validar_quantidade}


def validar_produto(corpo: dict, parcial: bool) -> dict:
    dados = {}
    for campo, fn in VALIDADORES_PRODUTO.items():
        if campo in corpo:
            dados[campo] = fn(corpo[campo])
        elif not parcial:
            raise ApiError(400, f"O campo '{campo}' é obrigatório.")
    if parcial and not dados:
        raise ApiError(400, "Envie ao menos um campo para atualizar (nome, descricao ou quantidade).")
    return dados


def produto_por_id(id_str: str) -> dict:
    if not USER_ID_RE.fullmatch(id_str):
        raise ApiError(400, "O id do produto na URL está mal formatado.")
    p = products.get(int(id_str))
    if p is None:
        raise ApiError(404, "Produto não encontrado.")
    return p


@router.get("/products", dependencies=AUTH)
async def listar_produtos(request: Request):
    autenticar(request)
    return [products[k] for k in sorted(products)]


@router.post("/products", status_code=201, dependencies=AUTH, openapi_extra=DOC_PRODUCT)
async def criar_produto(request: Request):
    exigir_admin(request)
    dados = validar_produto(await ler_corpo(request), parcial=False)
    pid = next(_next_product_id)
    products[pid] = {"id": pid, **dados}
    return products[pid]


@router.get("/products/{id}", dependencies=AUTH)
async def buscar_produto(id: str, request: Request):
    autenticar(request)
    return produto_por_id(id)


async def _atualizar_produto(id: str, request: Request, parcial: bool):
    exigir_admin(request)  # ordem: 401 -> 403 (papel) -> 400 (id) -> 404 -> 400 (corpo)
    p = produto_por_id(id)
    p.update(validar_produto(await ler_corpo(request), parcial))
    return p


@router.put("/products/{id}", dependencies=AUTH, openapi_extra=DOC_PRODUCT)
async def atualizar_produto(id: str, request: Request):
    return await _atualizar_produto(id, request, parcial=False)


@router.patch("/products/{id}", dependencies=AUTH, openapi_extra=DOC_PRODUCT_PATCH)
async def atualizar_produto_parcial(id: str, request: Request):
    return await _atualizar_produto(id, request, parcial=True)


@router.delete("/products/{id}", dependencies=AUTH)
async def remover_produto(id: str, request: Request):
    exigir_admin(request)
    p = produto_por_id(id)
    del products[p["id"]]
    return Response(status_code=204)


# --------------------------------------------------------------------------
# App, CORS e tratamento global de erros
# --------------------------------------------------------------------------
app = FastAPI(title="Protocolo Cliente-Servidor", redirect_slashes=False)
app.include_router(router)


@app.middleware("http")
async def cors_e_erro_interno(request: Request, call_next):
    if request.method == "OPTIONS":  # preflight: 204, sem token, sem corpo
        return Response(status_code=204, headers=CORS_HEADERS)
    try:
        response = await call_next(request)
    except Exception:
        log.exception("Erro interno")
        response = erro(500, "Erro interno do servidor.")
    for k, v in CORS_HEADERS.items():
        response.headers[k] = v
    return response


@app.exception_handler(ApiError)
async def _api_error(request: Request, exc: ApiError):
    return erro(exc.status, exc.mensagem)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    msgs = {404: "Rota não encontrada.", 405: "Método não permitido nesta rota."}
    return erro(exc.status_code, msgs.get(exc.status_code, str(exc.detail)), exc.headers)


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError):
    return erro(400, "Requisição inválida.")


if __name__ == "__main__":
    import uvicorn

    while True:
        entrada = input("Porta do servidor [8000]: ").strip() or "8000"
        if entrada.isdigit() and 1 <= int(entrada) <= 65535:
            break
        print("Porta inválida. Digite um número entre 1 e 65535.")
    uvicorn.run(app, host="0.0.0.0", port=int(entrada))