from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import sqlite3
from datetime import datetime
import subprocess
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

ph = PasswordHasher()

# Banco SQLite
DB_FILE = "clientes.db"

# === DETECÇÃO AUTOMÁTICA DO RUSTDESK ===
POSSIVEIS_CAMINHOS = [
    r"C:\Program Files\RustDesk\rustdesk.exe",                          # Padrão oficial atual
    r"C:\Program Files (x86)\RustDesk\rustdesk.exe",                    # Versões antigas
    os.path.expanduser(r"~\AppData\Local\Programs\RustDesk\rustdesk.exe"),  # Instalação por usuário (Microsoft Store ou portable)
    r"C:\RustDesk\rustdesk.exe",                                        # Portable comum
]

RUSTDESK_PATH = None
for caminho in POSSIVEIS_CAMINHOS:
    if os.path.isfile(caminho):  # Use isfile para ser mais preciso
        RUSTDESK_PATH = caminho
        break

if RUSTDESK_PATH:
    print(f"[SUCESSO] RustDesk encontrado automaticamente em: {RUSTDESK_PATH}")
else:
    print("[ERRO] RustDesk NÃO encontrado em nenhum caminho comum.")
    print("   Verifique se está instalado e procure manualmente o rustdesk.exe")
    print("   Depois adicione o caminho correto na lista POSSIVEIS_CAMINHOS")

# =====================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS clientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    empresa TEXT,
    cnpj TEXT,                    -- NOVA COLUNA
    rustdesk_id TEXT UNIQUE NOT NULL,
    senha TEXT,
    observacoes TEXT,
    status TEXT DEFAULT 'desconectado',
    criado_em TEXT
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS acessos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tecnico TEXT NOT NULL,
        cliente_id INTEGER,
        data_hora TEXT,
        duracao_minutos INTEGER,
        observacoes TEXT,
        FOREIGN KEY(cliente_id) REFERENCES clientes(id)
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS tecnicos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        criado_em TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()

# ================== ROTAS ==================

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(request: Request, nome: str = Form(...), usuario: str = Form(...), senha: str = Form(...)):
    db = get_db()
    try:
        senha_hash = ph.hash(senha)
        db.execute("INSERT INTO tecnicos (nome, usuario, senha_hash, criado_em) VALUES (?, ?, ?, ?)",
                   (nome, usuario.lower(), senha_hash, datetime.now().strftime("%Y-%m-%d %H:%M")))
        db.commit()
        tecnico_id = db.execute("SELECT id FROM tecnicos WHERE usuario = ?", (usuario.lower(),)).fetchone()['id']
        response = RedirectResponse("/dashboard")
        response.set_cookie(key="authenticated", value="true")
        response.set_cookie(key="tecnico_id", value=str(tecnico_id))
        db.close()
        return response
    except sqlite3.IntegrityError:
        db.close()
        return templates.TemplateResponse("register.html", {"request": request, "error": "Usuário já existe"})

@app.post("/login")
async def login(request: Request, usuario: str = Form(...), senha: str = Form(...)):
    db = get_db()
    tecnico = db.execute("SELECT * FROM tecnicos WHERE usuario = ?", (usuario.lower(),)).fetchone()
    db.close()
    if tecnico and ph.verify(tecnico['senha_hash'], senha):
        response = RedirectResponse("/dashboard")
        response.set_cookie(key="authenticated", value="true")
        response.set_cookie(key="tecnico_id", value=str(tecnico['id']))
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Usuário ou senha incorretos"})

@app.get("/dashboard")
@app.post("/dashboard")
async def dashboard(request: Request, busca: str = None):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    
    db = get_db()
    
    query = "SELECT * FROM clientes"
    params = []
    
    if busca:
        busca = busca.strip()
        query += " WHERE nome LIKE ? OR empresa LIKE ? OR cnpj LIKE ?"
        like_term = f"%{busca}%"
        params = [like_term, like_term, like_term]
    
    query += " ORDER BY nome"
    
    clientes = db.execute(query, params).fetchall()
    db.close()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "clientes": clientes
    })

@app.get("/add", response_class=HTMLResponse)
async def add_page(request: Request):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    return templates.TemplateResponse("add_cliente.html", {"request": request})

@app.post("/add")
async def add_cliente(
    request: Request,
    nome: str = Form(...),
    empresa: str = Form(""),  # opcional
    cnpj: str = Form(""),
    rustdesk_id: str = Form(...),
    senha: str = Form(""),     # opcional
    observacoes: str = Form(None)
):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    db = get_db()
    try:
        db.execute("""
        INSERT INTO clientes (nome, empresa, rustdesk_id, senha, observacoes, criado_em, status) 
        VALUES (?, ?, ?, ?, ?, ?, 'desconectado')
        """, (nome, empresa or None, rustdesk_id, senha or None, observacoes, datetime.now().strftime("%Y-%m-%d %H:%M")))
        db.commit()
        db.close()
        return RedirectResponse("/dashboard", status_code=303)
    except sqlite3.IntegrityError:
        db.close()
        return templates.TemplateResponse("add_cliente.html", {"request": request, "error": "ID RustDesk já existe"})

@app.get("/conectar/{cliente_id}")
async def conectar(cliente_id: int, request: Request):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    
    db = get_db()
    cliente = db.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    db.close()
    
    if not cliente:
        raise HTTPException(404)
    
    if RUSTDESK_PATH and os.path.isfile(RUSTDESK_PATH):
        args = [RUSTDESK_PATH, "--connect", cliente['rustdesk_id'].strip()]
        if cliente['senha']:
            args += ["--password", cliente['senha'].strip()]
        try:
            subprocess.Popen(args)
            print(f"[SUCESSO] RustDesk aberto para ID: {cliente['rustdesk_id']}")
        except Exception as e:
            print(f"[ERRO] Falha ao abrir RustDesk: {e}")
    else:
        print("[ERRO] RustDesk não encontrado – conexão automática desativada")
    
    # Atualiza status
    db = get_db()
    db.execute("UPDATE clientes SET status = 'conectado' WHERE id = ?", (cliente_id,))
    db.commit()
    db.close()
    
    return RedirectResponse("/dashboard")

@app.get("/finalizar/{cliente_id}")
async def finalizar(cliente_id: int, request: Request):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    db = get_db()
    db.execute("UPDATE clientes SET status = 'desconectado' WHERE id = ?", (cliente_id,))
    db.commit()
    db.close()
    return RedirectResponse("/dashboard")

@app.get("/logout")
async def logout():
    response = RedirectResponse("/")
    response.delete_cookie("authenticated")
    response.delete_cookie("tecnico_id")
    return response


@app.get("/editar/{cliente_id}", response_class=HTMLResponse)
async def editar_page(request: Request, cliente_id: int):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    
    db = get_db()
    cliente = db.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    db.close()
    
    if not cliente:
        raise HTTPException(404)
    
    return templates.TemplateResponse("editar_cliente.html", {"request": request, "cliente": cliente})


@app.post("/editar/{cliente_id}")
async def salvar_edicao(
    request: Request,
    cliente_id: int,
    nome: str = Form(...),
    empresa: str = Form(""),
    cnpj: str = Form(""),
    rustdesk_id: str = Form(...),
    senha: str = Form(""),
    observacoes: str = Form(None)
):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    
    db = get_db()
    
    # Verifica se o novo rustdesk_id já existe em outro cliente
    existente = db.execute(
        "SELECT id FROM clientes WHERE rustdesk_id = ? AND id != ?",
        (rustdesk_id, cliente_id)
    ).fetchone()
    
    if existente:
        db.close()
        cliente = db.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
        db.close()
        return templates.TemplateResponse("editar_cliente.html", {
            "request": request,
            "cliente": cliente,
            "error": "Este ID RustDesk já está cadastrado em outro cliente."
        })
    
    # Atualiza os dados (senha só altera se o campo não estiver vazio)
    if senha:
        db.execute("""
            UPDATE clientes 
            SET nome = ?, empresa = ?, rustdesk_id = ?, senha = ?, observacoes = ?
            WHERE id = ?
        """, (nome, empresa or None, rustdesk_id, senha, observacoes, cliente_id))
    else:
        db.execute("""
            UPDATE clientes 
            SET nome = ?, empresa = ?, rustdesk_id = ?, observacoes = ?
            WHERE id = ?
        """, (nome, empresa or None, rustdesk_id, observacoes, cliente_id))
    
    db.commit()
    db.close()
    
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/excluir/{cliente_id}")
async def excluir_cliente(cliente_id: int, request: Request):
    if request.cookies.get("authenticated") != "true":
        return RedirectResponse(url="/")
    
    db = get_db()
    db.execute("DELETE FROM clientes WHERE id = ?", (cliente_id,))
    db.commit()
    db.close()
    
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/teste")
async def teste():
    return {"mensagem": "Servidor está vivo!"}