import os, json, sqlite3, time, base64, zipfile, hashlib
from pathlib import Path
from functools import wraps
from hashlib import sha256
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_from_directory
import jwt, requests
from cryptography.fernet import Fernet
import base64 as b64

# ========= CONFIG & DIRS =========
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"
EXPORTS_DIR = DATA_DIR / "exports"
for d in (DATA_DIR, FRONTEND_DIR, EXPORTS_DIR): d.mkdir(parents=True, exist_ok=True)

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
BUDGET_TOKENS = {
  "openai": int(os.getenv("BUDGET_TOKENS_OPENAI","0") or 0),
  "anthropic": int(os.getenv("BUDGET_TOKENS_ANTHROPIC","0") or 0),
  "google": int(os.getenv("BUDGET_TOKENS_GOOGLE","0") or 0),
  "mistral": int(os.getenv("BUDGET_TOKENS_MISTRAL","0") or 0),
}

app = Flask(__name__, static_folder="frontend", static_url_path="")

# ========= DB =========
DB_PATH = DATA_DIR / "app.db"
def db():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c
def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
           id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT, created_at INTEGER)""")
        con.execute("""CREATE TABLE IF NOT EXISTS api_keys(
           id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, provider TEXT, alias TEXT,
           key_hash TEXT, key_mask TEXT, key_enc BLOB, last_status TEXT, last_checked INTEGER)""")
        con.execute("""CREATE TABLE IF NOT EXISTS exports(
           id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, product_name TEXT, version TEXT,
           zip_path TEXT, size_bytes INTEGER, checksums_json TEXT, created_at INTEGER)""")
        con.execute("""CREATE TABLE IF NOT EXISTS costs(
           id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, provider TEXT, tokens INTEGER, calls INTEGER, period TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS settings(
           id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, key TEXT, value TEXT, UNIQUE(user_id,key))""")
init_db()

# ========= CRYPTO (API keys) =========
def fernet_key_from_secret(s: str) -> bytes:
    raw = sha256(s.encode()).digest()
    return b64.urlsafe_b64encode(raw)
FERNET = Fernet(fernet_key_from_secret(JWT_SECRET))
def enc(s:str)->bytes: return FERNET.encrypt(s.encode())
def dec(b:bytes)->str: return FERNET.decrypt(b).decode()

# ========= AUTH =========
def token_required(f):
    @wraps(f)
    def w(*a, **k):
        auth = request.headers.get("Authorization","")
        if not auth.startswith("Bearer "): return jsonify({"error":"missing_token"}), 401
        try: payload = jwt.decode(auth.split(" ",1)[1], JWT_SECRET, algorithms=["HS256"])
        except Exception as e: return jsonify({"error":"invalid_token","detail":str(e)}), 401
        request.user_id = payload["uid"]; return f(*a,**k)
    return w

@app.post("/auth/register")
def register():
    d = request.get_json(force=True); email = (d.get("email") or "").strip().lower(); pwd = d.get("password") or ""
    if not email or not pwd: return jsonify({"error":"missing_fields"}), 400
    h = sha256(pwd.encode()).hexdigest()
    try:
        with db() as con: con.execute("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)",(email,h,int(time.time())))
    except sqlite3.IntegrityError: return jsonify({"error":"email_exists"}), 400
    return jsonify({"ok":True})

@app.post("/auth/login")
def login():
    d = request.get_json(force=True); email=(d.get("email") or "").strip().lower(); pwd=d.get("password") or ""
    with db() as con:
        row = con.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
        if not row or sha256(pwd.encode()).hexdigest()!=row["password_hash"]: return jsonify({"error":"invalid_credentials"}), 401
        uid=row["id"]
    exp = datetime.utcnow()+timedelta(days=7)
    tok = jwt.encode({"uid":uid,"exp":exp}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token":tok})

# ========= KEYS =========
def detect_provider(k:str):
    if k.startswith("sk-"): return "openai"
    if k.startswith("sk-ant-"): return "anthropic"
    if k.startswith("AIza"): return "google"
    if k.startswith("mistral-"): return "mistral"
    return "unknown"
def mask_key(k:str): return "*"*(len(k)-4)+k[-4:]

def check_key(provider,k):
    try:
        if provider=="openai":
            r=requests.get("https://api.openai.com/v1/models",headers={"Authorization":f"Bearer {k}"},timeout=12)
        elif provider=="anthropic":
            r=requests.get("https://api.anthropic.com/v1/models",headers={"x-api-key":k,"anthropic-version":"2023-06-01"},timeout=12)
        elif provider=="google":
            r=requests.get("https://generativelanguage.googleapis.com/v1/models",params={"key":k},timeout=12)
        elif provider=="mistral":
            r=requests.get("https://api.mistral.ai/v1/models",headers={"Authorization":f"Bearer {k}"},timeout=12)
        else: return "UNKNOWN"
        if r.status_code==200: return "OK"
        if r.status_code in (401,403): return "INVALID_KEY"
        if r.status_code==429: return "RATE_LIMITED"
        return "UNKNOWN"
    except requests.exceptions.RequestException: return "NETWORK_ERROR"

SUGGEST = {
  "openai":["gpt-5","gpt-4o","gpt-4o-mini"],
  "anthropic":["claude-3-5-sonnet","claude-3-opus"],
  "google":["gemini-1.5-pro","gemini-1.5-flash"],
  "mistral":["mistral-large","mistral-small"]
}

@app.post("/keys/verify")
@token_required
def keys_verify():
    d=request.get_json(force=True); raw=(d.get("api_key") or "").strip(); alias=(d.get("label") or "").strip()
    if not raw: return jsonify({"error":"missing_api_key"}),400
    prov=detect_provider(raw); status=check_key(prov,raw) if prov!="unknown" else "UNKNOWN"
    with db() as con:
        con.execute("""INSERT INTO api_keys(user_id,provider,alias,key_hash,key_mask,key_enc,last_status,last_checked)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (request.user_id,prov,alias or prov,sha256(raw.encode()).hexdigest(),mask_key(raw),enc(raw),status,int(time.time())))
    acts=[]
    if status in ("INVALID_KEY","BILLING_INACTIVE"): acts.append({"label":"Apri billing","url":""})
    if status=="RATE_LIMITED": acts.append({"label":"Riprova tra 60s"})
    return jsonify({"provider":prov,"model_suggestion":SUGGEST.get(prov,[]),"status":status,"actions":acts})

@app.get("/keys/status")
@token_required
def keys_status():
    with db() as con:
        rows=con.execute("""SELECT id,provider,alias,key_mask,last_status,last_checked
                            FROM api_keys WHERE user_id=? ORDER BY id DESC""",(request.user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.delete("/keys/<int:key_id>")
@token_required
def keys_delete(key_id):
    with db() as con: con.execute("DELETE FROM api_keys WHERE id=? AND user_id=?", (key_id, request.user_id))
    return jsonify({"ok":True})

def active_keys(user_id:int):
    order=("openai","anthropic","google","mistral"); out=[]
    with db() as con:
        for p in order:
            r=con.execute("""SELECT key_enc FROM api_keys WHERE user_id=? AND provider=? ORDER BY id DESC LIMIT 1""",(user_id,p)).fetchone()
            if r: out.append((p,dec(r["key_enc"])))
    return out

# ========= COSTS & BUDGET =========
def add_cost(user_id, provider, tokens, calls=1):
    period=datetime.utcnow().strftime("%Y-%m")
    with db() as con:
        r=con.execute("""SELECT id,tokens,calls FROM costs WHERE user_id=? AND provider=? AND period=?""",(user_id,provider,period)).fetchone()
        if r:
            con.execute("UPDATE costs SET tokens=?, calls=? WHERE id=?", (r["tokens"]+tokens, r["calls"]+calls, r["id"]))
        else:
            con.execute("INSERT INTO costs(user_id,provider,tokens,calls,period) VALUES (?,?,?,?,?)",(user_id,provider,tokens,calls,period))

def budget_ok(user_id, provider):
    lim=BUDGET_TOKENS.get(provider,0)
    if not lim: return True, None
    with db() as con:
        r=con.execute("""SELECT COALESCE(SUM(tokens),0) as used FROM costs
                         WHERE user_id=? AND provider=? AND period=?""",(user_id,provider,datetime.utcnow().strftime("%Y-%m"))).fetchone()
    used=r["used"] if r else 0
    return used<lim, (lim-used)

@app.get("/costs")
@token_required
def costs():
    with db() as con:
        rows=con.execute("""SELECT provider, SUM(tokens) as tokens, SUM(calls) as calls
                            FROM costs WHERE user_id=? GROUP BY provider""",(request.user_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ========= LLM CALLS (fallback) =========
def call_openai(k,prompt,model="gpt-4o",max_tokens=1800):
    r=requests.post("https://api.openai.com/v1/chat/completions",
        headers={"Authorization":f"Bearer {k}","Content-Type":"application/json"},
        json={"model":model,"messages":[{"role":"system","content":"You are a product content generator."},{"role":"user","content":prompt}],
              "temperature":0.6,"max_tokens":max_tokens},timeout=40)
    r.raise_for_status(); out=r.json()
    txt=out["choices"][0]["message"]["content"]; used=out.get("usage",{}).get("total_tokens",int(len(prompt+txt)/4))
    return txt,used

def call_anthropic(k,prompt,model="claude-3-5-sonnet-20240620",max_tokens=1800):
    r=requests.post("https://api.anthropic.com/v1/messages",
        headers={"x-api-key":k,"anthropic-version":"2023-06-01","content-type":"application/json"},
        json={"model":model,"max_tokens":max_tokens,"messages":[{"role":"user","content":prompt}]},timeout=40)
    r.raise_for_status(); out=r.json()
    txt="".join([c["text"] for c in out.get("content",[]) if c.get("type")=="text"])
    used=out.get("usage",{}).get("input_tokens",0)+out.get("usage",{}).get("output_tokens",0)
    if not used: used=int(len(prompt+txt)/4)
    return txt,used

def try_generate(user_id, prompt, max_tokens=2000):
    warns=[]
    for prov,key in active_keys(user_id):
        ok,remain=budget_ok(user_id,prov)
        if not ok: warns.append(f"budget_exceeded:{prov}"); continue
        try:
            if prov=="openai": txt,toks=call_openai(key,prompt,"gpt-4o",max_tokens)
            elif prov=="anthropic": txt,toks=call_anthropic(key,prompt,"claude-3-5-sonnet-20240620",max_tokens)
            else: txt,toks=call_openai(key,prompt,"gpt-4o-mini",max_tokens)
            add_cost(user_id,prov,toks); return {"ok":True,"provider":prov,"text":txt,"tokens":toks,"warnings":warns}
        except Exception: warns.append(f"provider_error:{prov}"); continue
    return {"ok":False,"error":"no_provider_available","warnings":warns}

@app.post("/gen/idea")
@token_required
def gen_idea():
    d=request.get_json(force=True); niche=(d.get("niche") or "digital products").strip(); lang=(d.get("lang") or "it").lower()
    prompt=f"Genera 5 idee di prodotto digitale per la nicchia: {niche}. Per ogni idea: nome, promise, cosa include, differenziatore. Lingua: {lang}."
    out=try_generate(request.user_id,prompt,1200); 
    if not out["ok"]: return jsonify(out),429
    return jsonify({"provider":out["provider"],"ideas":out["text"],"warnings":out["warnings"]})

@app.post("/gen/content")
@token_required
def gen_content():
    d=request.get_json(force=True); idea=d.get("idea") or "AI Prompt Vault"; lang=(d.get("lang") or "it").lower()
    prompt=f"""Crea contenuti completi per: {idea}. Output in {lang}.
1) README (Markdown)
2) LICENSE (Markdown, uso personale)
3) GUIDA_UTENTE (Markdown)
4) PROMPT_PACK_EN (solo testo in inglese)
5) PROMPT_PACK_{lang.upper()} (solo testo in {lang})."""
    out=try_generate(request.user_id,prompt,3000); 
    if not out["ok"]: return jsonify(out),429
    return jsonify({"provider":out["provider"],"content":out["text"],"warnings":out["warnings"]})

@app.post("/gen/listing")
@token_required
def gen_listing():
    d=request.get_json(force=True); product=d.get("product_name") or "AI Prompt Vault"; lang=(d.get("lang") or "it").lower()
    prompt=f"""Scrivi il listing per Etsy e Gumroad del prodotto: {product}. Lingua: {lang}.
Restituisci JSON con: title, description (max 1000 parole), tags (20), price_suggestion (EUR)."""
    out=try_generate(request.user_id,prompt,1200); 
    if not out["ok"]: return jsonify(out),429
    try: listing=json.loads(out["text"])
    except Exception: listing={"raw":out["text"]}
    return jsonify({"provider":out["provider"],"listing":listing,"warnings":out["warnings"]})

# ========= EXPORT (PDF/ZIP + SBOM + CHECKSUMS) =========
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
def md_to_plain(md:str):
    txt=[]; 
    for line in md.splitlines():
        line=line.replace('**','').replace('__','').lstrip('# ').replace('* ','• ')
        txt.append(line)
    return "\n".join(txt)
def render_pdf_bytes(title, content_md, author=""):
    from io import BytesIO
    buf=BytesIO(); c=canvas.Canvas(buf, pagesize=A4); w,h=A4
    c.setTitle(title); c.setAuthor(author or "AI Product Factory")
    left, top = 20*mm, h-20*mm; c.setFont("Helvetica",16); c.drawString(left, top, title)
    c.setFont("Helvetica",11); y=top-12*mm; text=md_to_plain(content_md)
    from textwrap import wrap
    for paragraph in text.split("\n\n"):
        for line in wrap(paragraph, width=100):
            if y<25*mm: c.showPage(); c.setFont("Helvetica",11); y=h-25*mm
            c.drawString(left,y,line); y-=6*mm
        y-=3*mm
    c.showPage(); c.save(); return buf.getvalue()

def safe_name(name:str):
    import re
    name=name.strip().replace(" ","_")
    return re.sub(r"[^A-Za-z0-9_\-\.]+","",name)

def sha256_file(p:Path):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

@app.post("/export/zip")
@token_required
def export_zip():
    m=request.get_json(force=True)
    product=safe_name(m.get("product_name") or "PRODUCT"); version=safe_name(m.get("version") or "1.0.0")
    branding=(m.get("branding") or {}); author=branding.get("author","")
    root=EXPORTS_DIR/f"{product}_v{version}"; (root / "PROMPTS").mkdir(parents=True, exist_ok=True); (root/"MEDIA").mkdir(exist_ok=True)

    # PDFs
    for a in (m.get("assets") or []):
        if a.get("type")=="pdf":
            name=safe_name(a.get("name") or "DOC"); pdf=render_pdf_bytes(name, a.get("content_md") or "", author)
            with open(root/f"{name}.pdf","wb") as f: f.write(pdf)
        elif a.get("type")=="txt":
            name=safe_name(a.get("name") or "FILE")
            (root/"PROMPTS"/f"{name}.txt").write_text(a.get("content") or "", encoding="utf-8")
        elif a.get("type") in ("png_base64","image_base64"):
            data_b64=(a.get("data") or ""); 
            with open(root/"MEDIA"/"COVER.png","wb") as f: f.write(base64.b64decode(data_b64.split(",")[-1]))

    # listing.json
    listing=m.get("listing") or {}
    (root/"listing.json").write_text(json.dumps(listing,ensure_ascii=False,indent=2),encoding="utf-8")

    # SBOM
    try:
        import importlib.metadata as md
        libs={d.metadata["Name"]: d.version for d in md.distributions()
              if d.metadata.get("Name") in ["Flask","reportlab","requests","PyJWT","cryptography"]}
    except Exception: libs={}
    (root/"SBOM.json").write_text(json.dumps({
        "generated_at": int(time.time()),
        "components": [{"name":k,"version":v} for k,v in libs.items()],
        "notes": "AI-assisted export; includes hashes in CHECKSUMS.txt"
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    # CHECKSUMS
    checksums={}
    for p in root.rglob("*"):
        if p.is_file(): checksums[str(p.relative_to(root))]=sha256_file(p)
    (root/"CHECKSUMS.txt").write_text("\n".join([f"{h}  {f}" for f,h in checksums.items()]), encoding="utf-8")

    # ZIP
    zip_path=EXPORTS_DIR/f"{product}_v{version}.zip"
    with zipfile.ZipFile(zip_path,"w",zipfile.ZIP_DEFLATED) as z:
        for r,_,files in os.walk(root):
            for f in files:
                ab=Path(r)/f; rel=ab.relative_to(root); z.write(ab, arcname=str(rel))
    size=zip_path.stat().st_size
    with db() as con:
        con.execute("""INSERT INTO exports(user_id,product_name,version,zip_path,size_bytes,checksums_json,created_at)
                       VALUES (?,?,?,?,?,?,?)""",(request.user_id,product,version,str(zip_path),size,json.dumps(checksums),int(time.time())))
    return jsonify({"zip_path":str(zip_path),"size_bytes":size,"download_url":f"{BASE_URL}/download/{zip_path.name}","checksums":checksums})

@app.get("/download/<path:filename>")
def download(filename): return send_from_directory(EXPORTS_DIR, filename, as_attachment=True)

@app.get("/exports")
@token_required
def exports_list():
    with db() as con:
        rows=con.execute("""SELECT product_name,version,zip_path,size_bytes,created_at
                            FROM exports WHERE user_id=? ORDER BY id DESC""",(request.user_id,)).fetchall()
    def row2(x):
        return {"product_name":x["product_name"],"version":x["version"],"size_bytes":x["size_bytes"],
                "created_at":x["created_at"],"download_url":f"{BASE_URL}/download/{Path(x['zip_path']).name}"}
    return jsonify([row2(r) for r in rows])

# ========= SETTINGS =========
@app.get("/settings")
@token_required
def settings_get():
    with db() as con:
        rows=con.execute("SELECT key,value FROM settings WHERE user_id=?", (request.user_id,)).fetchall()
    return jsonify({r["key"]: r["value"] for r in rows})

@app.post("/settings")
@token_required
def settings_post():
    d=request.get_json(force=True) or {}
    with db() as con:
        for k,v in d.items():
            con.execute("""INSERT INTO settings(user_id,key,value) VALUES (?,?,?)
                           ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value""",
                        (request.user_id,k,json.dumps(v) if isinstance(v,(dict,list)) else str(v)))
    return jsonify({"ok":True})

# ========= HEALTH =========
@app.get("/healthz")
def healthz():
    try:
        t=EXPORTS_DIR/".write_test"; t.write_text("ok",encoding="utf-8"); t.unlink(missing_ok=True); st="green"
    except Exception: st="red"
    return jsonify({"status":st,"time":int(time.time())})

# ========= FRONTEND (autogenerate files on first run) =========
INDEX_HTML = """<!doctype html><html lang="it"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="manifest" href="/manifest.webmanifest"><meta name="theme-color" content="#0ea5e9"/>
<title>AI Product Factory</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><h1>AI Product Factory™</h1><div id="loginBox"></div></header>
<main id="app" class="hidden">
<section><h2>Key Manager</h2>
<input id="keyInput" placeholder="Incolla API key (OpenAI/Anthropic/Google/Mistral)"/>
<input id="keyLabel" placeholder="Etichetta (opzionale)"/><button id="btnVerify">Verifica</button>
<pre id="keyResult"></pre></section>
<section><h2>Generazione</h2>
<input id="niche" placeholder="Niche (es: Canva templates premium)"/>
<select id="lang"><option value="it">Italiano</option><option value="en">English</option></select>
<button id="btnIdea">Genera Idee</button><pre id="ideas"></pre>
<input id="idea" placeholder="Idea scelta (incolla o scrivi)"/><button id="btnContent">Genera Contenuti</button>
<pre id="genContent"></pre><input id="prod" placeholder="Nome prodotto per listing"/>
<button id="btnListing">Genera Listing</button><pre id="genListing"></pre><div id="warnings" class="muted"></div></section>
<section><h2>Wizard Manifest</h2>
<input id="prodName" placeholder="Nome prodotto" value="AI_Prompt_Vault"/>
<input id="prodVersion" placeholder="Versione" value="1.0.0"/>
<textarea id="readme" rows="5" pl
