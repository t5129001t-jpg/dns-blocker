import asyncio
import socket
import time
import sqlite3
import dns.message
import dns.rdatatype
import dns.resolver
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import uvicorn

# --- КОНФИГУРАЦИЯ ---
LISTEN_PORT = 1053
WEB_PORT = 8000
UPSTREAM_DNS = "1.1.1.1"
BLOCKLIST_FILE = "lists/blocklist.txt"
DB_FILE = "stats.db"

blocked_domains = set()
db_conn = None
sock = None

# --- БАЗА ДАННЫХ ---
def init_db():
    global db_conn
    db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cursor = db_conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL, domain TEXT, action TEXT, response_time_ms REAL)''')
    db_conn.commit()

def load_blocklist():
    global blocked_domains
    try:
        with open(BLOCKLIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('!'):
                    if '||' in line:
                        domain = line.split('||')[1].split('^')[0]
                        if domain: blocked_domains.add(domain.lower())
                    elif '.' in line:
                         blocked_domains.add(line.lower())
        print(f"[INFO] Загружено {len(blocked_domains)} доменов.")
    except FileNotFoundError:
        print("[WARN] blocklist.txt не найден.")

def log_query(domain, action, response_time_ms):
    cursor = db_conn.cursor()
    cursor.execute("INSERT INTO logs (timestamp, domain, action, response_time_ms) VALUES (?, ?, ?, ?)",
        (time.time(), domain, action, response_time_ms))
    db_conn.commit()

# --- DNS ЛОГИКА ---
async def handle_dns_packet(data, addr):
    start_time = time.time()
    try:
        request = dns.message.from_wire(data)
        if not request.question: return
        
        qname = request.question[0].name.to_text().rstrip('.')
        qtype = request.question[0].rdtype
        
        if qname.lower() in blocked_domains:
            print(f"[BLOCK] {qname}")
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.NXDOMAIN)
            sock.sendto(response.to_wire(), addr)
            log_query(qname, "BLOCKED", (time.time() - start_time) * 1000)
            return

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [UPSTREAM_DNS]
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        
        try:
            answer = resolver.resolve(qname, dns.rdatatype.RdataType(qtype))
            response = dns.message.make_response(request)
            response.answer = answer.response.answer
            sock.sendto(response.to_wire(), addr)
            log_query(qname, "ALLOWED", (time.time() - start_time) * 1000)
        except Exception:
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.SERVFAIL)
            sock.sendto(response.to_wire(), addr)
    except Exception as e:
        print(f"[ERR] {e}")

async def dns_server_loop():
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', LISTEN_PORT))
    sock.setblocking(False)
    print(f"👂 DNS сервер запущен на порту {LISTEN_PORT}")
    
    loop = asyncio.get_event_loop()
    while True:
        try:
            data, addr = await loop.sock_recvfrom(sock, 4096)
            asyncio.create_task(handle_dns_packet(data, addr))
        except Exception as e:
            print(f"DNS Loop Error: {e}")

# --- LIFESPAN (вместо on_event) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Инициализация...")
    load_blocklist()
    init_db()
    asyncio.create_task(dns_server_loop())
    yield
    print("🛑 Завершение работы...")
    if db_conn:
        db_conn.close()
    if sock:
        sock.close()

# --- ВЕБ ИНТЕРФЕЙС ---
app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/stats")
async def get_stats():
    cursor = db_conn.cursor()
    
    now = time.time()
    day_ago = now - 86400
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE timestamp > ?", (day_ago,))
    total_req = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE timestamp > ? AND action='BLOCKED'", (day_ago,))
    total_blocked = cursor.fetchone()[0]
    
    cursor.execute("SELECT domain, COUNT(*) as count FROM logs WHERE action='BLOCKED' GROUP BY domain ORDER BY count DESC LIMIT 5")
    top_blocked = cursor.fetchall()
    
    return {
        "total_requests": total_req,
        "total_blocked": total_blocked,
        "top_blocked": top_blocked
    }
# Добавьте этот код перед последней строкой файла

@app.get("/api/stats")
async def get_stats():
    cursor = db_conn.cursor()
    
    now = time.time()
    day_ago = now - 86400
    
    # Общая статистика
    cursor.execute("SELECT COUNT(*) FROM logs WHERE timestamp > ?", (day_ago,))
    total_req = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM logs WHERE timestamp > ? AND action='BLOCKED'", (day_ago,))
    total_blocked = cursor.fetchone()[0]
    
    # Топ заблокированных
    cursor.execute("SELECT domain, COUNT(*) as count FROM logs WHERE action='BLOCKED' GROUP BY domain ORDER BY count DESC LIMIT 5")
    top_blocked = cursor.fetchall()
    
    # Почасовая статистика для графика
    cursor.execute("""
        SELECT strftime('%H:00', datetime(timestamp, 'unixepoch')) as hour, 
               COUNT(*) as count 
        FROM logs 
        WHERE timestamp > ? 
        GROUP BY hour 
        ORDER BY hour
    """, (day_ago,))
    hourly_stats = cursor.fetchall()
    
    return {
        "total_requests": total_req,
        "total_blocked": total_blocked,
        "top_blocked": top_blocked,
        "hourly_stats": [{"hour": h[0], "count": h[1]} for h in hourly_stats]
    }

@app.post("/api/add-block")
async def add_to_blocklist(request: Request):
    try:
        data = await request.json()
        domain = data.get('domain', '').strip().lower()
        
        if not domain or '.' not in domain:
            return {"success": False, "message": "Некорректный домен"}
        
        # Добавляем в глобальный набор
        blocked_domains.add(domain)
        
        # Сохраняем в файл
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(f"\n{domain}")
        
        print(f"[INFO] Добавлен новый домен в чёрный список: {domain}")
        return {"success": True, "message": f"Домен {domain} заблокирован"}
        
    except Exception as e:
        return {"success": False, "message": str(e)}
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=WEB_PORT)
