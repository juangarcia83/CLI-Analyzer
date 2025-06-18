import argparse
import requests
from bs4 import BeautifulSoup
import socket
import asyncio
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
import aiohttp

console = Console()

# ----------- Encabezados y Cookies ------------

def analyze_headers(url, headers):
    console.rule("[bold blue] Análisis de Encabezados de Seguridad")
    security_headers = {
        "Content-Security-Policy": "❌",
        "Strict-Transport-Security": "❌",
        "X-Content-Type-Options": "❌",
        "X-Frame-Options": "❌",
        "Referrer-Policy": "❌",
        "Permissions-Policy": "❌",
    }
    for h in security_headers:
        if h in headers:
            security_headers[h] = "✅"

    table = Table(title="Cabeceras de Seguridad")
    table.add_column("Cabecera", style="cyan")
    table.add_column("Estado", style="green")
    for h, v in security_headers.items():
        table.add_row(h, v)
    console.print(table)

def analyze_cookies(cookies):
    console.rule("[bold blue] Análisis de Cookies")
    if not cookies:
        console.print("[green]No se detectaron cookies.")
        return
    for c in cookies:
        secure = "✅" if c.secure else "❌"
        http_only = "✅" if "httponly" in c._rest else "❌"
        console.print(f" - {c.name}: Secure={secure}, HttpOnly={http_only}")

# ----------- Formularios ------------

def analyze_forms(url, html):
    console.rule("[bold blue] Análisis de Formularios")
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        console.print("[green]No se detectaron formularios.")
        return
    for i, form in enumerate(forms, 1):
        action = form.get("action", "No definido")
        method = form.get("method", "GET").upper()
        inputs = [inp.get("type", "text") for inp in form.find_all("input")]
        console.print(f"[cyan]Formulario {i}:[/cyan] Acción={action}, Método={method}, Inputs={inputs}")

# ----------- Archivos sensibles ------------

SENSITIVE_PATHS = [
    "robots.txt", ".env", "phpinfo.php", ".git/config", ".htaccess", "admin/", "backup.zip", "db.sql"
]

async def check_file(session, base, path):
    url = urljoin(base, path)
    try:
        async with session.get(url, timeout=5) as resp:
            if resp.status == 200:
                return (path, url)
    except:
        return None

async def scan_sensitive_files(url):
    console.rule("[bold blue] Archivos/Directorios Sensibles")
    found = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_file(session, url, path) for path in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)
        found = [r for r in results if r]
    if found:
        for path, full_url in found:
            console.print(f"[bold red]⚠️ Encontrado: {path} → {full_url}")
    else:
        console.print("[green]No se detectaron archivos sensibles.")

# ----------- Puertos comunes ------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

def scan_ports(host):
    console.rule("[bold blue] Escaneo de Puertos Comunes")
    try:
        ip = socket.gethostbyname(host)
        open_ports = []
        for port in COMMON_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        if open_ports:
            for p in open_ports:
                console.print(f"[yellow]Puerto abierto:[/yellow] {p}")
        else:
            console.print("[green]No se detectaron puertos abiertos.")
    except Exception as e:
        console.print(f"[red]Error al escanear puertos: {e}")

# ----------- CLI principal ------------

def main():
    parser = argparse.ArgumentParser(description="🔎 Auditoría Web Ética")
    parser.add_argument("-c", "--check", type=str, help="URL a analizar", required=True)
    parser.add_argument("--headers", action="store_true", help="Analizar encabezados HTTP")
    parser.add_argument("--cookies", action="store_true", help="Analizar cookies")
    parser.add_argument("--forms", action="store_true", help="Buscar formularios")
    parser.add_argument("--files", action="store_true", help="Buscar archivos/directorios sensibles")
    parser.add_argument("--ports", action="store_true", help="Escanear puertos comunes")
    args = parser.parse_args()

    url = args.check
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)

    try:
        response = requests.get(url, timeout=10)
        html = response.text
        headers = response.headers
        cookies = response.cookies
    except Exception as e:
        console.print(f"[red]Error al conectar con la URL: {e}")
        return

    if args.headers:
        analyze_headers(url, headers)
    if args.cookies:
        analyze_cookies(cookies)
    if args.forms:
        analyze_forms(url, html)
    if args.files:
        asyncio.run(scan_sensitive_files(url))
    if args.ports and parsed.hostname:
        scan_ports(parsed.hostname)

if __name__ == "__main__":
    main()
