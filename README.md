# 🔍 WebAudit: Herramienta Ética de Auditoría Web

WebAudit es una herramienta de **auditoría web básica y ética**, escrita en Python, pensada para realizar análisis pasivo y mínimamente intrusivo sobre sitios web. Está orientada a estudiantes de ciberseguridad, pentesters en formación y desarrolladores que deseen evaluar la configuración de seguridad de sus propios sitios.

---

## ✅ Funcionalidades

WebAudit permite realizar auditorías sobre una URL proporcionada, y seleccionar los módulos que deseas ejecutar:

| Módulo               | Descripción                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `--headers`          | Verifica si las cabeceras de seguridad están presentes                      |
| `--cookies`          | Evalúa si las cookies usan atributos `Secure` y `HttpOnly`                 |
| `--forms`            | Detecta formularios HTML y posibles problemas (método GET inseguro, etc.)   |
| `--files`            | Busca archivos/directorios sensibles (`.env`, `.git`, `phpinfo.php`, etc.)  |
| `--ports`            | Escanea puertos comunes del servidor (80, 443, 22, etc.)                    |

---

## 🚀 Instalación

### Requisitos:

- Python 3.7 o superior
- Librerías de Python:

```bash
pip install -r requirements.txt
