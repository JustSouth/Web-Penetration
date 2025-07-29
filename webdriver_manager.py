import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import config # config.py dosyasını import ediyoruz
import json

class WebDriverManager:
    def __init__(self, logger):
        self.logger = logger
        self._driver = None
        self.chromedriver_path = self._get_saved_chromedriver_path()
        self.screenshot_dir = self._get_saved_screenshot_dir()
        os.makedirs(self.screenshot_dir, exist_ok=True) # Ekran görüntüsü klasörünü oluştur

    def _get_saved_chromedriver_path(self):
        # Ayarlar dosyasından chromedriver yolunu oku veya varsayılanı kullan
        settings_file = os.path.join(config.BASE_DIR, "settings.json")
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    return settings.get('chromedriver_path', config.CHROME_DRIVER_PATH)
            except json.JSONDecodeError:
                self.logger.warning("settings.json dosyası bozuk, varsayılan ChromeDriver yolu kullanılıyor.")
        return config.CHROME_DRIVER_PATH

    def _get_saved_screenshot_dir(self):
        settings_file = os.path.join(config.BASE_DIR, "settings.json")
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    return settings.get('screenshot_dir', config.SCREENSHOT_DIR)
            except json.JSONDecodeError:
                self.logger.warning("settings.json dosyası bozuk, varsayılan ekran görüntüsü klasörü kullanılıyor.")
        return config.SCREENSHOT_DIR

    def _save_settings(self):
        settings_file = os.path.join(config.BASE_DIR, "settings.json")
        settings = {
            'chromedriver_path': self.chromedriver_path,
            'screenshot_dir': self.screenshot_dir
        }
        try:
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            self.logger.error(f"Ayarlar kaydedilirken hata oluştu: {e}")

    def update_chromedriver_path(self, new_path):
        self.chromedriver_path = new_path
        self._save_settings()

    def update_screenshot_dir(self, new_dir):
        self.screenshot_dir = new_dir
        os.makedirs(self.screenshot_dir, exist_ok=True) # Yeni klasörü oluştur
        self._save_settings()

    def initialize_driver(self):
        if self._driver:
            self.quit_driver() # Eğer zaten varsa, önce kapat

        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Tarayıcıyı gizli çalıştır
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--log-level=3") # Daha az log çıktısı

            service = Service(executable_path=self.chromedriver_path)
            self._driver = webdriver.Chrome(service=service, options=chrome_options)
            self._driver.set_page_load_timeout(20)
            self._driver.implicitly_wait(5)
            self.logger("Chrome WebDriver başarıyla başlatıldı (headless modda).\n", "success")
            return self._driver
        except WebDriverException as e:
            self.logger(f"Chrome WebDriver başlatılamadı: {str(e)}\n", "error")
            self.logger(f"Lütfen Chrome WebDriver'ın '{self.chromedriver_path}' yolunda olduğundan ve Chrome sürümünüzle uyumlu olduğundan emin olun.\n", "warning")
            return None
        except Exception as e:
            self.logger(f"Beklenmeyen bir hata oluştu: {str(e)}\n", "error")
            return None

    def get_driver(self):
        return self._driver

    def quit_driver(self):
        if self._driver:
            self.logger("Chrome WebDriver kapatılıyor...\n", "info")
            self._driver.quit()
            self._driver = None
            self.logger("Chrome WebDriver kapatıldı.\n", "success")

    def take_screenshot(self, filename="screenshot.png"):
        if not self._driver:
            self.logger("Ekran görüntüsü alınamadı: WebDriver mevcut değil.", "warning")
            return None
        
        filepath = os.path.join(self.screenshot_dir, filename)
        try:
            self._driver.save_screenshot(filepath)
            self.logger(f"Ekran görüntüsü kaydedildi: {filepath}", "info")
            return filepath
        except Exception as e:
            self.logger(f"Ekran görüntüsü alınırken hata oluştu: {e}", "error")
            return None