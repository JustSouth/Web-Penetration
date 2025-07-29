import tkinter as tk
from tkinter import messagebox, Scrollbar, Text, Label, Checkbutton, IntVar, Frame
import tkinter.ttk as ttk
import threading
import os
import sys
import json
import logging # Python'ın kendi logging modülünü kullanacağız

# Kendi modüllerimizi import ediyoruz
from utils.logger import setup_logging, get_logger
from utils.webdriver_manager import WebDriverManager
from scanner_core import ScannerCore
from vulnerability_tests.sql_injector import SQLInjector
from vulnerability_tests.xss_tester import XSSTester
from config import SQL_PAYLOADS_FILE, XSS_PAYLOADS_FILE, DEFAULT_SQL_PAYLOADS, DEFAULT_XSS_PAYLOADS

# Logger'ı ayarlayın
setup_logging()
app_logger = get_logger("AppLogger")

class WebPenetrationScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gelişmiş Web Güvenliği Tarayıcı (v3.0 - Akıllı ve Hedef Odaklı)")
        self.root.geometry("1800x980")
        self.root.configure(bg="#2F3238")

        self.url_var = tk.StringVar()
        self.test_status_var = tk.StringVar()
        self.test_status_var.set("Hazır.")

        self.is_scanning_or_testing = False

        # Test seçimi değişkenleri
        self.enable_sql_test = IntVar(value=1) # Varsayılan olarak açık
        self.enable_xss_test = IntVar(value=1) # Varsayılan olarak açık

        self.driver_manager = WebDriverManager(app_logger)
        self.driver = None # WebDriver, tarama başladığında başlatılacak

        self.create_widgets()
        self.initialize_payload_files()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def initialize_payload_files(self):
        # Payload dosyalarını kontrol et ve yoksa varsayılanları yaz
        try:
            if not os.path.exists(SQL_PAYLOADS_FILE):
                with open(SQL_PAYLOADS_FILE, 'w', encoding='utf-8') as f:
                    for p in DEFAULT_SQL_PAYLOADS:
                        f.write(f"{p}\n")
                app_logger.info(f"SQL payload dosyası oluşturuldu: {SQL_PAYLOADS_FILE}")

            if not os.path.exists(XSS_PAYLOADS_FILE):
                with open(XSS_PAYLOADS_FILE, 'w', encoding='utf-8') as f:
                    for p in DEFAULT_XSS_PAYLOADS:
                        f.write(f"{p}\n")
                app_logger.info(f"XSS payload dosyası oluşturuldu: {XSS_PAYLOADS_FILE}")

            # Payloadları metin kutularına yükle
            with open(SQL_PAYLOADS_FILE, 'r', encoding='utf-8') as f:
                self.sql_payload_text.insert(tk.END, f.read())
            with open(XSS_PAYLOADS_FILE, 'r', encoding='utf-8') as f:
                self.xss_payload_text.insert(tk.END, f.read())

        except Exception as e:
            app_logger.error(f"Payload dosyaları yüklenirken hata oluştu: {e}")
            messagebox.showerror("Hata", f"Payload dosyaları yüklenirken hata oluştu: {e}")

    def create_widgets(self):
        # Stil tanımlamaları
        label_font = ("Segoe UI", 10, "bold")
        entry_font = ("Segoe UI", 10)
        button_font = ("Segoe UI", 10, "bold")
        text_font = ("Consolas", 9)

        fg_color = "#E0E0E0"
        bg_color = "#2F3238"
        button_bg_blue = "#1E88E5"
        button_bg_green = "#4CAF50"
        button_fg_white = "#FFFFFF"
        checkbox_bg = "#3A3E47"
        listbox_bg = "#3A3E47"
        listbox_fg = "#E0E0E0"
        output_bg = "#212121"
        output_fg = "#FFFFFF"
        payload_text_bg = "#3A3A3A"
        exploit_output_bg = "#1A1A1A"
        summary_bg = "#282C34"

        self.main_frame = tk.Frame(self.root, bg=bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1) # Tek bir ana çerçeve gibi davranacak

        # Notebook (Sekmeler) oluşturma
        self.notebook = tk.ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        # Sekme 1: Ana Tarama Ekranı
        self.scan_tab = tk.Frame(self.notebook, bg=bg_color)
        self.notebook.add(self.scan_tab, text=" Ana Tarama ")
        self.scan_tab.columnconfigure(0, weight=1)
        self.scan_tab.columnconfigure(1, weight=1)
        self.scan_tab.rowconfigure(7, weight=1) # Test Sonuçları için
        self.scan_tab.rowconfigure(9, weight=2) # Sömürü Sonuçları için

        # URL Girişi
        Label(self.scan_tab, text="Hedef URL:",
              font=label_font, fg=fg_color, bg=bg_color).grid(row=0, column=0, pady=5, sticky="w")
        tk.Entry(self.scan_tab, textvariable=self.url_var, width=80,
                 font=entry_font, bg="#4A4A4A", fg=fg_color, insertbackground=fg_color,
                 highlightbackground=bg_color, highlightthickness=1).grid(row=1, column=0, pady=5, sticky="ew")

        # Tarama Seçenekleri (SQL/XSS Seçimi)
        options_frame = tk.Frame(self.scan_tab, bg=bg_color)
        options_frame.grid(row=2, column=0, pady=5, sticky="w")
        Label(options_frame, text="Test Edilecek Zafiyet Tipleri:", font=label_font, fg=fg_color, bg=bg_color).pack(side=tk.LEFT, padx=(0,10))
        Checkbutton(options_frame, text="SQL Enjeksiyonu", variable=self.enable_sql_test,
                    font=label_font, fg=fg_color, bg=checkbox_bg, selectcolor=checkbox_bg,
                    activebackground=checkbox_bg, activeforeground=fg_color).pack(side=tk.LEFT, padx=5)
        Checkbutton(options_frame, text="XSS (Cross-Site Scripting)", variable=self.enable_xss_test,
                    font=label_font, fg=fg_color, bg=checkbox_bg, selectcolor=checkbox_bg,
                    activebackground=checkbox_bg, activeforeground=fg_color).pack(side=tk.LEFT, padx=5)


        # Otomatik Tarama Butonu
        self.auto_scan_exploit_button = tk.Button(self.scan_tab, text="Otomatik Tarama ve Testi Başlat",
                  command=self.start_auto_scan_and_exploit,
                  font=button_font, bg=button_bg_green, fg=button_fg_white,
                  activebackground="#388E3C", activeforeground=button_fg_white, bd=0, padx=15, pady=8,
                  cursor="hand2")
        self.auto_scan_exploit_button.grid(row=3, column=0, pady=10, sticky="ew")

        # Durum mesajı etiketi
        self.status_label = tk.Label(self.scan_tab, textvariable=self.test_status_var,
                                     font=("Segoe UI", 10, "italic"), fg="#888888", bg=bg_color)
        self.status_label.grid(row=4, column=0, pady=5, sticky="w")

        # Ulaşılan Sayfalar ve Tespit Edilen Inputlar Listbox
        Label(self.scan_tab, text="Ulaşılan Sayfalar ve Tespit Edilen Inputlar:",
                 font=label_font, fg=fg_color, bg=bg_color).grid(row=5, column=0, pady=(15, 5), sticky="w")

        listbox_frame = tk.Frame(self.scan_tab, bg=listbox_bg)
        listbox_frame.grid(row=6, column=0, sticky="nsew", pady=5)

        self.listbox = tk.Listbox(listbox_frame,
                                  bg=listbox_bg, fg=listbox_fg, selectbackground="#5A5A5A",
                                  selectforeground=fg_color, font=entry_font, relief="flat", bd=0)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        listbox_scrollbar = Scrollbar(listbox_frame, command=self.listbox.yview, orient="vertical", troughcolor="#3A3E47")
        listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=listbox_scrollbar.set)

        # Tarama Logları (eski Test Sonuçları)
        Label(self.scan_tab, text="Tarama Logları:",
                 font=label_font, fg=fg_color, bg=bg_color).grid(row=7, column=0, pady=(15, 5), sticky="w")

        output_frame = tk.Frame(self.scan_tab, bg=output_bg)
        output_frame.grid(row=8, column=0, sticky="nsew", pady=5)

        self.output_text = Text(output_frame,
                                   bg=output_bg, fg=output_fg, font=text_font,
                                   insertbackground=fg_color, wrap="word", relief="flat", bd=0)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        output_scrollbar = Scrollbar(output_frame, command=self.output_text.yview, orient="vertical", troughcolor="#212121")
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=output_scrollbar.set)

        # Sömürü Çıktısı (Sağ Panelin Üstüne Yerleştirildi - Ana Sayfada Görülecek)
        Label(self.scan_tab, text="Sömürü Sonuçları (Başarılı Tespitler):",
                 font=label_font, fg=fg_color, bg=bg_color).grid(row=0, column=1, pady=5, sticky="w")
        self.exploit_output_text = Text(self.scan_tab,
                                           bg=exploit_output_bg, fg=output_fg, font=text_font,
                                           insertbackground=fg_color, wrap="word", relief="flat", bd=0)
        self.exploit_output_text.grid(row=1, column=1, rowspan=8, sticky="nsew", padx=(5, 0), pady=5)

        exploit_output_scrollbar = Scrollbar(self.scan_tab, command=self.exploit_output_text.yview, orient="vertical", troughcolor="#1A1A1A")
        exploit_output_scrollbar.grid(row=1, column=2, rowspan=8, sticky="ns", padx=(0, 5), pady=5)
        self.exploit_output_text.config(yscrollcommand=exploit_output_scrollbar.set)

        # Sekme 2: Payload Yönetimi
        self.payload_tab = tk.Frame(self.notebook, bg=bg_color)
        self.notebook.add(self.payload_tab, text=" Payload Yönetimi ")
        self.payload_tab.columnconfigure(0, weight=1)
        self.payload_tab.columnconfigure(1, weight=1)
        self.payload_tab.rowconfigure(1, weight=1)

        Label(self.payload_tab, text="SQL Payloadları (Her satıra bir tane):",
              font=label_font, fg=fg_color, bg=bg_color).grid(row=0, column=0, pady=(10, 5), padx=10, sticky="w")
        self.sql_payload_text = Text(self.payload_tab, height=20, font=text_font,
                                        bg=payload_text_bg, fg=fg_color, insertbackground=fg_color,
                                        relief="flat", bd=0)
        self.sql_payload_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        sql_payload_scrollbar = Scrollbar(self.payload_tab, command=self.sql_payload_text.yview, orient="vertical")
        sql_payload_scrollbar.grid(row=1, column=0, sticky="nse", padx=(0,10), pady=5)
        self.sql_payload_text.config(yscrollcommand=sql_payload_scrollbar.set)


        Label(self.payload_tab, text="XSS Payloadları (Her satıra bir tane):",
              font=label_font, fg=fg_color, bg=bg_color).grid(row=0, column=1, pady=(10, 5), padx=10, sticky="w")
        self.xss_payload_text = Text(self.payload_tab, height=20, font=text_font,
                                        bg=payload_text_bg, fg=fg_color, insertbackground=fg_color,
                                        relief="flat", bd=0)
        self.xss_payload_text.grid(row=1, column=1, sticky="nsew", padx=10, pady=5)
        xss_payload_scrollbar = Scrollbar(self.payload_tab, command=self.xss_payload_text.yview, orient="vertical")
        xss_payload_scrollbar.grid(row=1, column=1, sticky="nse", padx=(0,10), pady=5)
        self.xss_payload_text.config(yscrollcommand=xss_payload_scrollbar.set)

        tk.Button(self.payload_tab, text="Payloadları Kaydet",
                  command=self.save_payloads,
                  font=button_font, bg=button_bg_blue, fg=button_fg_white,
                  activebackground="#1565C0", activeforeground=button_fg_white, bd=0, padx=15, pady=8,
                  cursor="hand2").grid(row=2, column=0, columnspan=2, pady=10)


        # Sekme 3: Ayarlar
        self.settings_tab = tk.Frame(self.notebook, bg=bg_color)
        self.notebook.add(self.settings_tab, text=" Ayarlar ")
        self.settings_tab.columnconfigure(0, weight=1)
        self.settings_tab.columnconfigure(1, weight=2)
        self.settings_tab.rowconfigure(0, weight=1)
        self.settings_tab.rowconfigure(1, weight=1)

        Label(self.settings_tab, text="Chrome WebDriver Yolu:",
              font=label_font, fg=fg_color, bg=bg_color).grid(row=0, column=0, pady=10, padx=10, sticky="w")
        self.chromedriver_path_var = tk.StringVar(value=self.driver_manager.chromedriver_path)
        tk.Entry(self.settings_tab, textvariable=self.chromedriver_path_var, width=60,
                 font=entry_font, bg="#4A4A4A", fg=fg_color, insertbackground=fg_color,
                 highlightbackground=bg_color, highlightthickness=1).grid(row=0, column=1, pady=10, padx=10, sticky="ew")
        tk.Button(self.settings_tab, text="Yolu Kaydet",
                  command=self.save_chromedriver_path,
                  font=button_font, bg=button_bg_blue, fg=button_fg_white,
                  activebackground="#1565C0", activeforeground=button_fg_white, bd=0, padx=10, pady=5,
                  cursor="hand2").grid(row=0, column=2, pady=10, padx=10, sticky="w")
        
        # Ekran Görüntüsü Kayıt Yolu
        Label(self.settings_tab, text="Ekran Görüntüsü Kayıt Klasörü:",
              font=label_font, fg=fg_color, bg=bg_color).grid(row=1, column=0, pady=10, padx=10, sticky="w")
        self.screenshot_path_var = tk.StringVar(value=self.driver_manager.screenshot_dir)
        tk.Entry(self.settings_tab, textvariable=self.screenshot_path_var, width=60,
                 font=entry_font, bg="#4A4A4A", fg=fg_color, insertbackground=fg_color,
                 highlightbackground=bg_color, highlightthickness=1).grid(row=1, column=1, pady=10, padx=10, sticky="ew")
        tk.Button(self.settings_tab, text="Yolu Kaydet",
                  command=self.save_screenshot_path,
                  font=button_font, bg=button_bg_blue, fg=button_fg_white,
                  activebackground="#1565C0", activeforeground=button_fg_white, bd=0, padx=10, pady=5,
                  cursor="hand2").grid(row=1, column=2, pady=10, padx=10, sticky="w")

        # Sekme 4: Hakkında
        self.about_tab = tk.Frame(self.notebook, bg=bg_color)
        self.notebook.add(self.about_tab, text=" Hakkında ")
        Label(self.about_tab, text="""
Gelişmiş Web Güvenliği Tarayıcı
Sürüm: 3.0 (Akıllı ve Hedef Odaklı)

Bu araç, bir web sitesindeki potansiyel SQL Enjeksiyonu ve Cross-Site Scripting (XSS) zafiyetlerini otomatik olarak tespit etmek için tasarlanmıştır.

Özellikler:
- URL ve form tabanlı SQL Enjeksiyonu testi.
- URL ve form/input tabanlı XSS testi (Selenium ile gerçek tarayıcı ortamında).
- Tespit edilen zafiyetlerin detaylı raporlanması ve CVE bilgileri.
- Sadece başarılı ve doğrulanmış sömürülerin gösterilmesi.
- Özel payload listeleri ekleyebilme.
- Chrome WebDriver entegrasyonu (headless modda).

Geliştirici: [İsminiz veya Takımınız]
Lisans: MIT Lisansı (veya uygun bir lisans)

Kullanım:
1. Hedef URL'yi girin.
2. Test etmek istediğiniz zafiyet tiplerini seçin.
3. 'Otomatik Tarama ve Testi Başlat' butonuna tıklayın.
4. Sonuçları 'Sömürü Sonuçları' panelinden takip edin.

Yasal Uyarı: Bu araç sadece yasal ve etik güvenlik testleri için kullanılmalıdır. Yetkisiz sistemlere yapılan saldırılar yasa dışıdır ve ciddi sonuçları olabilir. Tüm sorumluluk kullanıcıya aittir.
        """,
              font=entry_font, fg=fg_color, bg=bg_color, justify=tk.LEFT, wraplength=700).pack(pady=20, padx=20)


    def log_output(self, message, level='info'):
        """GUI'deki ana log penceresine çıktı ekler."""
        def _insert_log():
            tag_colors = {
                'info': 'white',
                'success': 'light green',
                'warning': 'orange',
                'error': 'red',
                'debug': 'gray',
                'highlight': 'cyan',
                'critical': 'dark red'
            }
            color = tag_colors.get(level, 'white')
            self.output_text.tag_config(color, foreground=color)
            self.output_text.insert(tk.END, message, color)
            self.output_text.see(tk.END)
        self.root.after(0, _insert_log)
        # Konsol çıktısı için de logger'ı kullanıyoruz
        if level == 'info': app_logger.info(message.strip())
        elif level == 'success': app_logger.info(message.strip())
        elif level == 'warning': app_logger.warning(message.strip())
        elif level == 'error': app_logger.error(message.strip())
        elif level == 'debug': app_logger.debug(message.strip())
        elif level == 'critical': app_logger.critical(message.strip())

    def log_exploit_output(self, message, level='info'):
        """GUI'deki sömürü sonuçları penceresine çıktı ekler."""
        def _insert_exploit_log():
            tag_colors = {
                'info': 'white',
                'success': 'light green',
                'warning': 'orange',
                'error': 'red',
                'critical': 'dark red',
                'exploit_success': 'red', # Başarılı exploit için özel kırmızı
                'exploit_info': 'magenta' # Exploit ile ilgili bilgi için
            }
            color = tag_colors.get(level, 'white')
            self.exploit_output_text.tag_config(color, foreground=color)
            self.exploit_output_text.insert(tk.END, message, color)
            self.exploit_output_text.see(tk.END)
        self.root.after(0, _insert_exploit_log)
        if level == 'exploit_success': app_logger.critical(f"Exploit Success: {message.strip()}")
        else: app_logger.info(f"Exploit Log: {message.strip()}")


    def update_button_states(self, enable=True):
        state = tk.NORMAL if enable else tk.DISABLED
        self.auto_scan_exploit_button.config(state=state)
        self.sql_payload_text.config(state=state)
        self.xss_payload_text.config(state=state)
        # Diğer UI elemanlarını da devre dışı bırakabilirsiniz

    def save_payloads(self):
        try:
            with open(SQL_PAYLOADS_FILE, 'w', encoding='utf-8') as f:
                f.write(self.sql_payload_text.get("1.0", tk.END).strip())
            with open(XSS_PAYLOADS_FILE, 'w', encoding='utf-8') as f:
                f.write(self.xss_payload_text.get("1.0", tk.END).strip())
            messagebox.showinfo("Başarılı", "Payloadlar başarıyla kaydedildi.")
            app_logger.info("Payloadlar kaydedildi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Payloadlar kaydedilirken hata oluştu: {e}")
            app_logger.error(f"Payloadlar kaydedilirken hata oluştu: {e}")

    def save_chromedriver_path(self):
        new_path = self.chromedriver_path_var.get().strip()
        self.driver_manager.update_chromedriver_path(new_path)
        app_logger.info(f"ChromeDriver yolu güncellendi: {new_path}")
        messagebox.showinfo("Başarılı", f"Chrome WebDriver yolu kaydedildi:\n{new_path}")
    
    def save_screenshot_path(self):
        new_path = self.screenshot_path_var.get().strip()
        self.driver_manager.update_screenshot_dir(new_path)
        app_logger.info(f"Ekran görüntüsü klasör yolu güncellendi: {new_path}")
        messagebox.showinfo("Başarılı", f"Ekran görüntüsü klasör yolu kaydedildi:\n{new_path}")


    def start_auto_scan_and_exploit(self):
        if self.is_scanning_or_testing:
            messagebox.showinfo("Bilgi", "Zaten bir tarama veya test işlemi devam ediyor. Lütfen bitmesini bekleyin.")
            return

        base_url = self.url_var.get().strip().rstrip('/')
        if not base_url.startswith("http"):
            messagebox.showerror("Hata", "Lütfen geçerli bir URL girin (örn: http://site.com).")
            return

        if not self.enable_sql_test.get() and not self.enable_xss_test.get():
            messagebox.showwarning("Uyarı", "Lütfen test etmek istediğiniz en az bir zafiyet tipini seçin (SQL veya XSS).")
            return

        # WebDriver'ı tarama başlamadan hemen önce başlat
        self.driver = self.driver_manager.initialize_driver()
        if self.driver is None:
            messagebox.showerror("Hata", "Chrome WebDriver başlatılamadı. Lütfen Ayarlar sekmesinden ChromeDriver yolunu kontrol edin ve yeniden deneyin.")
            return

        current_sql_payloads = [p.strip() for p in self.sql_payload_text.get("1.0", tk.END).split('\n') if p.strip()]
        current_xss_payloads = [p.strip() for p in self.xss_payload_text.get("1.0", tk.END).split('\n') if p.strip()]

        if self.enable_sql_test.get() and not current_sql_payloads:
            messagebox.showerror("Hata", "SQL Enjeksiyon testi seçildi ancak SQL payloadları boş.")
            return
        if self.enable_xss_test.get() and not current_xss_payloads:
            messagebox.showerror("Hata", "XSS testi seçildi ancak XSS payloadları boş.")
            return

        self.log_output("[+] Otomatik Tarama ve Test Başlatılıyor...\n", "highlight")
        self.test_status_var.set("Otomatik Tarama ve Test Devam Ediyor...")
        self.update_button_states(enable=False)
        self.is_scanning_or_testing = True

        # Temizleme işlemleri
        self.listbox.delete(0, tk.END)
        self.output_text.delete("1.0", tk.END)
        self.exploit_output_text.delete("1.0", tk.END)

        # ScannerCore ve Tester'ları başlat
        self.scanner_core = ScannerCore(
            driver=self.driver,
            logger=self.log_output,
            exploit_logger=self.log_exploit_output,
            listbox_updater=self.update_listbox,
            sql_payloads=current_sql_payloads,
            xss_payloads=current_xss_payloads,
            enable_sql=self.enable_sql_test.get(),
            enable_xss=self.enable_xss_test.get(),
            screenshot_manager=self.driver_manager # Ekran görüntüsü için
        )

        auto_scan_thread = threading.Thread(
            target=self.scanner_core.start_scan,
            args=(base_url,)
        )
        auto_scan_thread.daemon = True
        auto_scan_thread.start()

        # Thread bittiğinde UI'ı güncellemek için bir kontrol mekanizması
        self.root.after(1000, self._check_scan_completion)

    def _check_scan_completion(self):
        if not self.scanner_core.is_scanning: # ScannerCore'daki is_scanning bayrağını kontrol ediyoruz
            self.log_output("\n" + "="*50 + "\n", "highlight")
            self.log_exploit_output("\n" + "="*50 + "\n", "info")
            if not self.scanner_core.overall_vulnerabilities_found:
                self.log_output("[✓] Otomatik tarama ve test tamamlandı: Belirgin bir açık bulunamadı.", "success")
                self.log_exploit_output("[✓] Özet: Belirgin bir açık bulunamadı.\n", "success")
                self.test_status_var.set("Otomatik Tarama Tamamlandı: Açık bulunamadı.")
            else:
                self.log_output("[!!!] Otomatik tarama ve test tamamlandı: Açıklar Tespit Edildi! Lütfen Sömürü Sonuçları panelini inceleyin.", "error")
                self.log_exploit_output("[!!!] Özet: Açıklar Tespit Edildi! Lütfen Sömürü Sonuçları panelini inceleyin.\n", "exploit_success")
                self.test_status_var.set("Otomatik Tarama Tamamlandı: Açıklar Bulundu!")
            self.log_output("="*50 + "\n", "highlight")
            self.log_exploit_output("="*50 + "\n", "info")
            self.update_button_states(enable=True)
            self.is_scanning_or_testing = False
            # Tarama bitince driver'ı kapatabiliriz
            if self.driver:
                self.driver_manager.quit_driver()
                self.driver = None # Driver'ı sıfırla
        else:
            self.root.after(1000, self._check_scan_completion) # Bir saniye sonra tekrar kontrol et

    def update_listbox(self, item_type, data):
        """ScannerCore'dan gelen verileri Listbox'a ekler."""
        def _add_to_listbox():
            display_string = ""
            if item_type == 'url':
                display_string = f"URL: {data}"
            elif item_type == 'form':
                display_string = f"FORM: [Method: {data['method'].upper()}] [Action: {data['action']}] (Kaynak: {data['source_url']})"
            elif item_type == 'pseudo_form':
                input_name_display = data['inputs'][0]['name'] if data['inputs'] else 'N/A'
                display_string = f"INPUT: [Name: {input_name_display}] [Type: {data['inputs'][0]['type']}] (Kaynak: {data['source_url']})"

            self.listbox.insert(tk.END, display_string)
            self.listbox.see(tk.END) # En sona kaydır
        self.root.after(0, _add_to_listbox)

    def on_closing(self):
        if self.is_scanning_or_testing:
            if messagebox.askokcancel("Tarama Devam Ediyor", "Tarama devam ediyor. Kapatmak istediğinizden emin misiniz?"):
                if self.driver_manager:
                    self.driver_manager.quit_driver()
                self.root.destroy()
        else:
            if self.driver_manager:
                self.driver_manager.quit_driver()
            self.root.destroy()


if __name__ == "__main__":
    # PyInstaller için kaynak dosyalarının yolunu ayarla
    # Bu, PyInstaller ile paketlendiğinde resimler, payload dosyaları gibi
    # ek dosyaların bulunabilmesini sağlar.
    if getattr(sys, 'frozen', False): # Program PyInstaller ile dondurulmuşsa
        application_path = sys._MEIPASS
    else: # Normal Python ile çalışıyorsa
        application_path = os.path.dirname(os.path.abspath(__file__))

    # config.py'daki paths'leri güncelle
    import config
    config.SQL_PAYLOADS_FILE = os.path.join(application_path, "payloads", "sql_payloads.txt")
    config.XSS_PAYLOADS_FILE = os.path.join(application_path, "payloads", "xss_payloads.txt")
    config.SCREENSHOT_DIR = os.path.join(application_path, "screenshots")
    
    # Ekran görüntüsü klasörünü oluştur
    os.makedirs(config.SCREENSHOT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(config.SQL_PAYLOADS_FILE), exist_ok=True) # Payloads klasörünü oluştur

    root = tk.Tk()
    app = WebPenetrationScannerApp(root)
    root.mainloop()