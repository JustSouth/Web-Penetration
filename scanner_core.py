import requests
from requests.exceptions import ConnectionError, Timeout, RequestException
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import collections
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException, StaleElementReferenceException
import time
import json # CVE araması için
import config # config.py'yi import ediyoruz

from vulnerability_tests.sql_injector import SQLInjector
from vulnerability_tests.xss_tester import XSSTester

class ScannerCore:
    def __init__(self, driver, logger, exploit_logger, listbox_updater, sql_payloads, xss_payloads, enable_sql, enable_xss, screenshot_manager):
        self.driver = driver
        self.logger = logger
        self.exploit_logger = exploit_logger
        self.listbox_updater = listbox_updater
        self.sql_payloads = sql_payloads
        self.xss_payloads = xss_payloads
        self.enable_sql = enable_sql
        self.enable_xss = enable_xss
        self.screenshot_manager = screenshot_manager # Ekran görüntüsü yöneticisi

        self.crawl_queue = collections.deque()
        self.visited_urls = set()
        self.max_crawl_depth = config.MAX_CRAWL_DEPTH
        self.crawl_timeout = config.CRAWL_TIMEOUT
        self.is_scanning = False
        self.overall_vulnerabilities_found = False

        self.sql_injector = SQLInjector(self.logger, self.exploit_logger)
        self.xss_tester = XSSTester(self.driver, self.logger, self.exploit_logger, self.screenshot_manager)

    def start_scan(self, base_url):
        self.is_scanning = True
        self.overall_vulnerabilities_found = False
        self.crawl_queue.clear()
        self.visited_urls.clear()

        self.crawl_queue.append((base_url, 0))
        self.visited_urls.add(base_url)

        try:
            while self.crawl_queue:
                current_url, depth = self.crawl_queue.popleft()

                if depth > self.max_crawl_depth:
                    self.logger(f"[i] Maksimum tarama derinliğine ulaşıldı: {current_url}\n", "info")
                    continue

                # Sadece aynı domain içindeki URL'leri tara
                if urlparse(current_url).netloc != urlparse(base_url).netloc:
                    self.logger(f"[i] Harici URL atlanıyor: {current_url}\n", "info")
                    continue

                if current_url in self.visited_urls and current_url != base_url: # Base URL'i tekrar ziyaret etmek sorun değil
                    continue
                self.visited_urls.add(current_url)

                self.logger(f"\n[+] Tarayıcı: '{current_url}' (Derinlik: {depth}) taranıyor...", "highlight")

                try:
                    # Requests ile sayfa içeriğini çek (hızlı ön analiz ve input tespiti için)
                    r = requests.get(current_url, timeout=self.crawl_timeout, verify=False)
                    if r.status_code == 200:
                        self.logger(f"[✓] Ulaşıldı (Requests): {current_url}", "success")
                        self.listbox_updater('url', current_url)

                        # 1. URL parametrelerini test et
                        if self.enable_sql or self.enable_xss:
                            self._test_url_parameters(current_url)

                        # 2. Tüm formları ve form dışı inputları bul
                        all_input_elements = self._find_all_inputs_on_page(current_url, r.text)
                        
                        # Selenium ile de dinamik elemanları bulmayı deneyelim (JS ile yüklenenler için)
                        try:
                            self.driver.get(current_url)
                            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
                            
                            selenium_forms = self.driver.find_elements(By.TAG_NAME, 'form')
                            for sel_form in selenium_forms:
                                form_details = self._extract_form_details(sel_form, current_url, 'form')
                                if form_details and form_details not in all_input_elements:
                                    all_input_elements.append(form_details)
                            
                            selenium_inputs = self.driver.find_elements(By.XPATH, '//body//input[@name and not(@type="submit") and not(@type="button") and not(@type="file") and not(@type="reset") and not(@type="hidden") and not(@type="radio") and not(@type="checkbox") and not(@type="image")] | //body//textarea[@name]')
                            for sel_input in selenium_inputs:
                                if sel_input.find_element(By.XPATH, './ancestor::form'): # Eğer bir formun içindeyse atla
                                    continue
                                pseudo_form_details = self._extract_form_details(sel_input, current_url, 'pseudo_form')
                                if pseudo_form_details and pseudo_form_details not in all_input_elements:
                                    all_input_elements.append(pseudo_form_details)

                        except (TimeoutException, WebDriverException) as se:
                            self.logger(f"    [!] Selenium ile dinamik form/input tespiti hatası ({current_url}): {type(se).__name__} - {str(se)[:100]}...\n", "warning")
                        except Exception as e:
                            self.logger(f"    [!] Selenium ile dinamik form/input tespiti sırasında beklenmeyen hata ({current_url}): {type(e).__name__} - {str(e)}\n", "error")

                        if all_input_elements:
                            self.logger(f"    [i] {len(all_input_elements)} adet form/input elemanı bulundu.", "info")
                            for input_element_data in all_input_elements:
                                self.listbox_updater(input_element_data['type'], input_element_data)
                                if self.enable_sql or self.enable_xss:
                                    self._test_input_element(input_element_data)
                        else:
                            self.logger(f"    [i] Sayfada form veya input elemanı bulunamadı: {current_url}", "info")


                        # Yeni bağlantıları keşfet ve kuyruğa ekle
                        self._discover_and_queue_links(current_url, r.text, depth)
                        
                        # Selenium ile de linkleri keşfet (JS ile yüklenenler için)
                        try:
                            # Eğer zaten driver.get yapıldıysa tekrar yapmaya gerek yok
                            if self.driver.current_url != current_url:
                                self.driver.get(current_url)
                                WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

                            links = self.driver.find_elements(By.TAG_NAME, 'a')
                            for link_elem in links:
                                href = link_elem.get_attribute('href')
                                if href:
                                    new_url = urljoin(current_url, href)
                                    parsed_new_url = urlparse(new_url)
                                    if parsed_new_url.netloc == urlparse(base_url).netloc and \
                                       (parsed_new_url.scheme in ['http', 'https']) and \
                                       new_url not in self.visited_urls:
                                        self.crawl_queue.append((new_url, depth + 1))
                                        self.visited_urls.add(new_url)
                        except (WebDriverException, StaleElementReferenceException) as se:
                            self.logger(f"    [!] Selenium ile link tespiti hatası ({current_url}): {type(se).__name__} - {str(se)[:100]}...\n", "warning")


                    else:
                        self.logger(f"[!] Ulaşılamadı: {current_url} (HTTP Status: {r.status_code})", "warning")

                except (ConnectionError, Timeout, RequestException) as e:
                    self.logger(f"[!] Ağ/İstek hatası ({current_url}): {type(e).__name__} - {str(e)}", "error")
                except Exception as e:
                    self.logger(f"[!] Beklenmeyen hata ({current_url}): {type(e).__name__} - {str(e)}", "error")

                time.sleep(0.5) # Sunucuya yük bindirmemek için bekleme

        finally:
            self.is_scanning = False # Tarama bitti
            self.logger("[i] Tarama ve test işlemi tamamlandı.", "info")

    def _extract_form_details(self, element, current_url, element_type):
        details = {}
        if element_type == 'form':
            details['type'] = 'form'
            action = element.get_attribute('action')
            method = element.get_attribute('method') or 'get'
            details['action'] = urljoin(current_url, action) if action else current_url
            details['method'] = method.lower()
            details['inputs'] = []
            details['source_url'] = current_url
            details['id'] = element.get_attribute('id')
            details['class'] = element.get_attribute('class')

            for input_tag in element.find_elements(By.XPATH, ".//input | .//textarea | .//select"):
                input_name = input_tag.get_attribute('name')
                input_type = input_tag.get_attribute('type') or 'text'
                if input_name and input_type not in ['submit', 'button', 'file', 'reset', 'image']:
                    details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_tag.get_attribute('value')})
                elif input_name and input_type in ['radio', 'checkbox']:
                    details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_tag.get_attribute('value'), 'checked': input_tag.is_selected()})
                elif input_type == 'hidden':
                    details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_tag.get_attribute('value')})
            if not details['inputs']:
                return None # Input'u olmayan formu test etmeye gerek yok
            
        elif element_type == 'pseudo_form':
            input_name = element.get_attribute('name')
            input_type = element.get_attribute('type') or 'text'
            if input_name is None or input_type in ['submit', 'button', 'file', 'reset', 'hidden', 'radio', 'checkbox', 'image']:
                return None

            details['type'] = 'pseudo_form'
            details['action'] = current_url # Pseudo form için action URL'in kendisi
            details['method'] = 'get' # Genellikle GET ile parametre alırlar
            details['inputs'] = [{'name': input_name, 'type': input_type, 'value': element.get_attribute('value')}]
            details['source_url'] = current_url
            details['id'] = element.get_attribute('id')
            details['class'] = element.get_attribute('class')
            
        return details

    def _find_all_inputs_on_page(self, url, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        
        all_elements = []

        # HTML Formları
        for form_tag in soup.find_all('form'):
            form_details = {}
            action = form_tag.get('action')
            method = form_tag.get('method', 'get').lower()

            form_details['type'] = 'form'
            form_details['action'] = urljoin(url, action) if action else url
            form_details['method'] = method
            form_details['inputs'] = []
            form_details['source_url'] = url
            form_details['id'] = form_tag.get('id')
            form_details['class'] = form_tag.get('class')

            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text').lower()
                if input_name and input_type not in ['submit', 'button', 'file', 'reset', 'image']:
                    form_details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_tag.get('value', '')})
                elif input_name and input_type in ['radio', 'checkbox']:
                    form_details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_tag.get('value', ''), 'checked': input_tag.has_attr('checked')})
                elif input_type == 'hidden':
                    form_details['inputs'].append({'name': input_name, 'type': input_type, 'value': input_tag.get('value', '')})

            if form_details['inputs']:
                all_elements.append(form_details)
        
        # Form dışındaki input/textarea elemanları
        for input_tag in soup.find_all(['input', 'textarea']):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text').lower()

            # Zaten bir formun parçasıysa veya alakasız bir tipse atla
            if input_tag.find_parent('form') or input_name is None or \
               input_type in ['submit', 'button', 'file', 'reset', 'hidden', 'radio', 'checkbox', 'image']:
                continue
            
            # Duplikasyon kontrolü (basit)
            is_duplicate = False
            for existing_element in all_elements:
                if existing_element['type'] == 'pseudo_form' and \
                   existing_element['inputs'][0]['name'] == input_name and \
                   existing_element['source_url'] == url:
                    is_duplicate = True
                    break
            if is_duplicate:
                continue

            pseudo_form_details = {
                'type': 'pseudo_form',
                'action': url,
                'method': 'get', # Bu durumda action URL'in kendisi
                'inputs': [{'name': input_name, 'type': input_type, 'value': input_tag.get('value', '')}],
                'source_url': url,
                'id': input_tag.get('id'),
                'class': input_tag.get('class')
            }
            all_elements.append(pseudo_form_details)

        return all_elements

    def _discover_and_queue_links(self, current_url, html_content, depth):
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            new_url = urljoin(current_url, link['href'])
            parsed_new_url = urlparse(new_url)
            if parsed_new_url.netloc == urlparse(current_url).netloc and \
               (parsed_new_url.scheme in ['http', 'https']) and \
               new_url not in self.visited_urls:
                self.crawl_queue.append((new_url, depth + 1))
                self.visited_urls.add(new_url)


    def _test_url_parameters(self, url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        if not params:
            self.logger(f"    [=] {url} -> Test edilecek URL parametresi yok.", "info")
            return

        self.logger(f"    [+] URL parametreleri test ediliyor: {url}", "highlight")

        if self.enable_sql:
            self.logger(f"        [▶] SQL Enjeksiyon testi (URL parametreleri)...", "info")
            if self.sql_injector.test_url_parameters_sql(url, self.sql_payloads):
                self.overall_vulnerabilities_found = True

        if self.enable_xss:
            self.logger(f"        [▶] XSS testi (URL parametreleri - Selenium ile)...", "info")
            if self.xss_tester.test_url_parameters_xss(url, self.xss_payloads):
                self.overall_vulnerabilities_found = True

    def _test_input_element(self, input_element_data):
        input_type_display = input_element_data['type'].capitalize()
        target_url = input_element_data['action']
        source_url = input_element_data.get('source_url', 'Bilinmiyor')
        self.logger(f"    [+] {input_type_display} elemanı test ediliyor (Kaynak URL: {source_url})", "highlight")

        if self.enable_sql:
            self.logger(f"        [▶] SQL Enjeksiyon testi ({input_type_display})...", "info")
            if self.sql_injector.test_input_element_sql(input_element_data, self.sql_payloads):
                self.overall_vulnerabilities_found = True
        
        if self.enable_xss:
            self.logger(f"        [▶] XSS testi ({input_type_display} - Selenium ile)...", "info")
            if self.xss_tester.test_input_element_xss(input_element_data, self.xss_payloads):
                self.overall_vulnerabilities_found = True