import os
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import json # CVE araması için

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException, TimeoutException, UnexpectedAlertPresentException, NoSuchElementException, StaleElementReferenceException

import config # config.py'yi import ediyoruz

import requests
from requests.exceptions import Timeout

class XSSTester:
    def __init__(self, driver, logger, exploit_logger, screenshot_manager):
        self.driver = driver
        self.logger = logger
        self.exploit_logger = exploit_logger
        self.screenshot_manager = screenshot_manager # Screenshot alma yeteneği

    def _search_cve_for_vulnerability_type(self, vulnerability_type):
        query_keyword = ""
        if vulnerability_type == "xss":
            query_keyword = "Cross-Site Scripting"
        
        if not query_keyword:
            return

        self.exploit_logger(f"\n[i] '{query_keyword}' ile ilgili CVE'ler aranıyor (NVD API)...", "info")
        try:
            params = {"keywordSearch": query_keyword, "resultsPerPage": 3}
            response = requests.get(config.NVD_API_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            cve_data = response.json()

            if cve_data and cve_data.get('vulnerabilities'):
                self.exploit_logger(f"[✓] '{query_keyword}' ile ilgili bulunan CVE'ler:", "success")
                for cve_item in cve_data['vulnerabilities']:
                    cve_id = cve_item['cve']['id']
                    description = "Açıklama mevcut değil."
                    if cve_item['cve']['descriptions']:
                        for desc in cve_item['cve']['descriptions']:
                            if desc['lang'] == 'en':
                                description = desc['value']
                                break
                    self.exploit_logger(f"    - CVE ID: {cve_id}", "warning")
                    self.exploit_logger(f"      Açıklama: {description[:150]}...\n", "warning")
            else:
                self.exploit_logger(f"[i] '{query_keyword}' ile ilgili CVE bulunamadı veya API yanıtı boş.", "warning")

        except ConnectionError as e:
            self.exploit_logger(f"[!] CVE API bağlantı hatası: {type(e).__name__} - {str(e)}\n", "error")
        except Timeout as e:
            self.exploit_logger(f"[!] CVE API zaman aşımı hatası: {type(e).__name__} - {str(e)}\n", "error")
        except requests.exceptions.RequestException as e: # requests modülünden RequestException'ı yakala
            self.exploit_logger(f"[!] CVE API istek hatası: {type(e).__name__} - {str(e)}\n", "error")
        except json.JSONDecodeError:
            self.exploit_logger(f"[!] CVE API yanıtı JSON olarak ayrıştırılamadı. Geçersiz yanıt.\n", "error")
        except Exception as e:
            self.exploit_logger(f"[!] CVE aramasında beklenmeyen hata: {type(e).__name__} - {str(e)}\n", "error")

    def test_url_parameters_xss(self, url, payloads):
        vulnerability_found = False
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        for key in params:
            for payload_value in payloads:
                test_params = params.copy()
                test_params[key] = payload_value

                full_test_url_parts = list(parsed_url)
                full_test_url_parts[4] = urlencode(test_params, doseq=True)
                test_url = urlunparse(full_test_url_parts)

                self.logger(f"        [i] Denenen URL: {test_url}", "debug")

                try:
                    self.driver.get(test_url)
                    time.sleep(1) # Sayfanın ve JS'in yüklenmesini bekle

                    alert_present = False
                    alert_text = ""
                    try:
                        alert = self.driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        alert_present = True
                    except UnexpectedAlertPresentException as e:
                        self.logger(f"        [!] Beklenmeyen bir alert tetiklendi (otomatik kapatıldı): {e.alert_text}", "warning")
                        alert_text = e.alert_text
                        e.alert.accept()
                        alert_present = True
                    except TimeoutException:
                        alert_present = False # Alert penceresi yok

                    if alert_present and "xss-vuln" in alert_text.lower():
                        self.exploit_logger("\n[‼️] GERÇEK XSS (CROSS-SITE SCRIPTING) AÇIĞI TESPİT EDİLDİ!\n", "exploit_success")
                        self.exploit_logger(f"    Zafiyet Yeri        : URL Parametresi\n", "warning")
                        self.exploit_logger(f"    Hedef URL           : {url}\n", "warning")
                        self.exploit_logger(f"    Etkilenen Parametre : '{key}'\n", "exploit_success")
                        self.exploit_logger(f"    Kullanılan Payload  : '{payload_value}'\n", "exploit_success")
                        self.exploit_logger(f"    Test Edilen URL     : {test_url}\n", "exploit_success")
                        self.exploit_logger(f"    Tespit Detayı       : Payload tarayıcıda başarıyla yürütüldü ve 'alert(\"{alert_text}\")' tetiklendi.\n", "exploit_success")
                        
                        screenshot_path = self.screenshot_manager.take_screenshot(f"xss_url_{key}_{time.time()}.png")
                        if screenshot_path:
                            self.exploit_logger(f"    Ekran Görüntüsü     : {screenshot_path}\n", "info")
                        
                        self._search_cve_for_vulnerability_type("xss")
                        vulnerability_found = True
                        return True # İlk başarılı tespitte dur
                    # else:
                    #     self.logger(f"        [i] Alert tetiklenmedi veya beklenen XSS metni içermiyor.", "debug")

                except TimeoutException:
                    self.logger(f"        [i] Sayfa yükleme zaman aşımı ({test_url}). XSS testi atlanıyor.", "warning")
                except WebDriverException as e:
                    self.logger(f"        [!] Selenium hatası ({test_url}): {type(e).__name__} - {str(e)[:100]}...\n", "error")
                except Exception as e:
                    self.logger(f"        [!] XSS testi sırasında beklenmeyen hata ({test_url}): {type(e).__name__} - {str(e)}\n", "error")
        return vulnerability_found

    def test_input_element_xss(self, input_element_data, payloads):
        vulnerability_found = False
        target_url = input_element_data['action']
        method = input_element_data['method']
        inputs = input_element_data['inputs']
        source_url = input_element_data.get('source_url', 'Bilinmiyor')
        input_element_id = input_element_data.get('id')
        input_element_class = input_element_data.get('class')
        input_type_display = input_element_data['type']

        for input_field in inputs:
            input_name = input_field['name']
            field_type = input_field['type']

            if field_type in ['text', 'password', 'email', 'search', 'url', 'tel', 'number', 'textarea']:
                for payload_value in payloads:
                    try:
                        self.driver.get(source_url) # Input'un bulunduğu sayfaya git
                        WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

                        target_selenium_element = None
                        if input_type_display == 'form':
                            if input_element_id:
                                try: target_selenium_element = self.driver.find_element(By.ID, input_element_id)
                                except NoSuchElementException: pass
                            if not target_selenium_element and input_element_class:
                                try: target_selenium_element = self.driver.find_element(By.CLASS_NAME, input_element_class[0] if isinstance(input_element_class, list) else input_element_class)
                                except NoSuchElementException: pass
                            if not target_selenium_element: # Son çare: action ve method ile bulmaya çalış
                                try: target_selenium_element = self.driver.find_element(By.XPATH, f'//form[@action="{target_url}" and @method="{method}"]')
                                except NoSuchElementException: pass
                            if not target_selenium_element: # Sadece method ile bulmaya çalış
                                try: target_selenium_element = self.driver.find_element(By.XPATH, f'//form[@method="{method}"]')
                                except NoSuchElementException: pass
                        else: # pseudo_form
                            if input_element_id:
                                try: target_selenium_element = self.driver.find_element(By.ID, input_element_id)
                                except NoSuchElementException: pass
                            if not target_selenium_element:
                                try: target_selenium_element = self.driver.find_element(By.NAME, input_name)
                                except NoSuchElementException: pass
                            if not target_selenium_element and input_element_class:
                                try: target_selenium_element = self.driver.find_element(By.CLASS_NAME, input_element_class[0] if isinstance(input_element_class, list) else input_element_class)
                                except NoSuchElementException: pass
                            if not target_selenium_element:
                                try: target_selenium_element = self.driver.find_element(By.XPATH, f'//input[@name="{input_name}" and @type="{field_type}"] | //textarea[@name="{input_name}"]')
                                except NoSuchElementException: pass

                        if not target_selenium_element:
                            self.logger(f"        [!] Selenium: '{input_type_display.capitalize()}' elemanı bulunamadı. (ID: {input_element_id}, Class: {input_element_class}, Name: {input_name}) - Atlanıyor.\n", "warning")
                            continue

                        self.logger(f"        [i] '{input_name}' parametresi test ediliyor payload: '{payload_value}'", "debug")

                        # Input alanlarını doldur
                        for param_data in inputs:
                            p_name = param_data['name']
                            p_type = param_data['type']
                            p_value = ''

                            if p_name == input_name:
                                p_value = payload_value
                            elif p_type == 'hidden':
                                p_value = param_data.get('value', '')
                            elif p_type in ['radio', 'checkbox']:
                                if param_data.get('checked'): # Eğer form detaylarında checked ise işaretliyoruz
                                    p_value = param_data.get('value', 'on')
                                else:
                                    p_value = param_data.get('value', '') # checked değilse boş bırak
                            else:
                                p_value = 'test_value'

                            try:
                                if input_type_display == 'form':
                                    input_elem = target_selenium_element.find_element(By.NAME, p_name)
                                else: # Pseudo form
                                    if p_name == input_name: # test edilen input
                                        input_elem = target_selenium_element
                                    else: # diğer inputlar (eğer varsa, nadiren pseudo-formda)
                                        input_elem = self.driver.find_element(By.NAME, p_name)

                                if p_type in ['text', 'password', 'email', 'search', 'url', 'tel', 'number', 'textarea']:
                                    input_elem.clear()
                                    input_elem.send_keys(p_value)
                                elif p_type in ['radio', 'checkbox']:
                                    if input_elem.get_attribute('value') == p_value and not input_elem.is_selected():
                                        input_elem.click()
                            except NoSuchElementException:
                                self.logger(f"        [!] Selenium: '{p_name}' input alanı bulunamadı (kaynak: {source_url}).", "warning")
                                continue # Bu input bulunamadıysa bir sonraki payload'a geç
                            except StaleElementReferenceException:
                                self.logger(f"        [!] Selenium: '{p_name}' input alanı artık DOM'da değil. Atlanıyor.", "warning")
                                break # Bu payload için devam etme

                        # Elemanı gönder
                        if input_type_display == 'form':
                            target_selenium_element.submit()
                        else: # Pseudo form (input/textarea)
                            try:
                                target_selenium_element.send_keys(webdriver.common.keys.Keys.ENTER)
                            except Exception:
                                pass # Eğer enter tuşu bir submit tetiklemezse sorun değil.

                        time.sleep(1) # Yanıtı ve JS'in çalışmasını bekle

                        alert_present = False
                        alert_text = ""
                        try:
                            alert = self.driver.switch_to.alert
                            alert_text = alert.text
                            alert.accept()
                            alert_present = True
                        except UnexpectedAlertPresentException as e:
                            self.logger(f"        [!] Beklenmeyen bir alert tetiklendi (otomatik kapatıldı): {e.alert_text}", "warning")
                            alert_text = e.alert_text
                            e.alert.accept()
                            alert_present = True
                        except TimeoutException:
                            alert_present = False

                        if alert_present and "xss-vuln" in alert_text.lower():
                            self.exploit_logger("\n[‼️] GERÇEK XSS (CROSS-SITE SCRIPTING) AÇIĞI TESPİT EDİLDİ!\n", "exploit_success")
                            self.exploit_logger(f"    Zafiyet Yeri        : {input_type_display.capitalize()} Parametresi\n", "warning")
                            self.exploit_logger(f"    Hedef URL           : {target_url}\n", "warning")
                            self.exploit_logger(f"    Etkilenen Parametre : '{input_name}'\n", "exploit_success")
                            self.exploit_logger(f"    Kullanılan Payload  : '{payload_value}'\n", "exploit_success")
                            self.exploit_logger(f"    Tespit Detayı       : Payload tarayıcıda başarıyla yürütüldü ve 'alert(\"{alert_text}\")' tetiklendi.\n", "exploit_success")
                            
                            screenshot_name = f"xss_form_{input_name}_{time.time()}.png"
                            screenshot_path = self.screenshot_manager.take_screenshot(screenshot_name)
                            if screenshot_path:
                                self.exploit_logger(f"    Ekran Görüntüsü     : {screenshot_path}\n", "info")
                            
                            self._search_cve_for_vulnerability_type("xss")
                            vulnerability_found = True
                            return True # İlk başarılı tespitte dur
                        # else:
                        #     self.logger(f"        [i] Alert tetiklenmedi veya beklenen XSS metni içermiyor.", "debug")

                    except TimeoutException:
                        self.logger(f"        [i] Sayfa/element yükleme zaman aşımı ({source_url}). XSS testi atlanıyor.", "warning")
                    except WebDriverException as e:
                        self.logger(f"        [!] Selenium hatası ({source_url}): {type(e).__name__} - {str(e)[:100]}...\n", "error")
                    except Exception as e:
                        self.logger(f"        [!] XSS testi sırasında beklenmeyen hata ({source_url}): {type(e).__name__} - {str(e)}\n", "error")
                if vulnerability_found:
                    break # Bir input alanında başarı varsa, diğer payload'lara geçmeye gerek yok
        return vulnerability_found