import requests
from requests.exceptions import ConnectionError, Timeout, RequestException
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json
import config # config.py'yi import ediyoruz

class SQLInjector:
    def __init__(self, logger, exploit_logger):
        self.logger = logger
        self.exploit_logger = exploit_logger

    def _send_request_and_check_errors(self, url, method, params_or_data):
        try:
            if method == 'get':
                r = requests.get(url, params=params_or_data, timeout=7, verify=False)
            elif method == 'post':
                r = requests.post(url, data=params_or_data, timeout=7, verify=False)
            else:
                return None, False

            content = r.text

            sql_error_keywords = [
                "sql", "syntax", "mysql", "query", "warning", "error in your sql",
                "unclosed quotation mark", "microsoft sql server", "odbc", "sqlite error",
                "java.sql.sqlexception", "supplied argument is not a valid mysql result resource",
                "fatal error", "parse error", "db error", "database error", "error 500",
                "sqlstate", "sqlserver", "postgresql", "oracle error", "column count"
            ]

            is_sql_error = any(keyword in content.lower() for keyword in sql_error_keywords)

            return r, is_sql_error

        except ConnectionError as e:
            self.logger(f"[!] Bağlantı hatası: {type(e).__name__} - {str(e)}", "warning")
        except Timeout as e:
            self.logger(f"[!] Zaman aşımı hatası: {type(e).__name__} - {str(e)}", "warning")
        except RequestException as e:
            self.logger(f"[!] İstek hatası: {type(e).__name__} - {str(e)}", "warning")
        except Exception as e:
            self.logger(f"[!] Beklenmeyen hata: {type(e).__name__} - {str(e)}", "error")
        return None, False

    def _search_cve_for_vulnerability_type(self, vulnerability_type):
        query_keyword = ""
        if vulnerability_type == "sql":
            query_keyword = "SQL Injection"
        
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
        except RequestException as e:
            self.exploit_logger(f"[!] CVE API istek hatası: {type(e).__name__} - {str(e)}\n", "error")
        except json.JSONDecodeError:
            self.exploit_logger(f"[!] CVE API yanıtı JSON olarak ayrıştırılamadı. Geçersiz yanıt.\n", "error")
        except Exception as e:
            self.exploit_logger(f"[!] CVE aramasında beklenmeyen hata: {type(e).__name__} - {str(e)}\n", "error")


    def test_url_parameters_sql(self, url, payloads):
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

                r, is_sql_error = self._send_request_and_check_errors(test_url, 'get', test_params)

                if r and is_sql_error:
                    self.exploit_logger("\n[‼️] SQL ENJEKSİYON AÇIĞI TESPİT EDİLDİ!\n", "exploit_success")
                    self.exploit_logger(f"    Zafiyet Yeri        : URL Parametresi\n", "warning")
                    self.exploit_logger(f"    Hedef URL           : {url}\n", "warning")
                    self.exploit_logger(f"    Etkilenen Parametre : '{key}'\n", "exploit_success")
                    self.exploit_logger(f"    Kullanılan Payload  : '{payload_value}'\n", "exploit_success")
                    self.exploit_logger(f"    Test URL            : {test_url}\n", "exploit_success")
                    self.exploit_logger(f"    Tespit Detayı       : Sunucu yanıtında SQL hata mesajı belirteçleri tespit edildi.\n", "exploit_success")
                    self._search_cve_for_vulnerability_type("sql")
                    vulnerability_found = True
                    return True # İlk başarılı tespitte dur

        return vulnerability_found

    def test_input_element_sql(self, input_element_data, payloads):
        vulnerability_found = False
        target_url = input_element_data['action']
        method = input_element_data['method']
        inputs = input_element_data['inputs']
        source_url = input_element_data.get('source_url', 'Bilinmiyor')
        input_type_display = input_element_data['type']

        for input_field in inputs:
            input_name = input_field['name']
            field_type = input_field['type']

            if field_type in ['text', 'password', 'email', 'search', 'url', 'tel', 'number', 'textarea']:
                for payload_value in payloads:
                    test_params = {}
                    for other_input in inputs:
                        if other_input['name'] == input_name:
                            test_params[other_input['name']] = payload_value
                        elif other_input['type'] == 'hidden':
                            test_params[other_input['name']] = other_input.get('value', '')
                        elif other_input['type'] in ['radio', 'checkbox']:
                            test_params[other_input['name']] = other_input.get('value', 'on') # varsayılan değer
                        else:
                            test_params[other_input['name']] = 'test_value' # Diğer alanları doldur

                    r, is_sql_error = self._send_request_and_check_errors(target_url, method, test_params)

                    if r and is_sql_error:
                        self.exploit_logger("\n[‼️] SQL ENJEKSİYON AÇIĞI TESPİT EDİLDİ!\n", "exploit_success")
                        self.exploit_logger(f"    Zafiyet Yeri        : {input_type_display.capitalize()} Parametresi\n", "warning")
                        self.exploit_logger(f"    Hedef URL           : {target_url}\n", "warning")
                        self.exploit_logger(f"    Metot               : {method.upper()}\n", "warning")
                        self.exploit_logger(f"    Etkilenen Parametre : '{input_name}'\n", "exploit_success")
                        self.exploit_logger(f"    Kullanılan Payload  : '{payload_value}'\n", "exploit_success")
                        self.exploit_logger(f"    Tespit Detayı       : Sunucu yanıtında SQL hata mesajı belirteçleri tespit edildi.\n", "exploit_success")
                        self._search_cve_for_vulnerability_type("sql")

                        # Login bypass denemesi (sadece başarılı SQL hatası bulunursa simülasyon)
                        if "login" in source_url.lower() or "giris" in source_url.lower() or \
                           ("user" in input_name.lower() or "pass" in input_name.lower()):
                            self.exploit_logger(f"\n    [i] Potansiyel login alanı. Login bypass denemesi simüle ediliyor.", "exploit_info")
                            login_bypass_payload = "admin' OR '1'='1--"
                            self.exploit_logger(f"    Simüle Edilen Payload: '{login_bypass_payload}'", "exploit_info")
                            self.exploit_logger(f"    Eğer bu payload ile giriş başarılı olursa, login bypass mümkündür.\n", "exploit_info")

                        vulnerability_found = True
                        return True # İlk başarılı tespitte dur
        return vulnerability_found