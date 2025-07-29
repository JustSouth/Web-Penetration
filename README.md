# XSS & SQL Injection Scanner Tool

Bu proje, web uygulamalarında XSS (Cross-Site Scripting) ve SQL Injection açıklarını otomatik olarak tespit etmek amacıyla geliştirilmiş bir güvenlik analiz aracıdır.

⚠️ **Yalnızca eğitim ve etik hacking amaçlarıyla kullanılmalıdır. İzinsiz taramalar yasal sonuçlara yol açabilir.**

---

## 🔍 Özellikler

- Belirtilen URL üzerinde XSS ve SQLi testleri uygular
- Payload dosyaları kullanıcı tarafından düzenlenebilir
- Subdomain taraması desteği
- Otomatik analiz ve raporlama

---

📁 Yapı
payloads/
├── xss_payloads.txt
└── sql_payloads.txt


## ⚙️ Kurulum

```bash
git clone https://github.com/kullaniciadi/xss-sqli-scanner.git
cd xss-sqli-scanner
pip install -r requirements.txt
