# Mini Security Scanner

Termux ve Windows uyumlu, web güvenlik tarama aracı. SQL Injection, XSS, Command Injection gibi zafiyetleri tespit eder.

## 📋 Özellikler

- ✅ SQL Injection testi
- ✅ XSS testi
- ✅ Command Injection testi
- ✅ Çoklu hedef tarama
- ✅ Form ve URL parametrelerini otomatik tespit
- ✅ JSON, CSV, HTML, TXT rapor çıktısı
- ✅ Proxy desteği
- ✅ Rate limiting / delay
- ✅ Renkli terminal çıktısı
- ✅ İnteraktif menü
- ✅ Termux & Windows uyumlu

## 🚀 Kurulum

```bash
# Repoyu klonla
git clone https://github.com/zaza219-hub/mini-security-scanner.git
cd mini-security-scanner

# Gereksinimleri yükle
pip install -r requirements.txt

# direkt kurulum
python setup.py install

#son adım
python scanner.py