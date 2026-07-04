"""
Kurala karşı test edilecek, tamamen zararsız/gerçekçi kurumsal HTTP trafiği
örnekleri. Amaç: kuralın gerçek dünyadaki meşru trafikte yanlış pozitif
(false positive) üretip üretmediğini ölçmek.

Bu istekler herhangi bir exploit, saldırı deseni ya da zararlı payload
içermez; günlük kurumsal web kullanımını (login, arama, dosya indirme,
API çağrısı, sağlık kontrolü vb.) simüle eder.
"""

CLEAN_HTTP_REQUESTS = [
    # Basit sayfa görüntüleme
    "GET / HTTP/1.1\r\nHost: intranet.corp.local\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    # Login formu
    (
        "POST /login HTTP/1.1\r\nHost: portal.corp.local\r\nUser-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\n\r\n"
        "username=jdoe&password=Str0ngPass!"
    ),
    # Arama sorgusu
    "GET /search?q=quarterly+report+2026 HTTP/1.1\r\nHost: wiki.corp.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    # API sağlık kontrolü
    "GET /api/v1/health HTTP/1.1\r\nHost: api.corp.local\r\nUser-Agent: HealthCheck/1.0\r\nAccept: application/json\r\n\r\n",
    # Dosya indirme
    "GET /files/annual_report.pdf HTTP/1.1\r\nHost: docs.corp.local\r\nUser-Agent: Mozilla/5.0\r\nRange: bytes=0-1023\r\n\r\n",
    # REST API - JSON gövdeli POST
    (
        "POST /api/v1/orders HTTP/1.1\r\nHost: api.corp.local\r\nUser-Agent: internal-service/2.3\r\n"
        "Content-Type: application/json\r\nContent-Length: 46\r\n\r\n"
        '{"order_id": 10234, "status": "confirmed"}'
    ),
    # CSS/JS statik dosya
    "GET /static/app.min.js HTTP/1.1\r\nHost: cdn.corp.local\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
    # Webhook bildirimi
    (
        "POST /webhooks/ci HTTP/1.1\r\nHost: ci.corp.local\r\nUser-Agent: GitHubHookShot/1.0\r\n"
        "Content-Type: application/json\r\nContent-Length: 40\r\n\r\n"
        '{"event": "push", "branch": "main"}'
    ),
    # E-posta gönderim formu (helpdesk)
    (
        "POST /helpdesk/ticket HTTP/1.1\r\nHost: support.corp.local\r\nUser-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 46\r\n\r\n"
        "subject=Printer+not+working&priority=low&dept=IT"
    ),
    # Basit GET, cookie'li oturum
    "GET /dashboard HTTP/1.1\r\nHost: portal.corp.local\r\nCookie: session=a1b2c3d4e5\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
]
