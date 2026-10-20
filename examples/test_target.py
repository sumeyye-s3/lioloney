#!/usr/bin/env python3
"""
test_target.py
---------------
LIOLONEY'i test etmek için sahte, kasıtlı ZAYIF bir login sunucusu.
5 yanlış denemeden sonra 10 saniye kilitler (gerçek hayatta 30 sn olabilir,
testi hızlı tutmak için burada 10 sn verdim).

KİLİTLEME MODELİ: HESAP BAZLI (kullanıcı adına göre), IP bazlı DEĞİL.
Yani usernames.txt'deki her kullanıcı adının kendi bağımsız 5 deneme/10 sn
kotası vardır. Aynı IP'den (127.0.0.1) birden çok kullanıcı adı denemek
birbirini kilitlemez -> LIOLONEY'in "her kullanıcı için ayrı worker" tasarımı
burada gerçek bir paralellik avantajı sağlar.

Gizli şifre: tarih bazlı bir PIN (priority_passwords.txt içinde olduğu için
LIOLONEY'in bunu dakikalar içinde bulması beklenir).

Kurulum: pip install flask
Çalıştırma: python3 test_target.py
Sonra başka bir terminalde:
    echo admin > usernames.txt
    python3 lioloney.py -u http://127.0.0.1:8000/login --mode form-post \
        -d "username=FUSER&password=FPASS" -U usernames.txt \
        -f "Invalid credentials" --lockout-text "Too many attempts" \
        --lockout-threshold 5 --lockout-wait 10 -c 20 --dashboard
"""

from flask import Flask, request
import time

app = Flask(__name__)

SECRET_PASSWORD = "150395"  # priority_passwords.txt içinde var (DDMMYY formatı)
failed_attempts = {}  # username -> (count, locked_until)  <- artık IP değil, KULLANICI ADI bazlı
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 10


@app.route("/login", methods=["GET", "POST"])
def login():
    now = time.time()

    if request.method == "GET":
        username = request.args.get("username", "")
        password = request.args.get("password", "")
    else:
        username = request.form.get("username", "")
        password = request.form.get("password", "")

    # Sayaç artık kullanıcı adına bağlı, IP'ye değil -> her kullanıcının kendi kotası var
    count, locked_until = failed_attempts.get(username, (0, 0))

    if now < locked_until:
        return "Too many attempts, try again later.", 429

    if password == SECRET_PASSWORD:
        failed_attempts.pop(username, None)
        return "Login successful! Welcome.", 200
    else:
        count += 1
        if count >= LOCKOUT_THRESHOLD:
            failed_attempts[username] = (0, now + LOCKOUT_SECONDS)
            return "Too many attempts, try again later.", 429
        failed_attempts[username] = (count, 0)
        return "Invalid credentials", 401


if __name__ == "__main__":
    print(f"[*] Sahte hedef çalışıyor: http://127.0.0.1:8000/login")
    print(f"[*] Gizli şifre: {SECRET_PASSWORD} (sadece test/doğrulama amaçlı)")
    app.run(host="127.0.0.1", port=8000)
