# LIOLONEY🍯

**LIOLONEY** is an educational, asyncio-based HTTP/HTTPS credential brute-force
tool built for authorized penetration testing labs (TryHackMe, HTB, DVWA,
your own test environments). It focuses on **lockout-aware** testing: instead
of blindly hammering a target, it self-throttles per account to avoid
wasting time on login-attempt lockouts, and ships with a built-in local
dashboard for live progress.

> ⚠️ **Legal / Ethical use only.** Use LIOLONEY exclusively against systems
> you own or are explicitly authorized to test (CTF platforms, your own lab,
> a signed pentest engagement). Running this against systems you don't have
> permission to test is illegal in most jurisdictions. The authors assume no
> liability for misuse.

---

## Why LIOLONEY

Most brute-force tools treat every login attempt the same way. In practice,
real targets implement **account lockout** (e.g. "5 wrong attempts → 30s
lock"), which makes naive brute-forcing extremely slow — or outright
impossible for anything beyond a handful of digits.

LIOLONEY's design choices:

- **Per-username workers** — each username runs as its own independent task
  with its own lockout budget, so while one account is "cooling down",
  others keep going. If lockout is scoped per-account (the common case),
  this multiplies effective throughput by the number of usernames you have.
- **Proactive throttling** — it pauses *before* hitting the lockout
  threshold, instead of triggering the lockout and then reacting to it.
- **Honest math** — the tool warns you when a keyspace is large enough that
  no amount of engineering will make it finish in reasonable time (e.g. a
  full 10-digit numeric keyspace under a 5-attempts/30s lockout).

This is **not** a claim that LIOLONEY is unconditionally "faster than Hydra
or ffuf" — those are mature, battle-tested tools. LIOLONEY's value is being
purpose-built, transparent, and easy to extend for your own test scenarios.

## Features

- 4 attack modes: `http-get`, `http-post` (HTTP Basic Auth), `form-get`,
  `form-post` (web login forms)
- HTTP and HTTPS targets only (scheme is validated)
- Numeric password generation on the fly, 1–10 digits (`--min-len`/`--max-len`)
  — no need to store a multi-gigabyte wordlist file
- A bundled, curated wordlist (`wordlists/priority_passwords.txt`,
  ~116k entries) combining known common numeric passwords, repeated/sequential
  digit patterns, and date-based PINs (birth years, DDMMYY/MMDDYY/YYYYMMDD) —
  used automatically if you don't pass your own list
- Bring your own wordlist (`-P`) or merge an entire folder of lists
  (`--wordlist-dir`) so you and collaborators can keep adding wordlists over time
- Lockout-aware scheduling: proactive self-throttle (`--lockout-threshold`,
  `--lockout-wait`) plus optional detection of a real lockout response
  (`--lockout-text`)
- Live local dashboard (`--dashboard`) with progress bar, request-rate chart,
  and an HTTP status code breakdown — self-contained, no external JS
  dependency, works fully offline
- A ready-to-run mock vulnerable login server (`examples/test_target.py`) so
  you can test the whole thing end-to-end on localhost before pointing it at
  a real lab target

## Installation

```bash
git clone https://github.com/<your-username>/lioloney.git
cd lioloney
pip install -r requirements.txt
```

Requires Python 3.9+.

## Quick start (test against the included mock target)

```bash
# Terminal 1 — start a deliberately weak local login server
python3 examples/test_target.py

# Terminal 2 — run LIOLONEY against it
echo admin > usernames.txt
python3 lioloney.py -u http://127.0.0.1:8000/login --mode form-post \
    -d "username=FUSER&password=FPASS" -U usernames.txt \
    -f "Invalid credentials" --lockout-text "Too many attempts" \
    --lockout-threshold 5 --lockout-wait 10 -c 20 --dashboard
```

Open `http://127.0.0.1:5000` to watch live progress, request rate, and the
status code breakdown.

## Usage

### Attack modes

| Mode        | Auth style           | Success check                  |
|-------------|-----------------------|---------------------------------|
| `http-get`  | HTTP Basic Auth (GET) | HTTP status code                |
| `http-post` | HTTP Basic Auth (POST)| HTTP status code                |
| `form-get`  | Web form, GET params  | Absence of a failure string     |
| `form-post` | Web form, POST body   | Absence of a failure string     |

```bash
# HTTP Basic Auth
python3 lioloney.py -u http://target/admin --mode http-get \
    -U usernames.txt -P passwords.txt --success-status 200

# Web form (POST)
python3 lioloney.py -u http://target/login --mode form-post \
    -d "username=FUSER&password=FPASS" -U usernames.txt \
    -f "Invalid credentials"

# Web form (GET)
python3 lioloney.py -u "http://target/login?username=FUSER&password=FPASS" \
    --mode form-get -U usernames.txt -f "Invalid credentials"
```

### Password sources (priority order)

1. `-P passwords.txt` — your own list
2. `--wordlist-dir ./wordlists` — merge every `.txt` file in a folder
3. `--min-len N --max-len M` — generate all numeric combinations on the fly
   (1 ≤ N ≤ M ≤ 10)
4. *(default, if none of the above given)* — the bundled
   `wordlists/priority_passwords.txt`

### Lockout handling

```bash
--lockout-threshold 5     # attempts before self-throttling (default: 5)
--lockout-wait 30         # seconds to pause (default: 30)
--lockout-text "Too many attempts"   # optional: also detect a real lockout response
```

Each username is handled by its own worker, so it pauses independently
without blocking other usernames' progress.

### Dashboard

```bash
--dashboard                 # enable
--dashboard-port 5050       # change port (default: 5000; note macOS AirPlay
                             # also uses 5000 — change the port if it conflicts)
```

Bound to `127.0.0.1` only — not reachable from other machines on your network.

## Project structure

```
lioloney/
├── lioloney.py                      # main tool
├── wordlists/
│   └── priority_passwords.txt       # bundled default wordlist
├── examples/
│   └── test_target.py               # mock vulnerable login server, for local testing
├── requirements.txt
└── README.md
```

## Contributing

Pull requests that add new wordlists are welcome — just drop a `.txt` file
(one password per line) into `wordlists/` and it becomes usable via
`--wordlist-dir wordlists`. Other contributions (new modes, better lockout
heuristics, dashboard improvements) are welcome too.

## Disclaimer

This project is for educational use and authorized security testing only
(CTF platforms like TryHackMe/HackTheBox, your own lab environments, or
engagements you are explicitly contracted/authorized to test). Unauthorized
access to computer systems is illegal in most countries. You are solely
responsible for how you use this tool.

## License

MIT — see [LICENSE](LICENSE).
