"""
╔══════════════════════════════════════════════════════════════════════╗
║        BLOODLINE OSINT TOOL  —  Edition  v2.0                        ║
║        Yasal OSINT araştırmaları için tasarlanmıştır.                ║
║        Kişisel veri toplama / yasadışı kullanım yasaktır.            ║
╚══════════════════════════════════════════════════════════════════════╝

Modüller:
  • IP / Web Analyze   — GeoIP, ISP, ASN, harita
  • UserFind           — 40+ platform paralel tarama
  • Mail Analyze       — MX/TXT/NS/A kayıtları + SMTP doğrulama
  • Phone Analyze      — ülke / operatör / geçerlilik
  • OP Analyze         — global MCC/MNC operatör DB
  • WHOIS              — raw 2-adımlı IANA sorgusu
  • DNS Lookup         — A/MX/NS/TXT/CNAME/AAAA
  • Subdomain Tarayıcı — crt.sh + brute-force
  • Port Tarayıcı      — açık port tespiti
  • SSL/TLS Analizi    — sertifika bilgisi
  • Email Doğrulama    — SMTP varlık kontrolü
  • Breach Kontrolü    — HaveIBeenPwned API
  • Shodan             — cihaz / banner (API key gerekli)
  • Komut Paneli       — tüm analizler CLI'dan
  • Sorgu Geçmişi      — log görüntüleme
  • Favori Hedefler    — hızlı erişim
  • Cache sistemi      — tekrar sorguları önbellekten
  • Proxy desteği      — SOCKS5 / HTTP
  • HTML Rapor         — şablonlu dışa aktarma
"""

# ──────────────────────────────────────────────────────────────────────
#  STDLIB
# ──────────────────────────────────────────────────────────────────────
import tkinter as tk
from tkinter import filedialog, ttk
import tkinter.messagebox as messagebox
import math, threading, json, os, requests, time, ssl, socket
import re, difflib, datetime, hashlib, smtplib, concurrent.futures
import urllib.parse, ipaddress, struct, random

# ──────────────────────────────────────────────────────────────────────
#  PATHS
# ──────────────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE    = os.path.join(BASE_DIR, "config.json")
OPERATORS_FILE = os.path.join(BASE_DIR, "operators.json")
LOG_FILE       = os.path.join(BASE_DIR, "bloodline_log.txt")
CACHE_FILE     = os.path.join(BASE_DIR, "bloodline_cache.json")
FAVORITES_FILE = os.path.join(BASE_DIR, "bloodline_favorites.json")

# ──────────────────────────────────────────────────────────────────────
#  THEME
# ──────────────────────────────────────────────────────────────────────
APP_BG   = "#0b0b0b"
SIDE_BG  = "#0e0e0e"
TOP_BG   = "#0f0f0f"
CARD_BG  = "#111111"
INPUT_BG = "#161616"
OUT_BG   = "#0d0d0d"
BORDER   = "#252525"
TEXT_FG  = "#d0d0d0"
MUTED_FG = "#888888"
GREEN_FG = "#00ff88"
WARN_FG  = "#ffcc00"
ERR_FG   = "#ff4444"
BLUE_FG  = "#00d4ff"

# ──────────────────────────────────────────────────────────────────────
#  DEFAULT CONFIG
# ──────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "ui_color":    "#ff2a2a",
    "wave_color":  "#ff2a2a",
    "timeout":     10,
    "log_enabled": True,
    "cache_enabled": True,
    "cache_ttl":   3600,
    "proxy":       "",
    "shodan_key":  "",
    "hibp_key":    "",
    "max_ports":   1024,
    "port_threads": 100,
    "sub_threads": 50,
    "user_threads": 20,
}

MCCMNC_RAW_URL = (
    "https://raw.githubusercontent.com/telecomhall/mcc-mnc/master/mccmnc.json"
)

# ──────────────────────────────────────────────────────────────────────
#  SAFE IMPORTS
# ──────────────────────────────────────────────────────────────────────
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder
    from phonenumbers import timezone as pn_tz, number_type
    PHONE_OK = True
except ImportError:
    PHONE_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import socks
    SOCKS_OK = True
except ImportError:
    SOCKS_OK = False

# ══════════════════════════════════════════════════════════════════════
#  PLATFORM LIST  (single source of truth)
# ══════════════════════════════════════════════════════════════════════
PLATFORMS: dict[str, str] = {
    # Social
    "Twitter / X":   "https://x.com/{}",
    "Instagram":     "https://instagram.com/{}",
    "Facebook":      "https://www.facebook.com/{}",
    "LinkedIn":      "https://www.linkedin.com/in/{}",
    "TikTok":        "https://www.tiktok.com/@{}",
    "Snapchat":      "https://www.snapchat.com/add/{}",
    "Pinterest":     "https://pinterest.com/{}",
    "Tumblr":        "https://{}.tumblr.com",
    "Reddit":        "https://reddit.com/user/{}",
    "Quora":         "https://www.quora.com/profile/{}",
    "Mastodon":      "https://mastodon.social/@{}",
    "Bluesky":       "https://bsky.app/profile/{}",
    "Threads":       "https://www.threads.net/@{}",
    # Video / Stream
    "YouTube":       "https://youtube.com/{}",
    "Twitch":        "https://twitch.tv/{}",
    "Kick":          "https://kick.com/{}",
    "Dailymotion":   "https://www.dailymotion.com/{}",
    "Vimeo":         "https://vimeo.com/{}",
    # Gaming
    "Roblox":        "https://roblox.com/users/profile?username={}",
    "Steam":         "https://steamcommunity.com/id/{}",
    "Epic Games":    "https://www.epicgames.com/id/{}",
    "Xbox":          "https://account.xbox.com/en-us/Profile?gamerTag={}",
    "Origin/EA":     "https://www.origin.com/profile/{}",
    "PlayStation":   "https://my.playstation.com/{}",
    "Minecraft":     "https://namemc.com/profile/{}",
    "Discord":       "https://discord.com/users/{}",
    "Battle.net":    "https://battle.net/{}",
    "Ubisoft":       "https://ubisoftconnect.com/en-US/profile/{}",
    # Dev / Tech
    "GitHub":        "https://github.com/{}",
    "GitLab":        "https://gitlab.com/{}",
    "Bitbucket":     "https://bitbucket.org/{}",
    "Replit":        "https://replit.com/@{}",
    "HackerNews":    "https://news.ycombinator.com/user?id={}",
    "npm":           "https://www.npmjs.com/~{}",
    "PyPI":          "https://pypi.org/user/{}",
    "Keybase":       "https://keybase.io/{}",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    # Creative
    "Medium":        "https://medium.com/@{}",
    "Behance":       "https://www.behance.net/{}",
    "Dribbble":      "https://dribbble.com/{}",
    "DeviantArt":    "https://www.deviantart.com/{}",
    "Flickr":        "https://www.flickr.com/people/{}",
    "500px":         "https://500px.com/p/{}",
    # Music
    "SoundCloud":    "https://soundcloud.com/{}",
    "Bandcamp":      "https://{}.bandcamp.com",
    "Spotify":       "https://open.spotify.com/user/{}",
    "Last.fm":       "https://www.last.fm/user/{}",
    # Freelance / Business
    "Fiverr":        "https://www.fiverr.com/{}",
    "Upwork":        "https://www.upwork.com/freelancers/{}",
    "Patreon":       "https://www.patreon.com/{}",
    "Ko-fi":         "https://ko-fi.com/{}",
}

PLATFORM_CATS = {
    "Sosyal":     ["Twitter / X","Instagram","Facebook","LinkedIn","TikTok","Snapchat","Pinterest","Tumblr","Reddit","Quora","Mastodon","Bluesky","Threads"],
    "Video":      ["YouTube","Twitch","Kick","Dailymotion","Vimeo"],
    "Oyun":       ["Roblox","Steam","Epic Games","Xbox","Origin/EA","PlayStation","Minecraft","Discord","Battle.net","Ubisoft"],
    "Geliştirici":["GitHub","GitLab","Bitbucket","Replit","HackerNews","npm","PyPI","Keybase","StackOverflow"],
    "Yaratıcı":   ["Medium","Behance","Dribbble","DeviantArt","Flickr","500px"],
    "Müzik":      ["SoundCloud","Bandcamp","Spotify","Last.fm"],
    "İş":         ["Fiverr","Upwork","Patreon","Ko-fi"],
}

# ══════════════════════════════════════════════════════════════════════
#  COMMON SUBDOMAINS  (brute-force wordlist)
# ══════════════════════════════════════════════════════════════════════
SUBDOMAIN_WORDLIST = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","remote",
    "api","dev","staging","test","beta","demo","sandbox","preview",
    "admin","panel","dashboard","portal","manage","cpanel","webmail",
    "blog","shop","store","app","mobile","m","cdn","static","assets",
    "img","images","media","files","upload","download","docs","wiki",
    "support","help","kb","forum","community","chat","news","status",
    "monitor","metrics","grafana","jenkins","git","gitlab","bitbucket",
    "jira","confluence","redmine","teamcity","ci","cd","build",
    "db","database","mysql","postgres","redis","mongo","elastic",
    "ns1","ns2","mx","mx1","mx2","relay","gateway","proxy","vpn2",
    "auth","sso","login","accounts","id","oauth","connect",
    "old","legacy","v1","v2","v3","backup","archive","mirror",
    "internal","intranet","office","corp","extranet","private",
]

# ══════════════════════════════════════════════════════════════════════
#  HELPERS  —  config / cache / log / operators
# ══════════════════════════════════════════════════════════════════════

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict) -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[config] save error: {e}")


def load_operators() -> list:
    if os.path.exists(OPERATORS_FILE):
        try:
            with open(OPERATORS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception as e:
            print(f"[operators] parse error: {e}")
    return []


def load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_cache(cache: dict) -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def cache_get(cache: dict, key: str, ttl: int) -> str | None:
    entry = cache.get(key)
    if entry and (time.time() - entry.get("ts", 0)) < ttl:
        return entry.get("val")
    return None


def cache_set(cache: dict, key: str, val: str) -> None:
    cache[key] = {"ts": time.time(), "val": val}


def load_favorites() -> list:
    if os.path.exists(FAVORITES_FILE):
        try:
            with open(FAVORITES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def save_favorites(favs: list) -> None:
    try:
        with open(FAVORITES_FILE, "w", encoding="utf-8") as f:
            json.dump(favs, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def append_log(entry: str, enabled: bool = True) -> None:
    if not enabled:
        return
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {entry}\n")
    except Exception:
        pass


def make_session(proxy: str = "") -> requests.Session:
    """Proxy destekli requests session üretir."""
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (compatible; BloodlineOSINT/2.0)"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def build_operators_json_from_mccmnc(output_path: str = OPERATORS_FILE,
                                      proxy: str = "") -> str:
    try:
        sess = make_session(proxy)
        r = sess.get(MCCMNC_RAW_URL, timeout=40)
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        return f"[✘] MCC/MNC indirilemedi: {e}\n"

    if not isinstance(rows, list):
        return "[✘] MCC/MNC veri formatı beklenmedik.\n"

    index: dict = {}
    for row in rows:
        name = (row.get("network") or row.get("operator") or row.get("brand") or "").strip()
        if not name:
            continue
        mcc  = str(row.get("mcc", "")).strip()
        mnc  = str(row.get("mnc", "")).strip()
        plmn = f"{mcc}-{mnc}" if (mcc and mnc) else None
        iso  = (row.get("countryIso") or row.get("iso") or "").strip().upper()
        country = iso if iso else (row.get("countryName") or "").strip()
        key = (name.lower(), country)
        if key not in index:
            index[key] = {"name": name, "countries": [country] if country else [],
                          "type": (row.get("type") or "").strip().lower(),
                          "website": "", "mcc_mnc": [],
                          "notes": "Generated from MCC/MNC list."}
        ent = index[key]
        if plmn and plmn not in ent["mcc_mnc"]:
            ent["mcc_mnc"].append(plmn)
        if country and country not in ent["countries"]:
            ent["countries"].append(country)

    out = list(index.values())
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        return f"[✔] operators.json üretildi.\nKayıt: {len(out)}\nKonum: {output_path}\n"
    except Exception as e:
        return f"[✘] Yazılamadı: {e}\n"


# ══════════════════════════════════════════════════════════════════════
#  WAVE CANVAS
# ══════════════════════════════════════════════════════════════════════

class WaveCanvas(tk.Canvas):
    def __init__(self, master, color: str):
        super().__init__(master, bg=APP_BG, highlightthickness=0)
        self.phase   = 0.0
        self.color   = color
        self.running = True
        self.after(40, self._animate)

    def set_color(self, color: str) -> None:
        self.color = color

    def stop(self) -> None:
        self.running = False
        self.delete("all")

    def _animate(self) -> None:
        if not self.running:
            return
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 50 or h < 50:
            self.after(60, self._animate)
            return
        for i in range(4):
            pts = []
            amp, freq = 18 + i * 4, 55 + i * 8
            phase = self.phase + i * 0.6
            for x in range(0, w + 15, 15):
                y = h / 2 + math.sin(x / freq + phase) * amp
                pts.extend([x, y])
            if len(pts) >= 4:
                self.create_line(pts, fill=self.color, width=max(1, 3 - i), smooth=True)
        self.phase += 0.12
        self.after(40, self._animate)


# ══════════════════════════════════════════════════════════════════════
#  WHOIS
# ══════════════════════════════════════════════════════════════════════

def simple_whois(domain: str, timeout: int = 10) -> str:
    domain = domain.strip().lower()
    if not domain or " " in domain:
        return "[✘] Geçersiz domain.\n"
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode())
            raw = b""
            while chunk := s.recv(4096):
                raw += chunk
        iana_text = raw.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[✘] IANA WHOIS başarısız: {e}\n"

    whois_server = None
    for line in iana_text.splitlines():
        if line.lower().startswith("whois:"):
            whois_server = line.split(":", 1)[1].strip()
            break
    whois_server = whois_server or "whois.verisign-grs.com"

    try:
        with socket.create_connection((whois_server, 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode())
            raw = b""
            while chunk := s.recv(4096):
                raw += chunk
        return raw.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[✘] WHOIS sunucusu ({whois_server}) bağlantı hatası: {e}\n"


# ══════════════════════════════════════════════════════════════════════
#  ANALYSIS FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def ip_geo_lookup(target: str, timeout: int = 10, proxy: str = "") -> str:
    """GeoIP + PTR + ISP + ASN + sinyal analizi."""
    target = target.strip()
    if not target:
        return "[✘] Hedef giriniz.\n"

    ip = target
    is_domain = any(ch.isalpha() for ch in target)
    if is_domain:
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return "[✘] Domain çözümlenemedi (DNS hatası).\n"

    lines = [f"[✔] Hedef   : {target}", f"[✔] IP      : {ip}"]

    try:
        ptr = socket.gethostbyaddr(ip)[0]
        lines.append(f"[✔] PTR     : {ptr}")
    except Exception:
        lines.append("[ℹ] PTR     : Bulunamadı")

    # Private IP check
    try:
        if ipaddress.ip_address(ip).is_private:
            lines += ["", "[ℹ] Özel/yerel IP adresi — GeoIP sorgusu atlandı."]
            return "\n".join(lines) + "\n"
    except Exception:
        pass

    try:
        sess = make_session(proxy)
        geo  = sess.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,regionName,city,district,"
            "lat,lon,isp,org,as,hosting,proxy,mobile,query,timezone",
            timeout=timeout,
        ).json()
    except Exception as e:
        lines.append(f"[✘] GeoIP başarısız: {e}")
        return "\n".join(lines) + "\n"

    if geo.get("status") != "success":
        lines.append("[✘] GeoIP veri döndürmedi.")
        return "\n".join(lines) + "\n"

    lines += ["", "─── Yaklaşık Konum ─────────────────────────────"]
    for k, lbl in [("country","Ülke      "),("regionName","Bölge     "),
                   ("city","Şehir     "),("district","İlçe      "),
                   ("timezone","Zaman D.  ")]:
        v = geo.get(k)
        if v:
            lines.append(f"  {lbl}: {v}")

    lines += ["", "─── Ağ / Operatör ──────────────────────────────"]
    for k, lbl in [("isp","ISP      "),("org","Org      "),("as","ASN      ")]:
        v = geo.get(k)
        if v:
            lines.append(f"  {lbl}: {v}")

    lines += ["", "─── Sinyaller ──────────────────────────────────"]
    lines.append(f"  Hosting/DC   : {'EVET' if geo.get('hosting') else 'HAYIR'}")
    lines.append(f"  Proxy/VPN    : {'EVET' if geo.get('proxy')   else 'HAYIR'}")
    lines.append(f"  Mobil        : {'EVET' if geo.get('mobile')  else 'HAYIR'}")

    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is not None and lon is not None:
        lines += ["", "─── Harita ─────────────────────────────────────",
                  f"  Koordinat  : {lat}, {lon}",
                  f"  Google Maps: https://www.google.com/maps?q={lat},{lon}"]

    lines += ["", "─" * 50,
              "Not: Yaklaşık OSINT verisi; hassas konum/adres içermez."]
    return "\n".join(lines) + "\n"


def ssl_analyze(host: str, port: int = 443, timeout: int = 10) -> str:
    """SSL/TLS sertifika bilgisi."""
    host = host.strip()
    if not host:
        return "[✘] Host giriniz.\n"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                ver    = ssock.version()
    except ssl.SSLCertVerificationError as e:
        return f"[⚠] SSL Doğrulama Hatası: {e}\n(Sertifika geçersiz veya self-signed olabilir)\n"
    except Exception as e:
        return f"[✘] SSL bağlantısı kurulamadı: {e}\n"

    lines = [f"─── SSL/TLS Analizi: {host}:{port} ─────────────"]

    # Subject
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    lines.append(f"  CN (Subject)  : {subject.get('commonName','?')}")
    lines.append(f"  Organizasyon  : {subject.get('organizationName','?')}")
    lines.append(f"  Ülke          : {subject.get('countryName','?')}")
    lines += ["", "─── Yayıncı (Issuer) ──────────────────────────"]
    lines.append(f"  CA            : {issuer.get('commonName','?')}")
    lines.append(f"  Org           : {issuer.get('organizationName','?')}")

    # Validity
    nb = cert.get("notBefore","?")
    na = cert.get("notAfter","?")
    lines += ["", "─── Geçerlilik ─────────────────────────────────"]
    lines.append(f"  Başlangıç     : {nb}")
    lines.append(f"  Bitiş         : {na}")
    try:
        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
        remaining = (exp - datetime.datetime.utcnow()).days
        warn = " ⚠ YAKINDA SONA ERIYOR!" if remaining < 30 else (" ✘ SÜRESİ DOLMUŞ!" if remaining < 0 else "")
        lines.append(f"  Kalan gün     : {remaining}{warn}")
    except Exception:
        pass

    # SANs
    sans = cert.get("subjectAltName", [])
    if sans:
        lines += ["", "─── Subject Alt Names ──────────────────────────"]
        for _, v in sans[:20]:
            lines.append(f"  {v}")
        if len(sans) > 20:
            lines.append(f"  ... ve {len(sans)-20} tane daha")

    # Cipher
    lines += ["", "─── Bağlantı ───────────────────────────────────"]
    lines.append(f"  TLS Sürümü    : {ver}")
    if cipher:
        lines.append(f"  Cipher        : {cipher[0]}")
        lines.append(f"  Bit           : {cipher[2]}")

    return "\n".join(lines) + "\n"


def port_scan(host: str, max_port: int = 1024,
              num_threads: int = 100, timeout: float = 1.0) -> str:
    """Paralel port tarayıcı."""
    host = host.strip()
    if not host:
        return "[✘] Host giriniz.\n"

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return "[✘] Host çözümlenemedi.\n"

    COMMON_SERVICES = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
        143:"IMAP", 443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
        1723:"PPTP", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL",
        5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
        8888:"Jupyter", 9200:"Elasticsearch", 27017:"MongoDB",
    }

    open_ports = []
    scanned    = [0]
    lock       = threading.Lock()

    def check(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        svc = COMMON_SERVICES.get(port, "?")
                        open_ports.append((port, svc))
        except Exception:
            pass
        with lock:
            scanned[0] += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as ex:
        ex.map(check, range(1, max_port + 1))

    open_ports.sort()
    lines = [
        f"─── Port Tarama: {host} ({ip}) ─────────────",
        f"  Taranan      : 1–{max_port}",
        f"  Açık port    : {len(open_ports)}",
        "",
    ]
    if open_ports:
        lines.append(f"  {'PORT':<8} {'SERVİS'}")
        lines.append(f"  {'─'*6}   {'─'*20}")
        for port, svc in open_ports:
            lines.append(f"  {port:<8} {svc}")
    else:
        lines.append("  Açık port bulunamadı.")

    lines += ["", "Not: Kendi sisteminiz veya yetkili olduğunuz sistemler için kullanın."]
    return "\n".join(lines) + "\n"


def subdomain_scan(domain: str, use_crtsh: bool = True,
                   use_bruteforce: bool = True,
                   num_threads: int = 50, timeout: int = 3,
                   proxy: str = "") -> str:
    """crt.sh + brute-force subdomain tarayıcı."""
    domain = domain.strip().lower()
    if not domain:
        return "[✘] Domain giriniz.\n"

    found: set = set()

    # --- crt.sh ---
    if use_crtsh:
        try:
            sess = make_session(proxy)
            r = sess.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15,
            )
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.add(sub)
        except Exception as e:
            pass  # crt.sh başarısız olsa bile brute-force devam eder

    # --- brute-force ---
    if use_bruteforce:
        lock = threading.Lock()

        def probe(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(timeout)
                ip = socket.gethostbyname(fqdn)
                with lock:
                    found.add(fqdn)
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as ex:
            ex.map(probe, SUBDOMAIN_WORDLIST)

    results = sorted(found)
    lines   = [
        f"─── Subdomain Tarama: {domain} ──────────────",
        f"  Yöntem       : {'crt.sh ' if use_crtsh else ''}{'brute-force' if use_bruteforce else ''}",
        f"  Bulunan      : {len(results)}",
        "",
    ]
    if results:
        for s in results:
            try:
                ip = socket.gethostbyname(s)
                lines.append(f"  [✔] {s:<45} {ip}")
            except Exception:
                lines.append(f"  [✔] {s}")
    else:
        lines.append("  Subdomain bulunamadı.")

    lines += ["", "Not: Yalnızca yetkili olduğunuz domainlerde kullanın."]
    return "\n".join(lines) + "\n"


def smtp_email_verify(email: str, timeout: int = 10) -> str:
    """SMTP VRFY/RCPT komutu ile e-posta varlık kontrolü."""
    email = email.strip()
    if not email or "@" not in email:
        return "[✘] Geçerli e-posta giriniz.\n"

    domain = email.split("@")[-1]
    lines  = [f"─── E-posta Doğrulama: {email} ──────────────"]

    # MX kaydı bul
    mx_host = None
    if DNS_OK:
        try:
            mx_rec = dns.resolver.resolve(domain, "MX")
            mx_host = str(sorted(mx_rec, key=lambda r: r.preference)[0].exchange).rstrip(".")
            lines.append(f"  MX Host      : {mx_host}")
        except Exception as e:
            lines.append(f"  MX           : Bulunamadı ({e})")
    else:
        lines.append("  [ℹ] dnspython yok — MX sorgusu atlandı.")

    if not mx_host:
        lines.append("[✘] MX kaydı olmadan SMTP doğrulaması yapılamaz.")
        return "\n".join(lines) + "\n"

    # SMTP bağlantı
    try:
        with smtplib.SMTP(timeout=timeout) as smtp:
            smtp.connect(mx_host, 25)
            code, banner = smtp.ehlo_or_helo_if_needed(), b""
            smtp.mail("probe@bloodline-osint.local")
            code, msg = smtp.rcpt(email)
            if code == 250:
                lines.append("  Durum        : [✔] E-posta adresi MEVCUT görünüyor")
            elif code == 550:
                lines.append("  Durum        : [✘] E-posta adresi MEVCUT DEĞİL (550)")
            else:
                lines.append(f"  Durum        : [?] Belirsiz yanıt: {code} {msg.decode()}")
    except smtplib.SMTPConnectError as e:
        lines.append(f"  SMTP Bağlantı : [✘] {e}")
    except smtplib.SMTPServerDisconnected:
        lines.append("  SMTP          : [✘] Sunucu bağlantıyı kesti (greylisting?)")
    except Exception as e:
        lines.append(f"  SMTP          : [✘] {e}")

    lines += ["", "Not: Bazı mail sunucuları her adresi kabul eder (catch-all)."]
    return "\n".join(lines) + "\n"


def hibp_breach_check(email: str, api_key: str = "", timeout: int = 10,
                       proxy: str = "") -> str:
    """HaveIBeenPwned API v3 ile e-posta sızıntı kontrolü."""
    email = email.strip()
    if not email or "@" not in email:
        return "[✘] Geçerli e-posta giriniz.\n"

    lines = [f"─── Breach Kontrolü: {email} ─────────────────"]

    if not api_key:
        lines += [
            "  [⚠] HIBP API anahtarı girilmemiş.",
            "  Settings menüsünden API anahtarınızı ekleyin.",
            "  HIBP API key: https://haveibeenpwned.com/API/Key",
        ]
        return "\n".join(lines) + "\n"

    try:
        sess = make_session(proxy)
        r = sess.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers={"hibp-api-key": api_key, "User-Agent": "BloodlineOSINT/2.0"},
            params={"truncateResponse": "false"},
            timeout=timeout,
        )
        if r.status_code == 404:
            lines.append("  [✔] Bu e-posta herhangi bir bilinen sızıntıda YOK.")
        elif r.status_code == 200:
            breaches = r.json()
            lines.append(f"  [!] {len(breaches)} SIZMA BULUNDU!\n")
            for b in breaches:
                lines.append(f"  ■ {b.get('Name','?')}  ({b.get('BreachDate','?')})")
                lines.append(f"    Alan      : {b.get('Domain','?')}")
                dc = b.get("DataClasses", [])
                if dc:
                    lines.append(f"    Çalınan   : {', '.join(dc[:6])}")
                lines.append(f"    Kayıt     : {b.get('PwnCount', 0):,}")
                lines.append("")
        elif r.status_code == 401:
            lines.append("  [✘] API anahtarı geçersiz (401).")
        elif r.status_code == 429:
            lines.append("  [✘] Rate limit aşıldı. Biraz bekleyin (429).")
        else:
            lines.append(f"  [✘] API yanıtı: {r.status_code}")
    except Exception as e:
        lines.append(f"  [✘] HIBP sorgusu başarısız: {e}")

    lines += ["", "Not: E-posta bilgisi HIBP sunucusuna gönderilir."]
    return "\n".join(lines) + "\n"


def shodan_lookup(target: str, api_key: str = "", timeout: int = 10,
                   proxy: str = "") -> str:
    """Shodan API ile host bilgisi."""
    target = target.strip()
    if not target:
        return "[✘] IP veya domain giriniz.\n"

    lines = [f"─── Shodan: {target} ────────────────────────────"]

    if not api_key:
        lines += [
            "  [⚠] Shodan API anahtarı girilmemiş.",
            "  Settings menüsünden API anahtarınızı ekleyin.",
            "  Shodan API: https://account.shodan.io",
        ]
        return "\n".join(lines) + "\n"

    try:
        ip = target
        if any(ch.isalpha() for ch in target):
            ip = socket.gethostbyname(target)

        sess = make_session(proxy)
        r = sess.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=timeout,
        )
        if r.status_code == 401:
            return lines[0] + "\n  [✘] API anahtarı geçersiz.\n"
        if r.status_code == 404:
            return lines[0] + "\n  [ℹ] Bu IP Shodan'da kayıtlı değil.\n"
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        lines.append(f"  [✘] Shodan sorgusu başarısız: {e}")
        return "\n".join(lines) + "\n"

    lines.append(f"  IP           : {data.get('ip_str','?')}")
    lines.append(f"  Org          : {data.get('org','?')}")
    lines.append(f"  ISP          : {data.get('isp','?')}")
    lines.append(f"  ASN          : {data.get('asn','?')}")
    lines.append(f"  OS           : {data.get('os','?')}")
    cc = data.get("country_code","?")
    ci = data.get("city","?")
    lines.append(f"  Konum        : {ci}, {cc}")

    vulns = data.get("vulns", [])
    if vulns:
        lines += ["", f"  [!] CVE ({len(vulns)}):"]
        for v in list(vulns)[:10]:
            lines.append(f"      {v}")

    ports_data = data.get("data", [])
    if ports_data:
        lines += ["", f"  Açık servisler ({len(ports_data)}):"]
        for svc in ports_data[:15]:
            port    = svc.get("port","?")
            product = svc.get("product","")
            version = svc.get("version","")
            banner  = (svc.get("data","")[:80]).replace("\n"," ")
            lines.append(f"    [{port}] {product} {version}")
            if banner:
                lines.append(f"           {banner}")

    lines += ["", "Not: Shodan verileri kamuya açık tarama sonuçlarıdır."]
    return "\n".join(lines) + "\n"


def dns_lookup(rr: str, domain: str, timeout: int = 10) -> str:
    rr, domain = rr.upper().strip(), domain.strip()
    if not domain:
        return "[✘] Domain giriniz.\n"
    if not DNS_OK:
        if rr == "A":
            try:
                return f"[✔] {domain}  A  →  {socket.gethostbyname(domain)}\n"
            except Exception:
                return "[✘] DNS A çözümlenemedi.\n"
        return "[✘] dnspython kurulu değil.\npip install dnspython\n"
    try:
        res = dns.resolver.Resolver()
        res.timeout = timeout
        answers = res.resolve(domain, rr)
        out = [f"[✔] {domain}  {rr}:"]
        for a in answers:
            out.append(f"  {a}")
        return "\n".join(out) + "\n"
    except dns.resolver.NXDOMAIN:
        return f"[✘] Domain bulunamadı: {domain}\n"
    except dns.resolver.NoAnswer:
        return f"[ℹ] {domain} için {rr} kaydı yok.\n"
    except Exception as e:
        return f"[✘] DNS hatası ({rr} {domain}): {e}\n"


# ══════════════════════════════════════════════════════════════════════
#  OPERATOR SEARCH
# ══════════════════════════════════════════════════════════════════════

def op_search(operators: list, query: str, limit: int = 20) -> list:
    q = query.strip().lower()
    if not q or not operators:
        return []
    hits  = [op for op in operators if q in str(op.get("name","")).lower()]
    names = [str(op.get("name","")) for op in operators]
    for nm in difflib.get_close_matches(query, names, n=limit, cutoff=0.50):
        for op in operators:
            if op.get("name") == nm and op not in hits:
                hits.append(op)
    return hits[:limit]


def op_search_plmn(operators: list, plmn: str, limit: int = 20) -> list:
    return [op for op in operators if plmn.strip() in (op.get("mcc_mnc") or [])][:limit]


def op_search_country(operators: list, iso: str, limit: int = 20) -> list:
    iso = iso.strip().upper()
    return [op for op in operators
            if iso in [c.upper() for c in (op.get("countries") or [])]][:limit]


def op_format(operators: list, hits: list, title: str = "Sonuçlar") -> str:
    if not operators:
        return "[✘] operators.json yok. Settings → DB Güncelle çalıştırın.\n"
    if not hits:
        return "[ℹ] Sonuç bulunamadı.\n"
    lines = [f"─── {title} ─────────────────────────────────────",
             f"Toplam: {len(hits)}", ""]
    for i, op in enumerate(hits, 1):
        lines.append(f"  [{i:02d}] {op.get('name','?')}")
        cc = [str(x) for x in (op.get("countries") or []) if x]
        if cc: lines.append(f"       Ülke    : {', '.join(cc)}")
        t = op.get("type")
        if t: lines.append(f"       Tip     : {t}")
        w = op.get("website")
        if w: lines.append(f"       Web     : {w}")
        mm = op.get("mcc_mnc") or []
        if mm:
            lines.append(f"       MCC-MNC : {', '.join(mm[:10])}{'...' if len(mm)>10 else ''}")
        lines.append("")
    lines.append("Not: OP Analyze kişisel veri üretmez.")
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════════════════════

def generate_html_report(sections: list[tuple[str, str]], target: str = "") -> str:
    """sections: [(title, content), ...]"""
    now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows  = ""
    for title, content in sections:
        safe = content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        rows += f"""
        <div class="section">
          <h2>{title}</h2>
          <pre>{safe}</pre>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Bloodline OSINT Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0b0b0b; color: #d0d0d0; font-family: 'Consolas', monospace; padding: 30px; }}
  h1   {{ color: #ff2a2a; font-size: 1.6em; border-bottom: 1px solid #222; padding-bottom: 10px; margin-bottom: 6px; }}
  .meta {{ color: #555; font-size: .85em; margin-bottom: 30px; }}
  .section {{ background: #111; border: 1px solid #222; border-radius: 4px;
              padding: 18px; margin-bottom: 20px; }}
  .section h2 {{ color: #00ff88; font-size: 1em; margin-bottom: 12px;
                 border-bottom: 1px solid #1a1a1a; padding-bottom: 6px; }}
  pre {{ color: #c0c0c0; font-size: .88em; white-space: pre-wrap; word-break: break-all; }}
  .footer {{ color: #333; font-size: .8em; text-align: center; margin-top: 30px; }}
</style>
</head>
<body>
  <h1>BLOODLINE OSINT REPORT</h1>
  <p class="meta">Hedef: {target}  &nbsp;|&nbsp;  Tarih: {now}  &nbsp;|&nbsp;  Bloodline v2.0</p>
  {rows}
  <div class="footer">Yasal OSINT araştırmaları için üretilmiştir. Yasadışı kullanım yasaktır.</div>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════

class BloodlineApp(tk.Tk):

    # ── init ─────────────────────────────────────────────────────────
    def __init__(self):
        super().__init__()

        self.configs    = load_config()
        self.ui_color   = self.configs["ui_color"]
        self.wave_color = self.configs["wave_color"]
        self.timeout    = int(self.configs.get("timeout", 10))
        self.proxy      = self.configs.get("proxy", "")
        self.operators  = load_operators()
        self._cache     = load_cache()
        self.favorites  = load_favorites()
        self.wave: WaveCanvas | None = None

        self._cmd_history: list[str] = []
        self._cmd_idx: int = -1
        self._report_sections: list[tuple[str, str]] = []
        self._report_target: str = ""

        self.title("Bloodline OSINT Tool — Edition v2.0")
        self.geometry("1280x760")
        self.configure(bg=APP_BG)
        self.resizable(True, True)
        self.minsize(900, 600)

        self._build_layout()
        self._build_sidebar()
        self._build_topbar()
        self._build_statusbar()

        self.home_panel()

    # ── layout ───────────────────────────────────────────────────────
    def _build_layout(self):
        self.sidebar = tk.Frame(self, width=235, bg=SIDE_BG)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.content = tk.Frame(self, bg=APP_BG)
        self.content.pack(side="left", fill="both", expand=True)

        self.topbar = tk.Frame(self.content, bg=TOP_BG, height=50)
        self.topbar.pack(side="top", fill="x")
        self.topbar.pack_propagate(False)

        self.body = tk.Frame(self.content, bg=APP_BG)
        self.body.pack(side="top", fill="both", expand=True)

        self.statusbar = tk.Frame(self.content, bg="#080808", height=24)
        self.statusbar.pack(side="bottom", fill="x")
        self.statusbar.pack_propagate(False)

    def _build_sidebar(self):
        self.logo_label = tk.Label(
            self.sidebar, text="BLOODLINE",
            fg=self.ui_color, bg=SIDE_BG,
            font=("Consolas", 19, "bold"),
        )
        self.logo_label.pack(pady=(18, 1))
        tk.Label(self.sidebar, text="EDITION  v2.0",
                 fg="#333", bg=SIDE_BG, font=("Consolas", 8)).pack(pady=(0, 10))

        self._div()

        nav_groups = [
            ("─ TEMEL ─", [
                ("🏠  Ana Ekran",       self.home_panel),
                ("🌐  Web / IP",        self.web_panel),
                ("👤  UserFind",        self.userfind_panel),
                ("✉️  Mail Analyze",    self.mail_panel),
                ("📞  Phone Analyze",   self.phone_panel),
                ("📡  OP Analyze",      self.op_panel),
            ]),
            ("─ AĞLAR ─", [
                ("🔍  WHOIS",           self.whois_panel),
                ("📋  DNS Lookup",      self.dns_panel),
                ("🔐  SSL / TLS",       self.ssl_panel),
                ("🔌  Port Tarayıcı",   self.port_panel),
                ("🌿  Subdomain",       self.subdomain_panel),
            ]),
            ("─ GELİŞMİŞ ─", [
                ("📧  E-posta Doğrula", self.email_verify_panel),
                ("💥  Breach Kontrol",  self.breach_panel),
                ("👁️  Shodan",          self.shodan_panel),
            ]),
            ("─ ARAÇLAR ─", [
                ("⌨️  Komut Paneli",    self.command_panel),
                ("⭐  Favoriler",       self.favorites_panel),
                ("📜  Sorgu Geçmişi",   self.history_panel),
                ("📄  HTML Rapor",      self.report_panel),
                ("⚙️  Settings",        self.settings_panel),
            ]),
        ]

        for group_label, items in nav_groups:
            tk.Label(self.sidebar, text=group_label,
                     fg="#2a2a2a", bg=SIDE_BG,
                     font=("Consolas", 8, "bold")).pack(anchor="w", padx=16, pady=(8, 2))
            for label, cmd in items:
                self._make_btn(label, cmd)

        tk.Label(self.sidebar, text="by Acsida",
                 fg="#222", bg=SIDE_BG, font=("Consolas", 7)).pack(side="bottom", pady=8)

    def _build_topbar(self):
        tk.Label(self.topbar, text="›",
                 fg=self.ui_color, bg=TOP_BG,
                 font=("Consolas", 16, "bold")).pack(side="left", padx=(12, 4))

        self.quick_entry = tk.Entry(
            self.topbar, font=("Consolas", 12),
            bg=INPUT_BG, fg="white",
            insertbackground=self.ui_color,
            width=58, relief="flat", bd=0,
        )
        self.quick_entry.pack(side="left", padx=(0, 6), ipady=5, pady=10)
        self.quick_entry.bind("<Return>", lambda _: self.run_quick_command())

        tk.Button(
            self.topbar, text="RUN",
            bg=self.ui_color, fg="black",
            font=("Consolas", 10, "bold"), relief="flat", padx=12,
            command=self.run_quick_command,
        ).pack(side="left", pady=10)

        tk.Label(self.topbar,
                 text="  ip 8.8.8.8  |  user x  |  port 80  |  sub example.com  |  breach x@y.com",
                 fg="#2a2a2a", bg=TOP_BG, font=("Consolas", 9),
                 ).pack(side="left", padx=8)

    def _build_statusbar(self):
        self._status_var = tk.StringVar()
        tk.Label(self.statusbar, textvariable=self._status_var,
                 fg="#444", bg="#080808", font=("Consolas", 9), anchor="w",
                 ).pack(side="left", padx=10, fill="x", expand=True)
        self._clock_var = tk.StringVar()
        tk.Label(self.statusbar, textvariable=self._clock_var,
                 fg="#2a2a2a", bg="#080808", font=("Consolas", 9),
                 ).pack(side="right", padx=10)
        self._tick_clock()
        self._update_status("Hazır")

    def _tick_clock(self):
        self._clock_var.set(datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    # ── sidebar helpers ───────────────────────────────────────────────
    def _div(self):
        tk.Frame(self.sidebar, bg="#181818", height=1).pack(fill="x", padx=16, pady=5)

    def _make_btn(self, text: str, cmd):
        b = tk.Button(
            self.sidebar, text=text,
            fg="#666", bg=SIDE_BG,
            activebackground=self.ui_color, activeforeground="black",
            font=("Consolas", 10), relief="flat", anchor="w", padx=14,
            command=lambda t=text, c=cmd: self._nav(t, c),
        )
        b.pack(fill="x", padx=8, pady=1)

    def _nav(self, label: str, cmd):
        for w in self.sidebar.winfo_children():
            if isinstance(w, tk.Button):
                w.configure(bg=SIDE_BG, fg="#666")
        for w in self.sidebar.winfo_children():
            if isinstance(w, tk.Button) and w.cget("text") == label:
                w.configure(bg=self.ui_color, fg="black")
                break
        cmd()
        self._update_status(f"Açıldı: {label.strip()}")

    # ── body helpers ──────────────────────────────────────────────────
    def clear_body(self):
        if self.wave:
            self.wave.stop()
            self.wave = None
        for w in self.body.winfo_children():
            w.destroy()

    def _update_status(self, msg: str):
        db_ok = os.path.exists(OPERATORS_FILE)
        self._status_var.set(
            f"  {msg}   │   DB: {'✔' if db_ok else '✘'} {len(self.operators)} op"
            f"   │   cache: {len(self._cache)} keys"
            f"   │   proxy: {'ON' if self.proxy else 'off'}"
            f"   │   t/o: {self.timeout}s"
        )

    def _title(self, parent, title: str, sub: str = ""):
        h = tk.Frame(parent, bg=APP_BG)
        h.pack(fill="x", padx=26, pady=(14, 4))
        tk.Label(h, text=title, fg=self.ui_color, bg=APP_BG,
                 font=("Consolas", 18, "bold")).pack(side="left")
        if sub:
            tk.Label(h, text=f"  —  {sub}", fg="#444", bg=APP_BG,
                     font=("Consolas", 9)).pack(side="left", pady=(5, 0))

    def _input_row(self, parent, label: str, ph: str, btn_txt: str, btn_cmd,
                   wide: bool = False) -> tk.Entry:
        wrap = tk.Frame(parent, bg=APP_BG)
        wrap.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(wrap, text=label, fg="#555", bg=APP_BG,
                 font=("Consolas", 9, "bold")).pack(anchor="w")
        row = tk.Frame(wrap, bg=APP_BG)
        row.pack(fill="x", pady=(3, 0))
        ent = tk.Entry(row, font=("Consolas", 13), bg=INPUT_BG, fg="white",
                       insertbackground=self.ui_color, relief="flat", bd=0)
        ent.pack(side="left", fill="x", expand=True, ipady=6)
        ent.insert(0, ph)
        ent.bind("<FocusIn>",  lambda e: ent.get() == ph and ent.delete(0, "end"))
        ent.bind("<FocusOut>", lambda e: not ent.get() and ent.insert(0, ph))
        ent.bind("<Return>", lambda _: btn_cmd())
        tk.Button(row, text=btn_txt, bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=12,
                  command=btn_cmd).pack(side="left", padx=(6, 0))
        return ent

    def _output_box(self, parent, label: str = "Output",
                    color: str = GREEN_FG) -> tk.Text:
        wrap = tk.Frame(parent, bg=APP_BG)
        wrap.pack(fill="both", expand=True, padx=26, pady=(4, 0))
        tk.Label(wrap, text=label, fg="#444", bg=APP_BG,
                 font=("Consolas", 9, "bold")).pack(anchor="w")
        box = tk.Frame(wrap, bg=BORDER, bd=1, relief="solid")
        box.pack(fill="both", expand=True, pady=(3, 0))
        txt = tk.Text(box, bg=OUT_BG, fg=color,
                      font=("Consolas", 11), wrap="word",
                      relief="flat", bd=0, padx=10, pady=8, cursor="arrow")
        sb = tk.Scrollbar(box, command=txt.yview, bg=APP_BG, troughcolor=APP_BG)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        # color tags
        txt.tag_configure("ok",   foreground=GREEN_FG)
        txt.tag_configure("warn", foreground=WARN_FG)
        txt.tag_configure("err",  foreground=ERR_FG)
        txt.tag_configure("info", foreground=BLUE_FG)
        txt.config(state="disabled")
        return txt

    def _action_row(self, parent, out: tk.Text, report_title: str = ""):
        row = tk.Frame(parent, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(6, 12))

        def do_copy():
            self.clipboard_clear()
            self.clipboard_append(out.get("1.0", "end").strip())
            self._update_status("Panoya kopyalandı")

        def do_export():
            content = out.get("1.0", "end").strip()
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text","*.txt"),("HTML","*.html"),("JSON","*.json")])
            if not path:
                return
            try:
                if path.endswith(".html"):
                    html = generate_html_report(
                        [(report_title or "Sonuç", content)],
                        target=report_title)
                    open(path, "w", encoding="utf-8").write(html)
                elif path.endswith(".json"):
                    json.dump({"result": content,
                               "exported_at": str(datetime.datetime.now())},
                              open(path,"w",encoding="utf-8"), indent=2)
                else:
                    open(path, "w", encoding="utf-8").write(content)
                self._update_status(f"Kaydedildi: {os.path.basename(path)}")
            except Exception as e:
                self._update_status(f"Hata: {e}")

        def do_add_report():
            title  = report_title or "Bölüm"
            content = out.get("1.0", "end").strip()
            self._report_sections.append((title, content))
            self._update_status(f"Rapora eklendi: {title} ({len(self._report_sections)} bölüm)")

        for lbl, fn in [("⎘ Kopyala", do_copy), ("↓ Dışa Aktar", do_export),
                         ("+ Rapora Ekle", do_add_report)]:
            tk.Button(row, text=lbl, bg="#141414", fg="#555",
                      font=("Consolas", 9), relief="flat", padx=8,
                      activebackground="#1e1e1e", activeforeground="#aaa",
                      command=fn).pack(side="left", padx=(0, 5))

        tk.Label(row, text="Hassas adres/konum verisi üretilmez.",
                 fg="#2a2a2a", bg=APP_BG, font=("Consolas", 8)).pack(side="left", padx=6)

    def _fav_btn(self, parent, entry_widget):
        def add_fav():
            val = entry_widget.get().strip()
            if val and val not in self.favorites:
                self.favorites.append(val)
                save_favorites(self.favorites)
                self._update_status(f"Favorilere eklendi: {val}")
        tk.Button(parent, text="☆ Favori", bg="#141414", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=add_fav).pack(side="left", padx=(6, 0))

    # ── thread runner ────────────────────────────────────────────────
    def run_job(self, worker_fn, done_fn, busy: str = "Çalışıyor..."):
        self._update_status(busy)

        def _t():
            t0 = time.time()
            try:
                result = worker_fn()
            except Exception as e:
                result = f"[✘] Beklenmedik hata: {e}\n"
            elapsed = time.time() - t0
            self.after(0, lambda: done_fn(result, elapsed))

        threading.Thread(target=_t, daemon=True).start()

    # ── output helpers ───────────────────────────────────────────────
    def out_set(self, w: tk.Text, content: str):
        w.config(state="normal")
        w.delete("1.0", "end")
        # basic coloring
        for line in content.splitlines(keepends=True):
            if any(x in line for x in ["[✔]","[✘] "]) and "[✘]" not in line[:5]:
                w.insert("end", line, "ok")
            elif "[✘]" in line or "HATA" in line.upper():
                w.insert("end", line, "err")
            elif "[⚠]" in line or "[!]" in line or "⚠" in line:
                w.insert("end", line, "warn")
            elif "[ℹ]" in line:
                w.insert("end", line, "info")
            else:
                w.insert("end", line)
        w.config(state="disabled")

    # ── cache helper ─────────────────────────────────────────────────
    def _cache_lookup(self, key: str) -> str | None:
        if not self.configs.get("cache_enabled", True):
            return None
        return cache_get(self._cache, key, int(self.configs.get("cache_ttl", 3600)))

    def _cache_store(self, key: str, val: str):
        if self.configs.get("cache_enabled", True):
            cache_set(self._cache, key, val)
            save_cache(self._cache)

    # ── quick command ────────────────────────────────────────────────
    def run_quick_command(self):
        cmd = self.quick_entry.get().strip()
        if not cmd:
            return
        self.command_panel(prefill=cmd, auto_run=True)

    # ══════════════════════════════════════════════════════════════════
    #  COMMAND ENGINE
    # ══════════════════════════════════════════════════════════════════

    def _help_text(self) -> str:
        return (
            "╔══════════════════════════════════════════════════════╗\n"
            "║  BLOODLINE  —  Komut Referansı  (v2.0)               ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n"
            "Temel\n"
            "  komutlar / help                   bu yardım\n"
            "  clear                             ekranı temizle\n"
            "  log                               sorgu geçmişini göster\n"
            "  cache clear                       önbelleği temizle\n\n"
            "Ağ / IP\n"
            "  ip   <ip|domain>                  GeoIP + ISP + harita\n"
            "  web  <ip|domain>                  ip ile aynı\n"
            "  whois <domain>                    raw WHOIS\n"
            "  dns  <a|mx|ns|txt|cname> <domain> DNS kaydı\n"
            "  ssl  <host> [port]                SSL/TLS sertifika\n"
            "  port <host> [max_port]            port tarama\n"
            "  sub  <domain>                     subdomain keşfi\n\n"
            "Mail\n"
            "  mx     <email|domain>             MX kaydı\n"
            "  verify <email>                    SMTP doğrulama\n"
            "  breach <email>                    HIBP sızıntı kontrolü\n\n"
            "Telefon\n"
            "  phone <+numara>                   ülke / operatör\n\n"
            "Kullanıcı\n"
            "  user <username>                   platform taraması\n"
            "  user <username> [kategori]        örn: user x oyun\n\n"
            "Operatör DB\n"
            "  op   <ad>                         isme göre ara\n"
            "  op   plmn <mcc-mnc>               örn: op plmn 286-01\n"
            "  op   country <ISO>                ülke kodu\n\n"
            "Shodan\n"
            "  shodan <ip|domain>                Shodan host bilgisi\n\n"
            "Favoriler\n"
            "  fav list                          favorileri listele\n"
            "  fav add <hedef>                   favoriye ekle\n"
            "  fav del <hedef>                   favoriden sil\n\n"
            f"Dosyalar:\n"
            f"  operators.json : {OPERATORS_FILE}\n"
            f"  log            : {LOG_FILE}\n"
            f"  cache          : {CACHE_FILE}\n"
            f"  favorites      : {FAVORITES_FILE}\n"
        )

    def run_command(self, cmd: str) -> str:
        raw   = cmd.strip()
        if not raw:
            return self._help_text()

        parts = raw.split()
        head  = parts[0].lower()

        if head in ("komutlar", "help", "yardım", "?"):
            return self._help_text()

        if head == "clear":
            return ""

        if head == "log":
            if not os.path.exists(LOG_FILE):
                return "[ℹ] Henüz log yok.\n"
            return open(LOG_FILE, encoding="utf-8").read() or "[ℹ] Log boş.\n"

        if head == "cache":
            if len(parts) > 1 and parts[1] == "clear":
                self._cache.clear()
                save_cache(self._cache)
                return "[✔] Önbellek temizlendi.\n"
            return f"[ℹ] Önbellekte {len(self._cache)} kayıt var.\n"

        # ── Fav ──
        if head == "fav":
            sub = parts[1].lower() if len(parts) > 1 else ""
            if sub == "list":
                if not self.favorites:
                    return "[ℹ] Favori yok.\n"
                return "Favoriler:\n" + "\n".join(f"  {f}" for f in self.favorites) + "\n"
            if sub == "add" and len(parts) > 2:
                t = raw[len("fav add"):].strip()
                if t not in self.favorites:
                    self.favorites.append(t)
                    save_favorites(self.favorites)
                return f"[✔] Eklendi: {t}\n"
            if sub == "del" and len(parts) > 2:
                t = raw[len("fav del"):].strip()
                if t in self.favorites:
                    self.favorites.remove(t)
                    save_favorites(self.favorites)
                    return f"[✔] Silindi: {t}\n"
                return f"[ℹ] Bulunamadı: {t}\n"
            return "[✘] fav list / fav add <hedef> / fav del <hedef>\n"

        # ── IP / Web ──
        if head in ("ip", "web"):
            arg = raw[len(head):].strip()
            if not arg:
                return f"[✘] {head} için hedef gir.\n"
            cached = self._cache_lookup(f"ip:{arg}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            result = ip_geo_lookup(arg, self.timeout, self.proxy)
            self._cache_store(f"ip:{arg}", result)
            append_log(f"{head} {arg}", self.configs.get("log_enabled", True))
            return result

        # ── WHOIS ──
        if head == "whois":
            arg = raw[len("whois"):].strip()
            if not arg:
                return "[✘] Domain gir.\n"
            cached = self._cache_lookup(f"whois:{arg}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            result = simple_whois(arg, self.timeout)
            self._cache_store(f"whois:{arg}", result)
            append_log(f"whois {arg}", self.configs.get("log_enabled", True))
            return result

        # ── DNS ──
        if head == "dns":
            if len(parts) < 3:
                return "[✘] dns <a|mx|ns|txt|cname> <domain>\n"
            return dns_lookup(parts[1], parts[2], self.timeout)

        # ── SSL ──
        if head == "ssl":
            if len(parts) < 2:
                return "[✘] ssl <host> [port]\n"
            port = int(parts[2]) if len(parts) > 2 else 443
            return ssl_analyze(parts[1], port, self.timeout)

        # ── Port ──
        if head == "port":
            if len(parts) < 2:
                return "[✘] port <host> [max_port]\n"
            maxp = min(int(parts[2]), 65535) if len(parts) > 2 else self.configs.get("max_ports", 1024)
            append_log(f"port {parts[1]}", self.configs.get("log_enabled", True))
            return port_scan(parts[1], maxp,
                             self.configs.get("port_threads", 100), float(self.timeout) * 0.1)

        # ── Sub ──
        if head == "sub":
            arg = raw[len("sub"):].strip()
            if not arg:
                return "[✘] sub <domain>\n"
            append_log(f"sub {arg}", self.configs.get("log_enabled", True))
            return subdomain_scan(arg, num_threads=self.configs.get("sub_threads", 50),
                                  timeout=self.timeout, proxy=self.proxy)

        # ── MX ──
        if head == "mx":
            arg = raw[len("mx"):].strip()
            if not arg:
                return "[✘] mx <email|domain>\n"
            domain = arg.split("@")[-1].strip()
            if not DNS_OK:
                return "[✘] dnspython kurulu değil.\n"
            try:
                mx = dns.resolver.resolve(domain, "MX")
                return f"Domain : {domain}\nMX Host: {mx[0].exchange}\n"
            except Exception as e:
                return f"[✘] MX sorgusu başarısız: {e}\n"

        # ── Verify ──
        if head == "verify":
            arg = raw[len("verify"):].strip()
            if not arg:
                return "[✘] verify <email>\n"
            return smtp_email_verify(arg, self.timeout)

        # ── Breach ──
        if head == "breach":
            arg = raw[len("breach"):].strip()
            if not arg:
                return "[✘] breach <email>\n"
            return hibp_breach_check(arg, self.configs.get("hibp_key", ""),
                                      self.timeout, self.proxy)

        # ── Phone ──
        if head == "phone":
            arg = raw[len("phone"):].strip()
            if not arg:
                return "[✘] phone <+numara>\n"
            if not PHONE_OK:
                return "[✘] phonenumbers kurulu değil.\npip install phonenumbers\n"
            try:
                num = phonenumbers.parse(arg, None)
            except Exception:
                return "[✘] Numara parse edilemedi.\n"
            return "\n".join([
                f"Ülke        : {geocoder.description_for_number(num,'tr')}",
                f"Operatör    : {carrier.name_for_number(num,'tr') or 'Bilinmiyor'}",
                f"Zaman Dil.  : {list(pn_tz.time_zones_for_number(num))}",
                f"Tip         : {number_type(num)}",
                f"Geçerli     : {phonenumbers.is_valid_number(num)}",
                f"Ülke Kodu   : {phonenumbers.region_code_for_number(num)}",
                "",
                "Not: Konum/adres/takip yapılmaz.",
            ]) + "\n"

        # ── User ──
        if head == "user":
            username = raw[len("user"):].strip()
            if not username:
                return "[✘] user <username>\n"
            # kategori filtresi
            cat_filter = None
            for cat in PLATFORM_CATS:
                if cat.lower() in username.lower().split():
                    cat_filter = cat
                    username   = username.lower().replace(cat.lower(),"").strip()
                    break

            platforms = PLATFORMS
            if cat_filter:
                cat_keys = PLATFORM_CATS.get(cat_filter, [])
                platforms = {k: v for k, v in PLATFORMS.items() if k in cat_keys}

            append_log(f"user {username}", self.configs.get("log_enabled", True))

            found = []
            results = {}

            def check(item):
                name, url_tpl = item
                try:
                    r = requests.get(url_tpl.format(username), timeout=self.timeout)
                    ok = r.status_code == 200
                except Exception:
                    ok = False
                results[name] = (ok, url_tpl.format(username))

            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.configs.get("user_threads", 20)) as ex:
                ex.map(check, platforms.items())

            lines = [f"Platform taraması: {username}",
                     f"Taranan: {len(platforms)}  |  Filtre: {cat_filter or 'Tümü'}", ""]
            found_n = 0
            for name, (ok, url) in sorted(results.items()):
                icon = "✔" if ok else "✘"
                if ok:
                    found_n += 1
                lines.append(f"  [{icon}] {name:<20} {url}")
            lines += ["", f"Bulunan: {found_n} / {len(platforms)}"]
            return "\n".join(lines) + "\n"

        # ── Operator ──
        if head in ("op", "operator"):
            tail = raw[len(head):].strip()
            if not tail:
                return "[✘] op <ad|plmn <mcc-mnc>|country <ISO>>\n"
            self.operators = load_operators()
            if tail.lower().startswith("plmn "):
                plmn = tail[5:].strip()
                return op_format(self.operators, op_search_plmn(self.operators, plmn),
                                 f"PLMN {plmn}")
            if tail.lower().startswith("country "):
                iso = tail[8:].strip()
                return op_format(self.operators, op_search_country(self.operators, iso),
                                 f"Ülke {iso}")
            append_log(f"op {tail}", self.configs.get("log_enabled", True))
            return op_format(self.operators, op_search(self.operators, tail),
                             f"'{tail}' Sonuçları")

        # ── Shodan ──
        if head == "shodan":
            arg = raw[len("shodan"):].strip()
            if not arg:
                return "[✘] shodan <ip|domain>\n"
            return shodan_lookup(arg, self.configs.get("shodan_key",""),
                                  self.timeout, self.proxy)

        return f"[✘] Bilinmeyen komut: {head}\n\n" + self._help_text()

    # ══════════════════════════════════════════════════════════════════
    #  PANELS
    # ══════════════════════════════════════════════════════════════════

    # ── HOME ─────────────────────────────────────────────────────────
    def home_panel(self):
        self.clear_body()
        container = tk.Frame(self.body, bg=APP_BG)
        container.pack(fill="both", expand=True)
        self.wave = WaveCanvas(container, self.wave_color)
        self.wave.place(relwidth=1, relheight=1)

        info = (
            "BLOODLINE  OSINT  TOOL\n"
"Edition  v2.0\n\n"
            "──────────────────────────────────\n"
            f"  Operators DB : {len(self.operators):>6} kayıt\n"
            f"  Cache        : {len(self._cache):>6} giriş\n"
            f"  Favoriler    : {len(self.favorites):>6} hedef\n"
            f"  phonenumbers : {'✔' if PHONE_OK else '✘'}\n"
            f"  dnspython    : {'✔' if DNS_OK else '✘'}\n"
            f"  Proxy        : {self.proxy or '—'}\n"
            "──────────────────────────────────\n\n"
            "Yasal OSINT araştırmaları için.\n"
            "Yasadışı kullanım kesinlikle yasaktır.\n\n"
"by Acsida"
        )
        tk.Label(container, text=info, fg="#b0b0b0", bg=APP_BG,
                 font=("Consolas", 12), justify="center",
                 ).place(relx=0.5, rely=0.5, anchor="center")

    # ── WEB / IP ─────────────────────────────────────────────────────
    def web_panel(self):
        self.clear_body()
        self._title(self.body, "Web / IP Analyze", "GeoIP + ISP + ASN + harita")
        out = self._output_box(self.body)

        def worker():
            t = entry.get().strip()
            if not t or t == "example.com":
                return "[✘] Hedef giriniz.\n"
            cached = self._cache_lookup(f"ip:{t}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            result = ip_geo_lookup(t, self.timeout, self.proxy)
            self._cache_store(f"ip:{t}", result)
            append_log(f"ip {t}", self.configs.get("log_enabled", True))
            return result

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"IP/Web bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Domain veya IP", "example.com", "Araştır",
                                lambda: self.run_job(worker, done, "IP analiz..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._fav_btn(row, entry)
        self._action_row(self.body, out, "IP/Web Analyze")

    # ── USERFIND ─────────────────────────────────────────────────────
    def userfind_panel(self):
        self.clear_body()
        self._title(self.body, "UserFind", f"{len(PLATFORMS)} platform — paralel tarama")

        # Category filter buttons
        cat_frame = tk.Frame(self.body, bg=APP_BG)
        cat_frame.pack(fill="x", padx=26, pady=(2, 4))
        tk.Label(cat_frame, text="Filtre:", fg="#444", bg=APP_BG,
                 font=("Consolas", 9)).pack(side="left")
        self._uf_cat = tk.StringVar(value="Tümü")
        for cat in ["Tümü"] + list(PLATFORM_CATS.keys()):
            tk.Radiobutton(cat_frame, text=cat, variable=self._uf_cat, value=cat,
                           fg="#666", bg=APP_BG, selectcolor=APP_BG,
                           activebackground=APP_BG, font=("Consolas", 9),
                           ).pack(side="left", padx=4)

        out = self._output_box(self.body)

        def worker():
            u = entry.get().strip()
            if not u or u == "username":
                return "[✘] Kullanıcı adı giriniz.\n"
            cat = self._uf_cat.get()
            if cat == "Tümü":
                platforms = PLATFORMS
            else:
                keys = PLATFORM_CATS.get(cat, [])
                platforms = {k: v for k, v in PLATFORMS.items() if k in keys}

            results = {}

            def check(item):
                name, url_tpl = item
                try:
                    r = requests.get(url_tpl.format(u), timeout=self.timeout)
                    ok = r.status_code == 200
                except Exception:
                    ok = False
                results[name] = (ok, url_tpl.format(u))

            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.configs.get("user_threads", 20)) as ex:
                ex.map(check, platforms.items())

            found = sum(1 for ok, _ in results.values() if ok)
            lines = [f"Kullanıcı: {u}  |  Filtre: {cat}  |  Taranan: {len(platforms)}", ""]
            for name, (ok, url) in sorted(results.items()):
                lines.append(f"  [{'✔' if ok else '✘'}] {name:<22} {url if ok else ''}")
            lines += ["", f"BULUNAN: {found} / {len(platforms)}"]
            append_log(f"user {u}", self.configs.get("log_enabled", True))
            return "\n".join(lines) + "\n"

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"UserFind bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Kullanıcı adı", "username", "Tara",
                                lambda: self.run_job(worker, done, "UserFind taranıyor..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._fav_btn(row, entry)
        self._action_row(self.body, out, "UserFind")

    # ── MAIL ─────────────────────────────────────────────────────────
    def mail_panel(self):
        self.clear_body()
        self._title(self.body, "Mail Analyze", "MX + TXT + NS + SMTP doğrulama")
        out = self._output_box(self.body)

        def worker():
            raw_in = entry.get().strip()
            if not raw_in or raw_in == "example@gmail.com":
                return "[✘] E-posta veya domain giriniz.\n"
            domain = raw_in.split("@")[-1].strip()
            lines  = [f"Domain: {domain}", ""]
            if DNS_OK:
                for rr in ("MX","TXT","NS","A","AAAA"):
                    try:
                        ans = dns.resolver.resolve(domain, rr)
                        lines.append(f"[{rr}]")
                        for a in ans:
                            lines.append(f"  {a}")
                    except Exception:
                        lines.append(f"[{rr}]  — kayıt yok")
                    lines.append("")
            else:
                try:
                    lines.append(f"[A]  {socket.gethostbyname(domain)}")
                except Exception:
                    lines.append("[✘] Çözümlenemedi")
            append_log(f"mail {domain}", self.configs.get("log_enabled", True))
            return "\n".join(lines) + "\n"

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"Mail Analyze bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "E-posta veya domain", "example@gmail.com",
                                "Sorgula", lambda: self.run_job(worker, done, "Mail..."))
        self._action_row(self.body, out, "Mail Analyze")

    # ── PHONE ────────────────────────────────────────────────────────
    def phone_panel(self):
        self.clear_body()
        self._title(self.body, "Phone Analyze", "Operatör / ülke / geçerlilik")
        out = self._output_box(self.body)

        def worker():
            if not PHONE_OK:
                return "[✘] phonenumbers kurulu değil.\npip install phonenumbers\n"
            raw_num = entry.get().strip()
            if not raw_num or raw_num == "+905xxxxxxxxx":
                return "[✘] Numara giriniz.\n"
            try:
                num = phonenumbers.parse(raw_num, None)
            except Exception:
                return "[✘] Parse edilemedi. Format: +905xxxxxxxxx\n"
            return "\n".join([
                f"Ülke/Bölge    : {geocoder.description_for_number(num,'tr')}",
                f"Operatör      : {carrier.name_for_number(num,'tr') or 'Bilinmiyor'}",
                f"Zaman Dilimi  : {list(pn_tz.time_zones_for_number(num))}",
                f"Hat Tipi      : {number_type(num)}",
                f"Geçerli mi?   : {phonenumbers.is_valid_number(num)}",
                f"Ülke Kodu     : {phonenumbers.region_code_for_number(num)}",
                "", "Not: Konum/adres/takip yapılmaz.",
            ]) + "\n"

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"Phone bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Numara (+ülke kodu)", "+905xxxxxxxxx",
                                "Analiz Et", lambda: self.run_job(worker, done, "Phone..."))
        self._action_row(self.body, out, "Phone Analyze")

    # ── OP ───────────────────────────────────────────────────────────
    def op_panel(self):
        self.clear_body()
        self._title(self.body, "OP Analyze", "MCC/MNC / ad / ülke — global operatör DB")
        out = self._output_box(self.body)

        def worker():
            q = entry.get().strip()
            self.operators = load_operators()
            if not q:
                return "[✘] Sorgu boş.\n"
            if re.fullmatch(r"\d{3}-\d{2,3}", q):
                return op_format(self.operators, op_search_plmn(self.operators, q), f"PLMN {q}")
            if re.fullmatch(r"[A-Za-z]{2,3}", q):
                hits = op_search_country(self.operators, q.upper())
                if hits:
                    return op_format(self.operators, hits, f"Ülke {q.upper()}")
            append_log(f"op {q}", self.configs.get("log_enabled", True))
            return op_format(self.operators, op_search(self.operators, q), f"'{q}'")

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"OP bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Ad / PLMN / Ülke ISO", "Turkcell  |  286-01  |  TR",
                                "Ara", lambda: self.run_job(worker, done, "OP aranıyor..."))
        self._action_row(self.body, out, "OP Analyze")

    # ── WHOIS ────────────────────────────────────────────────────────
    def whois_panel(self):
        self.clear_body()
        self._title(self.body, "WHOIS", "IANA → 2-adımlı raw WHOIS")
        out = self._output_box(self.body)

        def worker():
            d = entry.get().strip()
            if not d or d == "google.com":
                return "[✘] Domain giriniz.\n"
            cached = self._cache_lookup(f"whois:{d}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            result = simple_whois(d, self.timeout)
            self._cache_store(f"whois:{d}", result)
            append_log(f"whois {d}", self.configs.get("log_enabled", True))
            return result

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"WHOIS bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Domain", "google.com", "Sorgula",
                                lambda: self.run_job(worker, done, "WHOIS..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._fav_btn(row, entry)
        self._action_row(self.body, out, "WHOIS")

    # ── DNS ──────────────────────────────────────────────────────────
    def dns_panel(self):
        self.clear_body()
        self._title(self.body, "DNS Lookup", "A / MX / NS / TXT / CNAME / AAAA")

        rr_frame = tk.Frame(self.body, bg=APP_BG)
        rr_frame.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(rr_frame, text="Kayıt:", fg="#444", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._rr_var = tk.StringVar(value="A")
        for rr in ("A","MX","NS","TXT","CNAME","AAAA","SOA","SRV"):
            tk.Radiobutton(rr_frame, text=rr, variable=self._rr_var, value=rr,
                           fg="#666", bg=APP_BG, selectcolor=APP_BG,
                           activebackground=APP_BG, font=("Consolas", 9),
                           ).pack(side="left", padx=4)

        out = self._output_box(self.body)

        def worker():
            d = entry.get().strip()
            if not d or d == "example.com":
                return "[✘] Domain giriniz.\n"
            append_log(f"dns {self._rr_var.get()} {d}", self.configs.get("log_enabled", True))
            return dns_lookup(self._rr_var.get(), d, self.timeout)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"DNS bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Domain", "example.com", "Sorgula",
                                lambda: self.run_job(worker, done, "DNS..."))
        self._action_row(self.body, out, "DNS Lookup")

    # ── SSL ──────────────────────────────────────────────────────────
    def ssl_panel(self):
        self.clear_body()
        self._title(self.body, "SSL / TLS", "Sertifika • Geçerlilik • Cipher • SAN")

        port_frame = tk.Frame(self.body, bg=APP_BG)
        port_frame.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(port_frame, text="Port:", fg="#444", bg=APP_BG,
                 font=("Consolas", 9)).pack(side="left")
        self._ssl_port = tk.StringVar(value="443")
        tk.Spinbox(port_frame, from_=1, to=65535, textvariable=self._ssl_port,
                   width=6, bg=INPUT_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left", padx=6)

        out = self._output_box(self.body)

        def worker():
            h = entry.get().strip()
            if not h or h == "example.com":
                return "[✘] Host giriniz.\n"
            try:
                port = int(self._ssl_port.get())
            except ValueError:
                port = 443
            append_log(f"ssl {h}:{port}", self.configs.get("log_enabled", True))
            return ssl_analyze(h, port, self.timeout)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"SSL bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Host", "example.com", "Analiz Et",
                                lambda: self.run_job(worker, done, "SSL analiz..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._fav_btn(row, entry)
        self._action_row(self.body, out, "SSL/TLS")

    # ── PORT ─────────────────────────────────────────────────────────
    def port_panel(self):
        self.clear_body()
        self._title(self.body, "Port Tarayıcı", "Paralel TCP port tarama")

        cfg_frame = tk.Frame(self.body, bg=APP_BG)
        cfg_frame.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(cfg_frame, text="Maks port:", fg="#444", bg=APP_BG,
                 font=("Consolas", 9)).pack(side="left")
        self._port_max = tk.StringVar(value=str(self.configs.get("max_ports", 1024)))
        tk.Spinbox(cfg_frame, from_=1, to=65535, textvariable=self._port_max,
                   width=7, bg=INPUT_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left", padx=6)
        tk.Label(cfg_frame, text="Thread:", fg="#444", bg=APP_BG,
                 font=("Consolas", 9)).pack(side="left", padx=(10, 0))
        self._port_thr = tk.StringVar(value=str(self.configs.get("port_threads", 100)))
        tk.Spinbox(cfg_frame, from_=1, to=500, textvariable=self._port_thr,
                   width=5, bg=INPUT_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left", padx=6)

        out = self._output_box(self.body)

        def worker():
            h = entry.get().strip()
            if not h or h == "example.com":
                return "[✘] Host giriniz.\n"
            try:
                maxp = min(int(self._port_max.get()), 65535)
                thr  = max(1, int(self._port_thr.get()))
            except ValueError:
                maxp, thr = 1024, 100
            append_log(f"port {h} 1-{maxp}", self.configs.get("log_enabled", True))
            return port_scan(h, maxp, thr, float(self.timeout) * 0.1)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"Port tarama bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Host", "example.com", "Tara",
                                lambda: self.run_job(worker, done, "Port taranıyor..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        tk.Label(row, text="⚠ Yalnızca yetkili olduğunuz sistemlerde kullanın.",
                 fg="#4a2a2a", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._action_row(self.body, out, "Port Tarama")

    # ── SUBDOMAIN ────────────────────────────────────────────────────
    def subdomain_panel(self):
        self.clear_body()
        self._title(self.body, "Subdomain Tarayıcı", "crt.sh + brute-force")

        opt_frame = tk.Frame(self.body, bg=APP_BG)
        opt_frame.pack(fill="x", padx=26, pady=(4, 2))
        self._sub_crt  = tk.BooleanVar(value=True)
        self._sub_bf   = tk.BooleanVar(value=True)
        for txt, var in [("crt.sh", self._sub_crt), ("Brute-force", self._sub_bf)]:
            tk.Checkbutton(opt_frame, text=txt, variable=var,
                           fg="#666", bg=APP_BG, selectcolor=APP_BG,
                           activebackground=APP_BG,
                           font=("Consolas", 9)).pack(side="left", padx=6)
        tk.Label(opt_frame, text=f"({len(SUBDOMAIN_WORDLIST)} kelime listesi)",
                 fg="#333", bg=APP_BG, font=("Consolas", 8)).pack(side="left")

        out = self._output_box(self.body)

        def worker():
            d = entry.get().strip()
            if not d or d == "example.com":
                return "[✘] Domain giriniz.\n"
            append_log(f"sub {d}", self.configs.get("log_enabled", True))
            return subdomain_scan(d,
                                  use_crtsh=self._sub_crt.get(),
                                  use_bruteforce=self._sub_bf.get(),
                                  num_threads=self.configs.get("sub_threads", 50),
                                  timeout=self.timeout, proxy=self.proxy)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"Subdomain bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "Domain", "example.com", "Tara",
                                lambda: self.run_job(worker, done, "Subdomain taranıyor..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        tk.Label(row, text="⚠ Yalnızca yetkili olduğunuz domainlerde kullanın.",
                 fg="#4a2a2a", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._action_row(self.body, out, "Subdomain")

    # ── EMAIL VERIFY ─────────────────────────────────────────────────
    def email_verify_panel(self):
        self.clear_body()
        self._title(self.body, "E-posta Doğrulama", "SMTP RCPT ile varlık kontrolü")
        out = self._output_box(self.body)

        def worker():
            e = entry.get().strip()
            if not e or e == "test@example.com":
                return "[✘] E-posta giriniz.\n"
            return smtp_email_verify(e, self.timeout)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"E-posta doğrulama bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "E-posta adresi", "test@example.com",
                                "Doğrula", lambda: self.run_job(worker, done, "SMTP doğrulama..."))
        tk.Label(self.body,
                 text="  Not: Catch-all sunucular her adresi kabul edebilir. Sonuç kesin değildir.",
                 fg="#3a3a2a", bg=APP_BG, font=("Consolas", 8)).pack(anchor="w", padx=26)
        self._action_row(self.body, out, "Email Verify")

    # ── BREACH ───────────────────────────────────────────────────────
    def breach_panel(self):
        self.clear_body()
        self._title(self.body, "Breach Kontrolü", "HaveIBeenPwned API v3")

        if not self.configs.get("hibp_key",""):
            tk.Label(self.body,
                     text="  ⚠  HIBP API anahtarı girilmemiş — Settings menüsünden ekleyin.",
                     fg=WARN_FG, bg=APP_BG, font=("Consolas", 10)).pack(anchor="w", padx=26, pady=(0, 6))

        out = self._output_box(self.body)

        def worker():
            e = entry.get().strip()
            if not e or e == "test@example.com":
                return "[✘] E-posta giriniz.\n"
            return hibp_breach_check(e, self.configs.get("hibp_key",""),
                                      self.timeout, self.proxy)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"Breach bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "E-posta adresi", "test@example.com",
                                "Kontrol Et", lambda: self.run_job(worker, done, "HIBP sorgulanıyor..."))
        self._action_row(self.body, out, "Breach")

    # ── SHODAN ───────────────────────────────────────────────────────
    def shodan_panel(self):
        self.clear_body()
        self._title(self.body, "Shodan", "Host bilgisi + açık servisler + CVE")

        if not self.configs.get("shodan_key",""):
            tk.Label(self.body,
                     text="  ⚠  Shodan API anahtarı girilmemiş — Settings menüsünden ekleyin.",
                     fg=WARN_FG, bg=APP_BG, font=("Consolas", 10)).pack(anchor="w", padx=26, pady=(0, 6))

        out = self._output_box(self.body)

        def worker():
            t = entry.get().strip()
            if not t or t == "8.8.8.8":
                return "[✘] IP veya domain giriniz.\n"
            return shodan_lookup(t, self.configs.get("shodan_key",""),
                                  self.timeout, self.proxy)

        def done(res, elapsed):
            self.out_set(out, res)
            self._update_status(f"Shodan bitti — {elapsed:.1f}s")

        entry = self._input_row(self.body, "IP veya domain", "8.8.8.8",
                                "Sorgula", lambda: self.run_job(worker, done, "Shodan..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._fav_btn(row, entry)
        self._action_row(self.body, out, "Shodan")

    # ── COMMAND PANEL ────────────────────────────────────────────────
    def command_panel(self, prefill: str = None, auto_run: bool = False):
        self.clear_body()
        self._title(self.body, "Komut Paneli", "komutlar → tam liste  |  ↑↓ geçmiş")
        out = self._output_box(self.body)

        def _run():
            cmd = entry.get().strip()
            if not cmd:
                return
            if cmd not in self._cmd_history:
                self._cmd_history.append(cmd)
            self._cmd_idx = len(self._cmd_history)

            def worker():
                return self.run_command(cmd)

            def done(res, elapsed):
                self.out_set(out, "" if cmd.lower() == "clear" else res)
                self._update_status(f"Komut bitti — {elapsed:.1f}s")

            self.run_job(worker, done, "Çalışıyor...")

        def hist_up(_e):
            if self._cmd_history and self._cmd_idx > 0:
                self._cmd_idx -= 1
                entry.delete(0, "end")
                entry.insert(0, self._cmd_history[self._cmd_idx])

        def hist_dn(_e):
            if self._cmd_idx < len(self._cmd_history) - 1:
                self._cmd_idx += 1
                entry.delete(0, "end")
                entry.insert(0, self._cmd_history[self._cmd_idx])
            else:
                self._cmd_idx = len(self._cmd_history)
                entry.delete(0, "end")

        entry = self._input_row(self.body, "Komut", prefill or "komutlar",
                                "Çalıştır", _run)
        entry.bind("<Up>",   hist_up)
        entry.bind("<Down>", hist_dn)
        self.out_set(out, self._help_text())
        self._action_row(self.body, out, "Komut")

        if auto_run and prefill:
            self.run_job(lambda: self.run_command(prefill),
                         lambda r, e: self.out_set(out, r), "Çalışıyor...")

    # ── FAVORITES ────────────────────────────────────────────────────
    def favorites_panel(self):
        self.clear_body()
        self._title(self.body, "Favoriler", "Hızlı erişim hedefleri")

        if not self.favorites:
            tk.Label(self.body, text="\n  Henüz favori yok.\n  Herhangi bir panelde ☆ Favori butonuna basın.",
                     fg="#444", bg=APP_BG, font=("Consolas", 11)).pack(anchor="w", padx=26)
            return

        frame = tk.Frame(self.body, bg=APP_BG)
        frame.pack(fill="both", expand=True, padx=26, pady=8)

        for i, fav in enumerate(self.favorites):
            row = tk.Frame(frame, bg=CARD_BG, bd=1, relief="solid")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=fav, fg=TEXT_FG, bg=CARD_BG,
                     font=("Consolas", 11)).pack(side="left", padx=10, pady=6)

            def _ip(f=fav): self._nav("🌐  Web / IP", lambda: None); self.web_panel(); \
                            self.run_job(lambda: ip_geo_lookup(f, self.timeout, self.proxy),
                                        lambda r, e: None, f"IP {f}...")

            def _whois(f=fav): self.whois_panel()
            def _ssl(f=fav):   self.ssl_panel()
            def _port(f=fav):  self.port_panel()

            def _run_ip(f=fav):
                self.command_panel(prefill=f"ip {f}", auto_run=True)

            for lbl, fn in [("ip", lambda f=fav: self.command_panel(f"ip {f}", True)),
                             ("whois", lambda f=fav: self.command_panel(f"whois {f}", True)),
                             ("ssl",   lambda f=fav: self.command_panel(f"ssl {f}", True)),
                             ("port",  lambda f=fav: self.command_panel(f"port {f}", True)),
                             ("sub",   lambda f=fav: self.command_panel(f"sub {f}", True))]:
                tk.Button(row, text=lbl, bg="#1a1a1a", fg="#666",
                          font=("Consolas", 9), relief="flat", padx=6,
                          command=fn).pack(side="left", padx=2, pady=4)

            def del_fav(f=fav):
                self.favorites.remove(f)
                save_favorites(self.favorites)
                self.favorites_panel()

            tk.Button(row, text="✕", bg="#1a1a1a", fg=ERR_FG,
                      font=("Consolas", 9), relief="flat", padx=6,
                      command=del_fav).pack(side="right", padx=8, pady=4)

    # ── HISTORY ──────────────────────────────────────────────────────
    def history_panel(self):
        self.clear_body()
        self._title(self.body, "Sorgu Geçmişi", LOG_FILE)
        out = self._output_box(self.body)
        if os.path.exists(LOG_FILE):
            try:
                content = open(LOG_FILE, encoding="utf-8").read()
                self.out_set(out, content or "[ℹ] Log boş.\n")
            except Exception as e:
                self.out_set(out, f"[✘] {e}\n")
        else:
            self.out_set(out, "[ℹ] Henüz log oluşturulmadı.\n")

        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(6, 14))

        def clear_log():
            if messagebox.askyesno("Log Temizle", "Tüm geçmiş silinsin mi?"):
                try:
                    os.remove(LOG_FILE)
                    self.out_set(out, "[ℹ] Log temizlendi.\n")
                except Exception as e:
                    self.out_set(out, f"[✘] {e}\n")

        tk.Button(row, text="Log Temizle", bg="#1a1a1a", fg="#666",
                  font=("Consolas", 9), relief="flat", padx=10,
                  command=clear_log).pack(side="left")

    # ── REPORT ───────────────────────────────────────────────────────
    def report_panel(self):
        self.clear_body()
        self._title(self.body, "HTML Rapor", "Tüm analizleri tek dosyaya aktar")

        info_frame = tk.Frame(self.body, bg=CARD_BG, bd=1, relief="solid")
        info_frame.pack(fill="x", padx=26, pady=(0, 8))
        tk.Label(info_frame,
                 text=f"  Raporda {len(self._report_sections)} bölüm var.\n"
                      "  Herhangi bir analizde '+ Rapora Ekle' butonunu kullanın.",
                 fg="#666", bg=CARD_BG, font=("Consolas", 10),
                 justify="left").pack(anchor="w", padx=10, pady=8)

        out = self._output_box(self.body, color=TEXT_FG)

        # section list
        if self._report_sections:
            preview = "\n".join(f"  [{i+1}] {t}" for i, (t, _) in enumerate(self._report_sections))
            self.out_set(out, f"Mevcut bölümler:\n{preview}\n")
        else:
            self.out_set(out, "[ℹ] Henüz bölüm eklenmedi.\n")

        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(6, 14))

        target_ent = tk.Entry(row, font=("Consolas", 11), bg=INPUT_BG, fg="white",
                              insertbackground=self.ui_color, relief="flat", width=30)
        target_ent.insert(0, "hedef.com")
        target_ent.pack(side="left", ipady=5)

        def export_html():
            if not self._report_sections:
                messagebox.showinfo("Rapor", "Önce en az bir bölüm ekleyin.")
                return
            path = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML","*.html"),("All","*.*")])
            if not path:
                return
            html = generate_html_report(
                self._report_sections,
                target=target_ent.get().strip())
            open(path, "w", encoding="utf-8").write(html)
            self._update_status(f"HTML raporu kaydedildi: {os.path.basename(path)}")

        def clear_report():
            self._report_sections.clear()
            self.out_set(out, "[ℹ] Rapor temizlendi.\n")
            self._update_status("Rapor temizlendi")

        tk.Button(row, text="HTML Olarak Kaydet",
                  bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=12,
                  command=export_html).pack(side="left", padx=(8, 6))
        tk.Button(row, text="Temizle", bg="#1a1a1a", fg="#666",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=clear_report).pack(side="left")

    # ── SETTINGS ─────────────────────────────────────────────────────
    def settings_panel(self):
        self.clear_body()
        self._title(self.body, "Settings", "DB • Renk • API • Ağ • Cache")

        canvas = tk.Canvas(self.body, bg=APP_BG, highlightthickness=0)
        vsb    = tk.Scrollbar(self.body, orient="vertical", command=canvas.yview,
                               bg=APP_BG, troughcolor=APP_BG)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=APP_BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))

        def sec(title):
            tk.Label(inner, text=title, fg=self.ui_color, bg=APP_BG,
                     font=("Consolas", 11, "bold")).pack(anchor="w", padx=26, pady=(14, 3))
            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", padx=26, pady=(0, 6))

        # ── DB ──
        sec("Operators DB")
        db_box = tk.Frame(inner, bg=CARD_BG, bd=1, relief="solid")
        db_box.pack(fill="x", padx=26, pady=(0, 8))
        db_lbl = tk.Label(db_box, text="", fg="#666", bg=CARD_BG,
                          font=("Consolas", 9), justify="left")
        db_lbl.pack(anchor="w", padx=10, pady=(8, 4))

        def refresh_db():
            self.operators = load_operators()
            ok = os.path.exists(OPERATORS_FILE)
            db_lbl.config(text=(
                f"  Durum  : {'✔' if ok else '✘'}\n"
                f"  Kayıt  : {len(self.operators)}\n"
                f"  Dosya  : {OPERATORS_FILE}"))
            self._update_status("DB yenilendi")

        def do_sync():
            self.run_job(
                lambda: build_operators_json_from_mccmnc(OPERATORS_FILE, self.proxy),
                lambda r, _: (refresh_db(), messagebox.showinfo("DB", r.strip())),
                "DB güncelleniyor...")

        btn_row = tk.Frame(db_box, bg=CARD_BG)
        btn_row.pack(anchor="w", padx=10, pady=(2, 10))
        tk.Button(btn_row, text="DB Güncelle (opsync)", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=10,
                  command=do_sync).pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="Yenile", bg="#1a1a1a", fg="#666",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=refresh_db).pack(side="left")
        refresh_db()

        # ── API Keys ──
        sec("API Anahtarları")
        api_box = tk.Frame(inner, bg=CARD_BG, bd=1, relief="solid")
        api_box.pack(fill="x", padx=26, pady=(0, 8))
        for key_name, cfg_key, placeholder in [
            ("HIBP API Key",   "hibp_key",   "Enter HaveIBeenPwned API key"),
            ("Shodan API Key", "shodan_key", "Enter Shodan API key"),
        ]:
            row = tk.Frame(api_box, bg=CARD_BG)
            row.pack(fill="x", padx=10, pady=5)
            tk.Label(row, text=f"{key_name}:", fg="#666", bg=CARD_BG,
                     font=("Consolas", 9), width=16, anchor="w").pack(side="left")
            ent = tk.Entry(row, font=("Consolas", 10), bg=INPUT_BG, fg="white",
                           insertbackground=self.ui_color, relief="flat",
                           show="•", width=40)
            ent.pack(side="left", ipady=4, padx=(4, 4))
            ent.insert(0, self.configs.get(cfg_key, ""))

            def save_key(e=ent, k=cfg_key):
                self.configs[k] = e.get().strip()
                save_config(self.configs)
                self._update_status(f"{k} kaydedildi")

            tk.Button(row, text="Kaydet", bg="#1a1a1a", fg="#666",
                      font=("Consolas", 8), relief="flat", padx=6,
                      command=save_key).pack(side="left")

        # ── Proxy ──
        sec("Proxy Ayarı")
        proxy_box = tk.Frame(inner, bg=CARD_BG, bd=1, relief="solid")
        proxy_box.pack(fill="x", padx=26, pady=(0, 8))
        prow = tk.Frame(proxy_box, bg=CARD_BG)
        prow.pack(fill="x", padx=10, pady=8)
        tk.Label(prow, text="Proxy URL:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 9)).pack(side="left")
        proxy_ent = tk.Entry(prow, font=("Consolas", 10), bg=INPUT_BG, fg="white",
                             insertbackground=self.ui_color, relief="flat", width=40)
        proxy_ent.pack(side="left", ipady=4, padx=6)
        proxy_ent.insert(0, self.proxy)
        tk.Label(prow, text="örn: socks5://127.0.0.1:9050", fg="#333", bg=CARD_BG,
                 font=("Consolas", 8)).pack(side="left")

        def save_proxy():
            self.proxy = proxy_ent.get().strip()
            self.configs["proxy"] = self.proxy
            save_config(self.configs)
            self._update_status(f"Proxy: {self.proxy or 'kapalı'}")

        tk.Button(prow, text="Uygula", bg="#1a1a1a", fg="#666",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=save_proxy).pack(side="left", padx=6)

        # ── Network ──
        sec("Ağ / Tarama Ayarları")
        net_box = tk.Frame(inner, bg=CARD_BG, bd=1, relief="solid")
        net_box.pack(fill="x", padx=26, pady=(0, 8))

        net_vars = {}
        for lbl, key, lo, hi in [
            ("Timeout (sn)",      "timeout",      1,  60),
            ("Port tarama thread","port_threads",  1, 500),
            ("Subdomain thread",  "sub_threads",   1, 200),
            ("UserFind thread",   "user_threads",  1, 100),
            ("Max port",          "max_ports",     1, 65535),
        ]:
            nrow = tk.Frame(net_box, bg=CARD_BG)
            nrow.pack(fill="x", padx=10, pady=3)
            tk.Label(nrow, text=f"{lbl}:", fg="#666", bg=CARD_BG,
                     font=("Consolas", 9), width=22, anchor="w").pack(side="left")
            var = tk.StringVar(value=str(self.configs.get(key, DEFAULT_CONFIG.get(key, 10))))
            net_vars[key] = var
            tk.Spinbox(nrow, from_=lo, to=hi, textvariable=var, width=7,
                       bg=INPUT_BG, fg="white", relief="flat",
                       font=("Consolas", 10)).pack(side="left", padx=4)

        def save_net():
            for k, v in net_vars.items():
                try:
                    self.configs[k] = int(v.get())
                except ValueError:
                    pass
            self.timeout = self.configs["timeout"]
            save_config(self.configs)
            self._update_status("Ağ ayarları kaydedildi")

        tk.Button(net_box, text="Kaydet", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=10,
                  command=save_net).pack(anchor="w", padx=10, pady=(4, 10))

        # ── Cache ──
        sec("Önbellek (Cache)")
        cache_box = tk.Frame(inner, bg=CARD_BG, bd=1, relief="solid")
        cache_box.pack(fill="x", padx=26, pady=(0, 8))
        crow = tk.Frame(cache_box, bg=CARD_BG)
        crow.pack(fill="x", padx=10, pady=8)
        cache_en = tk.BooleanVar(value=self.configs.get("cache_enabled", True))

        def toggle_cache():
            self.configs["cache_enabled"] = cache_en.get()
            save_config(self.configs)
            self._update_status(f"Cache {'açık' if cache_en.get() else 'kapalı'}")

        tk.Checkbutton(crow, text="Cache aktif", variable=cache_en, command=toggle_cache,
                       fg="#666", bg=CARD_BG, selectcolor=CARD_BG,
                       activebackground=CARD_BG, font=("Consolas", 9)).pack(side="left")
        tk.Label(crow, text="TTL (sn):", fg="#666", bg=CARD_BG,
                 font=("Consolas", 9)).pack(side="left", padx=(20, 4))
        ttl_var = tk.StringVar(value=str(self.configs.get("cache_ttl", 3600)))
        tk.Spinbox(crow, from_=60, to=86400, textvariable=ttl_var, width=7,
                   bg=INPUT_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left")

        def save_ttl():
            try:
                self.configs["cache_ttl"] = int(ttl_var.get())
                save_config(self.configs)
            except Exception:
                pass

        tk.Button(crow, text="TTL Kaydet", bg="#1a1a1a", fg="#666",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=save_ttl).pack(side="left", padx=6)

        tk.Label(crow, text=f"Şu an: {len(self._cache)} giriş", fg="#333", bg=CARD_BG,
                 font=("Consolas", 8)).pack(side="left", padx=10)

        def clear_cache():
            self._cache.clear()
            save_cache(self._cache)
            self._update_status("Cache temizlendi")

        tk.Button(crow, text="Cache Temizle", bg="#1a1a1a", fg=ERR_FG,
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=clear_cache).pack(side="left")

        # ── Colors ──
        sec("Renkler")
        colors = ["#ff2a2a","#00ff88","#00d4ff","#b400ff",
                  "#ff8800","#ffcc00","#ffffff","#ff69b4"]
        color_row = tk.Frame(inner, bg=APP_BG)
        color_row.pack(fill="x", padx=26, pady=(0, 10))
        for title_lbl, setter in [("UI Rengi", self._set_ui_color),
                                   ("Wave Rengi", self._set_wave_color)]:
            col = tk.Frame(color_row, bg=APP_BG)
            col.pack(side="left", fill="both", expand=True, padx=(0, 18))
            tk.Label(col, text=title_lbl, fg="#555", bg=APP_BG,
                     font=("Consolas", 9, "bold")).pack(anchor="w", pady=(0, 3))
            g = tk.Frame(col, bg=APP_BG)
            g.pack(fill="x")
            for i, c in enumerate(colors):
                tk.Button(g, bg=c, width=12, relief="flat",
                          command=lambda x=c, s=setter: s(x),
                          ).grid(row=i//4, column=i%4, padx=4, pady=4)

        # ── Log ──
        sec("Log")
        log_frame = tk.Frame(inner, bg=APP_BG)
        log_frame.pack(fill="x", padx=26, pady=(0, 20))
        log_var = tk.BooleanVar(value=self.configs.get("log_enabled", True))

        def toggle_log():
            self.configs["log_enabled"] = log_var.get()
            save_config(self.configs)
            self._update_status(f"Log {'açık' if log_var.get() else 'kapalı'}")

        tk.Checkbutton(log_frame, text="Sorgu logunu kaydet", variable=log_var,
                       command=toggle_log, fg="#666", bg=APP_BG, selectcolor=APP_BG,
                       activebackground=APP_BG, font=("Consolas", 10)).pack(side="left")
        tk.Label(log_frame, text=f"  ({LOG_FILE})", fg="#333", bg=APP_BG,
                 font=("Consolas", 8)).pack(side="left")

    def _set_ui_color(self, c: str):
        self.ui_color = c
        self.configs["ui_color"] = c
        save_config(self.configs)
        self.logo_label.config(fg=c)
        self._update_status(f"UI rengi: {c}")

    def _set_wave_color(self, c: str):
        self.wave_color = c
        self.configs["wave_color"] = c
        save_config(self.configs)
        if self.wave:
            self.wave.set_color(c)
        self._update_status(f"Wave rengi: {c}")


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = BloodlineApp()
    app.mainloop()
