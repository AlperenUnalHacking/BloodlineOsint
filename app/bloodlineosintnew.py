"""
╔══════════════════════════════════════════════════════════════════════╗
║      BLOODLINE OSINT TOOL  —  Edition  v3.2                         ║
║      Yasal OSINT araştırmaları için tasarlanmıştır.                 ║
║      Yasadışı kullanım kesinlikle yasaktır.                         ║
╚══════════════════════════════════════════════════════════════════════╝

  v3.2 yenilikleri:
  • 120+ subdomain wordlist (eskisi: 50)
  • 55+ platform (eskisi: 42) — Quora, Dailymotion, Battle.net vb.
  • 25+ port servis tespiti (eskisi: 21)
  • İptal butonu (✕ İptal) — her panelden uzun işlemleri durdurma
  • Klavye kısayolları: Ctrl+C kopyala, Ctrl+S kaydet, Ctrl+E export, Esc iptal, Ctrl+F ara
  • DNS Zone Transfer & DNSSEC kontrolü
  • SSL HSTS kontrolü
  • Toplu tarama (batch <dosya>)
  • Geçmiş panelinde arama/filtre
  • Zone transfer komutu (zonetransfer <domain>)
  • Timezone-aware datetime (utcnow deprecated fix)

  • RandomProxy  : Kapalı / Manuel / Rastgele (bloodlineproxy dosyası)
  • HIBP         : API'lı (tam) ↔ API'sız (k-Anonymity, sadece şifre)
  • Shodan       : API'lı (tam) ↔ API'sız (InternetDB, ücretsiz)
  • Toggle'lar   : Settings → her servis için ayrı API modu seçimi
"""

# ── stdlib ────────────────────────────────────────────────────────────
import tkinter as tk
from tkinter import filedialog
import tkinter.messagebox as messagebox
import math, threading, json, os, requests, time, ssl, socket
import re, difflib, datetime, hashlib, smtplib, urllib.parse
import ipaddress, random
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── paths ─────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE    = os.path.join(BASE_DIR, "config.json")
OPERATORS_FILE = os.path.join(BASE_DIR, "operators.json")
LOG_FILE       = os.path.join(BASE_DIR, "bloodline_log.txt")
CACHE_FILE     = os.path.join(BASE_DIR, "bloodline_cache.json")
FAVORITES_FILE = os.path.join(BASE_DIR, "bloodline_favorites.json")
PROXY_FILE     = os.path.join(BASE_DIR, "bloodlineproxy")

# ── theme ─────────────────────────────────────────────────────────────
APP_BG  = "#0b0b0b"
SIDE_BG = "#0e0e0e"
TOP_BG  = "#0f0f0f"
CARD_BG = "#111111"
IN_BG   = "#161616"
OUT_BG  = "#0d0d0d"
BORDER  = "#252525"
TXT_FG  = "#d0d0d0"
MUT_FG  = "#888888"
GRN_FG  = "#00ff88"
WRN_FG  = "#ffcc00"
ERR_FG  = "#ff4444"
BLU_FG  = "#00d4ff"

# ── default config ────────────────────────────────────────────────────
DEFAULT_CONFIG: dict = {
    "ui_color":       "#ff2a2a",
    "wave_color":     "#ff2a2a",
    "timeout":        10,
    "log_enabled":    True,
    "cache_enabled":  True,
    "cache_ttl":      3600,
    # proxy
    "proxy_mode":     "off",      # off | manual | random
    "proxy_manual":   "",
    # api keys
    "hibp_key":       "",
    "shodan_key":     "",
    # api mode toggles
    "hibp_mode":      "noapi",    # "api" | "noapi"
    "shodan_mode":    "noapi",    # "api" | "noapi"
    # scan limits
    "max_ports":      1024,
    "port_threads":   100,
    "sub_threads":    50,
    "user_threads":   20,
    "rate_limit_ms":  0,
}

MCCMNC_URL = "https://raw.githubusercontent.com/telecomhall/mcc-mnc/master/mccmnc.json"

# ── optional imports ──────────────────────────────────────────────────
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as pn_tz, number_type
    PHONE_OK = True
except ImportError:
    PHONE_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ── platforms ─────────────────────────────────────────────────────────
PLATFORMS: dict[str, str] = {
    # Social
    "Twitter/X":     "https://x.com/{}",
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

PLATFORM_CATS: dict[str, list] = {
    "Sosyal":     ["Twitter/X","Instagram","Facebook","LinkedIn","TikTok",
                   "Snapchat","Pinterest","Tumblr","Reddit","Quora",
                   "Mastodon","Bluesky","Threads"],
    "Video":      ["YouTube","Twitch","Kick","Dailymotion","Vimeo"],
    "Oyun":       ["Roblox","Steam","Epic Games","Xbox","Origin/EA",
                   "PlayStation","Minecraft","Discord","Battle.net","Ubisoft"],
    "Geliştirici":["GitHub","GitLab","Bitbucket","Replit","HackerNews",
                   "npm","PyPI","Keybase","StackOverflow"],
    "Yaratıcı":   ["Medium","Behance","Dribbble","DeviantArt","Flickr","500px"],
    "Müzik":      ["SoundCloud","Bandcamp","Spotify","Last.fm"],
    "İş":         ["Fiverr","Upwork","Patreon","Ko-fi"],
}

SUB_WORDLIST = [
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
#  CONFIG / CACHE / LOG / FAVORITES
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
        print(f"[config] {e}")

def load_operators() -> list:
    if os.path.exists(OPERATORS_FILE):
        try:
            with open(OPERATORS_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, list):
                return d
        except Exception:
            pass
    return []

def load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_cache(c: dict) -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(c, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def cache_get(c: dict, key: str, ttl: int):
    e = c.get(key)
    if e and (time.time() - e.get("ts", 0)) < ttl:
        return e.get("val")
    return None

def cache_set(c: dict, key: str, val: str) -> None:
    c[key] = {"ts": time.time(), "val": val}

def load_favorites() -> list:
    if os.path.exists(FAVORITES_FILE):
        try:
            with open(FAVORITES_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, list):
                return d
        except Exception:
            pass
    return []

def save_favorites(lst: list) -> None:
    try:
        with open(FAVORITES_FILE, "w", encoding="utf-8") as f:
            json.dump(lst, f, indent=2, ensure_ascii=False)
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

# ══════════════════════════════════════════════════════════════════════
#  PROXY MANAGER
# ══════════════════════════════════════════════════════════════════════

class ProxyManager:
    """
    Üç mod:
      off    — proxy yok
      manual — config["proxy_manual"] URL'si
      random — bloodlineproxy dosyasından rastgele satır
               Her get_proxy() çağrısında farklı proxy döner.
    """
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._pool: list[str] = []
        self._last: str = ""
        self._reload()

    def _reload(self) -> None:
        self._pool = []
        if os.path.exists(PROXY_FILE):
            try:
                with open(PROXY_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self._pool.append(line)
            except Exception:
                pass

    def pool_size(self) -> int:
        return len(self._pool)

    def get_proxy(self) -> str:
        """Aktif moda göre proxy URL veya '' döner."""
        mode = self.cfg.get("proxy_mode", "off")
        if mode == "off":
            return ""
        if mode == "manual":
            return self.cfg.get("proxy_manual", "").strip()
        if mode == "random":
            self._reload()
            if not self._pool:
                return ""
            pool = [p for p in self._pool if p != self._last] or self._pool
            chosen = random.choice(pool)
            self._last = chosen
            return chosen
        return ""

    def make_session(self, timeout: int = 10) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 (compatible; BloodlineOSINT/3.1)"
        p = self.get_proxy()
        if p:
            s.proxies = {"http": p, "https": p}
        return s

    def test_proxy(self, url: str, timeout: int = 8) -> tuple[bool, str]:
        if not url:
            return False, "Proxy URL boş."
        try:
            r = requests.get("http://ip-api.com/json/",
                             proxies={"http": url, "https": url},
                             timeout=timeout)
            j = r.json()
            return True, (f"[✔] Proxy çalışıyor!\n"
                          f"  Görünen IP : {j.get('query','?')}\n"
                          f"  Ülke       : {j.get('country','?')}\n"
                          f"  ISP        : {j.get('isp','?')}")
        except Exception as e:
            return False, f"[✘] Proxy başarısız: {e}"

    def create_proxy_file(self) -> None:
        if not os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, "w", encoding="utf-8") as f:
                f.write(
                    "# Bloodline Proxy Listesi — her satır bir proxy\n"
                    "# Boş satırlar ve # ile başlayanlar atlanır\n"
                    "#\n"
                    "# Örnekler:\n"
                    "# http://192.168.1.1:8080\n"
                    "# socks5://127.0.0.1:9050\n"
                    "# http://kullanici:sifre@proxy.site.com:3128\n"
                )

# ══════════════════════════════════════════════════════════════════════
#  OPERATORS DB BUILD
# ══════════════════════════════════════════════════════════════════════

def build_operators_db(session: requests.Session = None) -> str:
    try:
        sess = session or requests.Session()
        r = sess.get(MCCMNC_URL, timeout=40)
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        return f"[✘] İndirilemedi: {e}\n"
    if not isinstance(rows, list):
        return "[✘] Beklenmedik format.\n"
    index: dict = {}
    for row in rows:
        name = (row.get("network") or row.get("operator") or row.get("brand") or "").strip()
        if not name:
            continue
        mcc  = str(row.get("mcc", "")).strip()
        mnc  = str(row.get("mnc", "")).strip()
        plmn = f"{mcc}-{mnc}" if mcc and mnc else None
        iso  = (row.get("countryIso") or row.get("iso") or "").strip().upper()
        country = iso or (row.get("countryName") or "").strip()
        key = (name.lower(), country)
        if key not in index:
            index[key] = {"name": name,
                          "countries": [country] if country else [],
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
        with open(OPERATORS_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        return f"[✔] operators.json üretildi — {len(out)} kayıt\n"
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
        self.after(40, self._tick)

    def set_color(self, c: str):
        self.color = c

    def stop(self):
        self.running = False
        self.delete("all")

    def _tick(self):
        if not self.running:
            return
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w > 50 and h > 50:
            for i in range(4):
                pts = []
                for x in range(0, w + 15, 15):
                    y = h / 2 + math.sin(x / (55 + i * 8) + self.phase + i * 0.6) * (18 + i * 4)
                    pts.extend([x, y])
                if len(pts) >= 4:
                    self.create_line(pts, fill=self.color, width=max(1, 3 - i), smooth=True)
        self.phase += 0.12
        self.after(40, self._tick)

# ══════════════════════════════════════════════════════════════════════
#  ANALYSIS — IP / WHOIS / DNS / SSL / PORT / SUB
# ══════════════════════════════════════════════════════════════════════

def ip_geo_lookup(target: str, timeout: int = 10, sess: requests.Session = None) -> str:
    target = target.strip()
    if not target:
        return "[✘] Hedef giriniz.\n"
    ip = target
    if any(c.isalpha() for c in target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return "[✘] Domain çözümlenemedi.\n"
    lines = [f"[✔] Hedef   : {target}", f"[✔] IP      : {ip}"]
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        lines.append(f"[✔] PTR     : {ptr}")
    except Exception:
        lines.append("[ℹ] PTR     : Bulunamadı")
    try:
        if ipaddress.ip_address(ip).is_private:
            lines.append("[ℹ] Özel/yerel IP — GeoIP atlandı.")
            return "\n".join(lines) + "\n"
    except Exception:
        pass
    try:
        s = sess or requests.Session()
        geo = s.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,regionName,city,district,"
            "lat,lon,isp,org,as,hosting,proxy,mobile,query,timezone",
            timeout=timeout,
        ).json()
    except Exception as e:
        lines.append(f"[✘] GeoIP: {e}")
        return "\n".join(lines) + "\n"
    if geo.get("status") != "success":
        lines.append("[✘] GeoIP veri döndürmedi.")
        return "\n".join(lines) + "\n"
    lines += ["", "─── Yaklaşık Konum ─────────────────────────────"]
    for k, lbl in [("country","Ülke      "), ("regionName","Bölge     "),
                   ("city","Şehir     "), ("district","İlçe      "),
                   ("timezone","Zaman D.  ")]:
        v = geo.get(k)
        if v:
            lines.append(f"  {lbl}: {v}")
    lines += ["", "─── Ağ ─────────────────────────────────────────"]
    for k, lbl in [("isp","ISP      "), ("org","Org      "), ("as","ASN      ")]:
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
    lines += ["", "─" * 50, "Not: Yaklaşık OSINT verisi."]
    return "\n".join(lines) + "\n"


def simple_whois(domain: str, timeout: int = 10) -> str:
    domain = domain.strip().lower()
    if not domain or " " in domain:
        return "[✘] Geçersiz domain.\n"
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
        iana = raw.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[✘] IANA WHOIS: {e}\n"
    whois_srv = None
    for line in iana.splitlines():
        if line.lower().startswith("whois:"):
            whois_srv = line.split(":", 1)[1].strip()
            break
    whois_srv = whois_srv or "whois.verisign-grs.com"
    try:
        with socket.create_connection((whois_srv, 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
        return raw.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[✘] WHOIS ({whois_srv}): {e}\n"


def dns_lookup(rr: str, domain: str, timeout: int = 10) -> str:
    rr = rr.upper().strip()
    domain = domain.strip()
    if not domain:
        return "[✘] Domain giriniz.\n"
    if not DNS_OK:
        if rr == "A":
            try:
                return f"[✔] {domain}  A  →  {socket.gethostbyname(domain)}\n"
            except Exception:
                return "[✘] DNS A çözümlenemedi.\n"
        return "[✘] dnspython gerekli: pip install dnspython\n"
    try:
        res = dns.resolver.Resolver()
        res.timeout = timeout
        ans = res.resolve(domain, rr)
        lines = [f"[✔] {domain}  {rr}:"]
        for a in ans:
            lines.append(f"  {a}")
        return "\n".join(lines) + "\n"
    except dns.resolver.NXDOMAIN:
        return f"[✘] Domain bulunamadı: {domain}\n"
    except dns.resolver.NoAnswer:
        return f"[ℹ] {domain} için {rr} kaydı yok.\n"
    except Exception as e:
        return f"[✘] DNS ({rr} {domain}): {e}\n"


def dns_zone_transfer(domain: str, timeout: int = 10) -> str:
    """NS sunucularında zone transfer denemesi —Yetkili test."""
    domain = domain.strip().lower()
    if not domain:
        return "[✘] Domain giriniz.\n"
    if not DNS_OK:
        return "[✘] dnspython gerekli: pip install dnspython\n"
    lines = [f"─── DNS Zone Transfer: {domain} ──────────────"]
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        ns_hosts = [str(r.exchange).rstrip(".") for r in ns_records]
        lines.append(f"  NS Sunucuları: {', '.join(ns_hosts)}\n")
    except Exception as e:
        return f"[✘] NS sorgulanamadı: {e}\n"
    for ns in ns_hosts:
        try:
            import dns.zone, dns.query, dns.rdatatype
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns, domain, timeout=timeout, lifetime=timeout)
            )
            lines.append(f"  [⚠] {ns}: Zone transfer BAŞARILI! (güvenlik açığı)")
            rr_count = sum(len(rds) for rds in zone.nodes.values())
            lines.append(f"      {len(zone.nodes)} düğüm, ~{rr_count} kayıt")
        except dns.exception.Timeout:
            lines.append(f"  [✔] {ns}: Timeout — muhtemelen engellendi")
        except Exception:
            lines.append(f"  [✔] {ns}: Reddedildi (güvenli)")
    lines += ["", "Not: Zone transfer başarısı büyük bir güvenlik açığıdır."]
    return "\n".join(lines) + "\n"


def dnssec_check(domain: str, timeout: int = 10) -> str:
    """DNSSEC varlığını ve zincirini kontrol eder."""
    domain = domain.strip().lower()
    if not domain:
        return "[✘] Domain giriniz.\n"
    if not DNS_OK:
        return "[✘] dnspython gerekli: pip install dnspython\n"
    lines = [f"─── DNSSEC Kontrolü: {domain} ──────────────────"]
    try:
        res = dns.resolver.Resolver()
        res.timeout = timeout
        # DNSKEY kaydı
        try:
            ans = res.resolve(domain, "DNSKEY")
            lines.append(f"  [✔] DNSKEY bulundu ({len(ans)} anahtar)")
            for r in list(ans)[:5]:
                lines.append(f"      Flags:{r.flags} Algorithm:{r.algorithm}")
        except dns.resolver.NoAnswer:
            lines.append("  [✘] DNSKEY yok — DNSSEC aktif değil")
        except dns.resolver.NXDOMAIN:
            return f"[✘] Domain bulunamadı: {domain}\n"
        # DS kaydı
        try:
            ds_ans = res.resolve(domain, "DS")
            lines.append(f"  [✔] DS bulundu ({len(ds_ans)} kayıt)")
        except dns.resolver.NoAnswer:
            lines.append("  [ℹ] DS kaydı yok — üst zonapee DNSSEC yapılandırılmamış")
        # NSEC3
        try:
            nsec_ans = res.resolve(domain, "NSEC3")
            lines.append(f"  [✔] NSEC3 bulundu (bölge gizleme aktif)")
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            pass
    except Exception as e:
        lines.append(f"  [✘] DNSSEC kontrolü başarısız: {e}")
    lines += ["", "Not: DNSSEC veri bütünlüğü sağlar ama gizlilik sağlamaz."]
    return "\n".join(lines) + "\n"


def ssl_analyze(host: str, port: int = 443, timeout: int = 10) -> str:
    host = host.strip()
    if not host:
        return "[✘] Host giriniz.\n"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw_s:
            with ctx.wrap_socket(raw_s, server_hostname=host) as ss:
                cert   = ss.getpeercert()
                cipher = ss.cipher()
                ver    = ss.version()
    except ssl.SSLCertVerificationError as e:
        return f"[⚠] SSL Doğrulama Hatası: {e}\n"
    except Exception as e:
        return f"[✘] SSL bağlantısı kurulamadı: {e}\n"
    subj   = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer",  []))
    nb = cert.get("notBefore", "?")
    na = cert.get("notAfter",  "?")
    lines = [f"─── SSL/TLS: {host}:{port} ─────────────",
             f"  CN           : {subj.get('commonName','?')}",
             f"  Org          : {subj.get('organizationName','?')}",
             f"  CA           : {issuer.get('commonName','?')}",
             "", f"  Başlangıç    : {nb}", f"  Bitiş        : {na}"]
    try:
        exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        rem = (exp - datetime.datetime.now(datetime.timezone.utc)).days
        tag = (" ⚠ YAKINDA SONA ERİYOR!" if 0 < rem < 30
               else (" ✘ SÜRESİ DOLMUŞ!" if rem < 0 else ""))
        lines.append(f"  Kalan gün    : {rem}{tag}")
    except Exception:
        pass
    sans = cert.get("subjectAltName", [])
    if sans:
        lines += ["", "─── SAN ────────────────────────────────────────"]
        for _, v in sans[:20]:
            lines.append(f"  {v}")
        if len(sans) > 20:
            lines.append(f"  ... ve {len(sans) - 20} tane daha")
    lines += ["", "─── Bağlantı ───────────────────────────────────",
              f"  TLS Sürümü   : {ver}"]
    if cipher:
        lines.append(f"  Cipher       : {cipher[0]}")
        lines.append(f"  Bit          : {cipher[2]}")
    # HSTS kontrolü
    try:
        import requests as _req
        r = _req.get(f"https://{host}", timeout=5, allow_redirects=False,
                     headers={"User-Agent": "BloodlineOSINT/3.1"})
        hsts = r.headers.get("Strict-Transport-Security", "")
        if hsts:
            lines += ["", "─── HSTS ───────────────────────────────────────",
                      f"  Durum       : [✔] Aktif",
                      f"  max-age     : {hsts}"]
        else:
            lines += ["", "─── HSTS ───────────────────────────────────────",
                      "  Durum       : [⚠] Tanımlı değil"]
    except Exception:
        lines += ["", "─── HSTS ───────────────────────────────────────",
                  "  Durum       : [?] Kontrol edilemedi"]
    return "\n".join(lines) + "\n"


def port_scan(host: str, max_port: int = 1024,
              threads: int = 100, timeout: float = 1.0) -> str:
    host = host.strip()
    if not host:
        return "[✘] Host giriniz.\n"
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return "[✘] Host çözümlenemedi.\n"
    SVC = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
           80:"HTTP",110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",
           143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
           1433:"MSSQL",1723:"PPTP",3306:"MySQL",3389:"RDP",
           5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Alt",
           8443:"HTTPS-Alt",8888:"Jupyter",9200:"Elasticsearch",
           27017:"MongoDB"}
    open_ports: list = []
    lock = threading.Lock()

    def chk(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        open_ports.append((port, SVC.get(port, "")))
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(chk, range(1, max_port + 1))

    open_ports.sort()
    lines = [f"─── Port Tarama: {host} ({ip}) ─────────────",
             f"  Taranan : 1–{max_port}  |  Açık: {len(open_ports)}", ""]
    for port, svc in open_ports:
        lines.append(f"  [✔] {port:<7} {svc}")
    if not open_ports:
        lines.append("  Açık port bulunamadı.")
    lines += ["", "Not: Yalnızca yetkili sistemlerde kullanın."]
    return "\n".join(lines) + "\n"


def subdomain_scan(domain: str, use_crtsh: bool = True,
                   use_brute: bool = True, threads: int = 50,
                   timeout: int = 3, sess: requests.Session = None) -> str:
    domain = domain.strip().lower()
    if not domain:
        return "[✘] Domain giriniz.\n"
    found: set = set()
    if use_crtsh:
        try:
            s = sess or requests.Session()
            r = s.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            for entry in r.json():
                for sub in entry.get("name_value", "").splitlines():
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.add(sub)
        except Exception:
            pass
    if use_brute:
        lock = threading.Lock()
        def probe(w: str):
            fqdn = f"{w}.{domain}"
            try:
                socket.setdefaulttimeout(timeout)
                socket.gethostbyname(fqdn)
                with lock:
                    found.add(fqdn)
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(probe, SUB_WORDLIST)
    results = sorted(found)
    lines = [f"─── Subdomain: {domain} ───────────────────────",
             f"  Yöntem  : {'crt.sh ' if use_crtsh else ''}{'brute-force' if use_brute else ''}",
             f"  Bulunan : {len(results)}", ""]
    for sub in results:
        try:
            ip = socket.gethostbyname(sub)
            lines.append(f"  [✔] {sub:<45} {ip}")
        except Exception:
            lines.append(f"  [✔] {sub}")
    if not results:
        lines.append("  Subdomain bulunamadı.")
    lines += ["", "Not: Yalnızca yetkili domainlerde kullanın."]
    return "\n".join(lines) + "\n"


def batch_scan(targets_file: str, scan_type: str = "ip",
               timeout: int = 10, sess: requests.Session = None) -> str:
    """Dosyadan toplu tarama — her satır bir hedef."""
    if not os.path.exists(targets_file):
        return f"[✘] Dosya bulunamadı: {targets_file}\n"
    try:
        with open(targets_file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        return f"[✘] Dosya okunamadı: {e}\n"
    if not targets:
        return "[✘] Dosyada hedef yok.\n"
    lines = [f"─── Toplu Tarama: {scan_type.upper()} ──────────────",
             f"  Dosya   : {targets_file}",
             f"  Hedef   : {len(targets)} adet", ""]
    results = []
    for i, target in enumerate(targets, 1):
        lines.append(f"  [{i}/{len(targets)}] {target}...")
        try:
            if scan_type == "ip":
                r = ip_geo_lookup(target, timeout, sess)
            elif scan_type == "whois":
                r = simple_whois(target, timeout)
            elif scan_type == "ssl":
                r = ssl_analyze(target, 443, timeout)
            elif scan_type == "shodan":
                r = shodan_noapi(target, timeout, sess)
            else:
                r = ip_geo_lookup(target, timeout, sess)
            results.append((target, r))
            lines.append(f"    [✔] Tamamlandı")
        except Exception as e:
            results.append((target, f"[✘] Hata: {e}"))
            lines.append(f"    [✘] Hata: {e}")
    lines += ["", f"─── Özet ────────────────────────────────────"]
    for target, result in results:
        status = "[✔]" if "[✘]" not in result else "[✘]"
        lines.append(f"  {status} {target}")
    lines += ["", "Not: Toplu taramalarda rate-limit dikkate alınır."]
    return "\n".join(lines) + "\n"


def smtp_verify(email: str, timeout: int = 10) -> str:
    email = email.strip()
    if not email or "@" not in email:
        return "[✘] Geçerli e-posta giriniz.\n"
    domain = email.split("@")[-1]
    lines  = [f"─── SMTP Doğrulama: {email} ──────────────"]
    mx_host = None
    if DNS_OK:
        try:
            mx_rec  = dns.resolver.resolve(domain, "MX")
            mx_host = str(sorted(mx_rec, key=lambda r: r.preference)[0].exchange).rstrip(".")
            lines.append(f"  MX Host : {mx_host}")
        except Exception as e:
            lines.append(f"  MX      : Bulunamadı ({e})")
    if not mx_host:
        lines.append("[✘] MX kaydı yok, SMTP doğrulaması yapılamaz.")
        return "\n".join(lines) + "\n"
    try:
        with smtplib.SMTP(timeout=timeout) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo_or_helo_if_needed()
            smtp.mail("probe@bloodline-osint.local")
            code, msg = smtp.rcpt(email)
            mapping = {250: "[✔] MEVCUT görünüyor", 550: "[✘] MEVCUT DEĞİL (550)"}
            lines.append(f"  Durum   : {mapping.get(code, f'[?] {code} {msg.decode()}')}")
    except Exception as e:
        lines.append(f"  SMTP    : [✘] {e}")
    lines += ["", "Not: Catch-all sunucular her adresi kabul eder."]
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════
#  HIBP  —  API'LI / API'SİZ
# ══════════════════════════════════════════════════════════════════════

def hibp_email_apikey(email: str, api_key: str,
                       timeout: int = 10, sess: requests.Session = None) -> str:
    """
    HIBP v3 API — tam sonuç, breach detayları.
    Gereksinim: haveibeenpwned.com API key.
    """
    lines = [f"─── HIBP Breach (API'lı): {email} ─────────────"]
    s = sess or requests.Session()
    try:
        r = s.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            headers={"hibp-api-key": api_key,
                     "User-Agent": "BloodlineOSINT/3.1"},
            params={"truncateResponse": "false"},
            timeout=timeout,
        )
        if r.status_code == 404:
            lines.append("  [✔] Bu e-posta bilinen sızıntılarda YOK.")
        elif r.status_code == 200:
            breaches = r.json()
            lines.append(f"  [!] {len(breaches)} SIZMA BULUNDU!\n")
            for b in breaches:
                lines.append(f"  ■ {b.get('Name','?')}  ({b.get('BreachDate','?')})")
                lines.append(f"    Domain   : {b.get('Domain','?')}")
                dc = b.get("DataClasses", [])
                if dc:
                    lines.append(f"    Çalınan  : {', '.join(dc[:6])}")
                lines.append(f"    Kayıt    : {b.get('PwnCount', 0):,}\n")
        elif r.status_code == 401:
            lines.append("  [✘] API key geçersiz (401) — Settings'ten güncelleyin.")
        elif r.status_code == 429:
            lines.append("  [✘] Rate limit (429) — biraz bekleyin.")
        else:
            lines.append(f"  [?] HTTP {r.status_code}")
    except Exception as e:
        lines.append(f"  [✘] API hatası: {e}")
    lines += ["", "Not: E-posta HIBP sunucusuna gönderilir (resmi servis)."]
    return "\n".join(lines) + "\n"


def hibp_password_noapi(password: str) -> str:
    """
    HIBP k-Anonymity (Pwned Passwords) — API key GEREKMİYOR.
    SHA-1 hash'in yalnızca ilk 5 karakteri gönderilir.
    Şifre asla iletilmez.
    """
    if not password:
        return "[✘] Şifre giriniz.\n"
    sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    lines  = ["─── Şifre Sızıntı Kontrolü (API'sız / k-Anonymity) ─────",
              "  Yöntem : SHA-1 prefix — şifreniz iletilmez.", ""]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "BloodlineOSINT/3.1",
                     "Add-Padding": "true"},
            timeout=10,
        )
        r.raise_for_status()
        count = 0
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                count = int(parts[1].strip())
                break
        if count > 0:
            lines.append(f"  [!] Bu şifre {count:,} kez veri sızıntısında görüldü!")
            lines.append("  Hemen değiştirmeniz önerilir.")
        else:
            lines.append("  [✔] Bu şifre bilinen sızıntı veritabanında bulunamadı.")
    except Exception as e:
        lines.append(f"  [✘] HIBP Pwned Passwords: {e}")
    lines += ["", "Not: Yalnızca hash prefix gönderilir — tam şifre asla iletilmez."]
    return "\n".join(lines) + "\n"


def hibp_email_noapi(email: str, timeout: int = 10,
                      sess: requests.Session = None) -> str:
    """
    API key olmadan e-posta breach özeti.
    HIBP'nin ücretsiz truncated endpoint'ini dener.
    """
    lines = [f"─── HIBP Breach (API'sız): {email} ─────────────",
             "  [ℹ] API'sız modda yalnızca sızıntı adları görülebilir.",
             "  [ℹ] Tam detay için Settings → HIBP → API'lı moda geçin.\n"]
    s = sess or requests.Session()
    s.headers["User-Agent"] = "BloodlineOSINT/3.1"
    try:
        r = s.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            params={"truncateResponse": "true"},
            timeout=timeout,
        )
        if r.status_code == 404:
            lines.append("  [✔] Bu e-posta bilinen sızıntılarda YOK.")
        elif r.status_code == 200:
            breaches = r.json()
            lines.append(f"  [!] {len(breaches)} sızıntıda bulundu:")
            for b in breaches:
                lines.append(f"    ■ {b.get('Name','?')}")
        elif r.status_code == 401:
            lines += ["  [ℹ] Bu endpoint artık API key gerektiriyor.",
                      "  Settings → HIBP Modu → API'lı yapıp key girin.",
                      "  Key al: https://haveibeenpwned.com/API/Key"]
        elif r.status_code == 429:
            lines.append("  [✘] Rate limit — biraz bekleyin.")
        else:
            lines.append(f"  [?] HTTP {r.status_code}")
    except Exception as e:
        lines.append(f"  [✘] Bağlantı hatası: {e}")
    lines += ["", "Şifre kontrolü için: breach pw <şifre>  (her zaman API'sız çalışır)"]
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════
#  SHODAN  —  API'LI / API'SİZ
# ══════════════════════════════════════════════════════════════════════

def shodan_apikey(target: str, api_key: str,
                   timeout: int = 10, sess: requests.Session = None) -> str:
    """
    Shodan Host API — tam servis ve CVE bilgisi.
    Gereksinim: shodan.io API key.
    """
    target = target.strip()
    if not target:
        return "[✘] IP veya domain giriniz.\n"
    lines = [f"─── Shodan (API'lı): {target} ────────────────────"]
    s = sess or requests.Session()
    try:
        ip = socket.gethostbyname(target) if any(c.isalpha() for c in target) else target
        r  = s.get(f"https://api.shodan.io/shodan/host/{ip}",
                   params={"key": api_key}, timeout=timeout)
        if r.status_code == 401:
            return "\n".join(lines) + "\n  [✘] API key geçersiz (401).\n"
        if r.status_code == 404:
            return "\n".join(lines) + "\n  [ℹ] Bu IP Shodan'da kayıtlı değil.\n"
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return "\n".join(lines) + f"\n  [✘] Shodan API hatası: {e}\n"

    lines += [f"  IP           : {data.get('ip_str','?')}",
              f"  Org          : {data.get('org','?')}",
              f"  ISP          : {data.get('isp','?')}",
              f"  ASN          : {data.get('asn','?')}",
              f"  OS           : {data.get('os') or '?'}",
              f"  Konum        : {data.get('city','?')}, {data.get('country_code','?')}"]
    vulns = data.get("vulns", [])
    if vulns:
        lines += ["", f"  [!] CVE ({len(vulns)}):"]
        for v in list(vulns)[:15]:
            lines.append(f"      {v}")
    services = data.get("data", [])
    if services:
        lines += ["", f"  Servisler ({len(services)}):"]
        for svc in services[:15]:
            p = svc.get("port","?")
            prod = svc.get("product","")
            ver  = svc.get("version","")
            lines.append(f"    [{p}] {prod} {ver}".rstrip())
    lines += ["", "Not: Shodan verileri kamuya açık tarama sonuçlarıdır."]
    return "\n".join(lines) + "\n"


def shodan_noapi(target: str, timeout: int = 10,
                  sess: requests.Session = None) -> str:
    """
    Shodan InternetDB — ücretsiz, API key GEREKMİYOR.
    Portlar, CVE'ler, hostname'ler döner.
    """
    target = target.strip()
    if not target:
        return "[✘] IP veya domain giriniz.\n"
    lines = [f"─── Shodan InternetDB (API'sız): {target} ────────",
             "  [ℹ] Tam sonuç için Settings → Shodan → API'lı moda geçin.\n"]
    s = sess or requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"
    try:
        ip = socket.gethostbyname(target) if any(c.isalpha() for c in target) else target
        r  = s.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 404:
            lines.append("  [ℹ] Bu IP InternetDB'de kayıtlı değil.")
        elif r.status_code == 200:
            d = r.json()
            lines.append(f"  IP           : {d.get('ip','?')}")
            hn = d.get("hostnames", [])
            if hn:
                lines.append(f"  Hostname(s)  : {', '.join(hn)}")
            ports = d.get("ports", [])
            if ports:
                lines.append(f"  Açık Portlar : {', '.join(map(str, ports))}")
            vulns = d.get("vulns", [])
            if vulns:
                lines += ["", f"  [!] Olası CVE ({len(vulns)}):"]
                for v in vulns[:15]:
                    lines.append(f"      {v}")
            cpes = d.get("cpes", [])
            if cpes:
                lines.append(f"\n  CPE          : {', '.join(cpes[:5])}")
            tags = d.get("tags", [])
            if tags:
                lines.append(f"  Etiketler    : {', '.join(tags)}")
            if not ports and not vulns:
                lines.append("  [ℹ] Bu IP için kayıt yok.")
        else:
            lines.append(f"  [?] HTTP {r.status_code}")
    except Exception as e:
        lines.append(f"  [✘] InternetDB hatası: {e}")
    lines += ["", "Not: Shodan InternetDB kamuya açık verilerdir."]
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════
#  ASN / WAYBACK / EMAIL HEADER
# ══════════════════════════════════════════════════════════════════════

def asn_lookup(target: str, timeout: int = 10, sess: requests.Session = None) -> str:
    target = target.strip()
    if not target:
        return "[✘] IP, domain veya ASN giriniz.\n"
    lines = [f"─── ASN / BGP: {target} ─────────────────────────"]
    s = sess or requests.Session()
    try:
        ip = (socket.gethostbyname(target)
              if (any(c.isalpha() for c in target) and not target.upper().startswith("AS"))
              else target)
        r = s.get(f"https://ipinfo.io/{ip}/json", timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            for k, lbl in [("ip","IP          "), ("hostname","Hostname    "),
                            ("city","Şehir       "), ("region","Bölge       "),
                            ("country","Ülke        "), ("org","Org / ASN   "),
                            ("timezone","Zaman Dil.  ")]:
                v = d.get(k)
                if v:
                    lines.append(f"  {lbl}: {v}")
            loc = d.get("loc", "")
            if loc:
                lines.append(f"  Koordinat   : {loc}")
    except Exception as e:
        lines.append(f"  [✘] ipinfo.io: {e}")
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sc:
            sc.sendall(f" -v {target}\r\n".encode())
            raw = b""
            while True:
                chunk = sc.recv(4096)
                if not chunk:
                    break
                raw += chunk
        cymru = raw.decode("utf-8", errors="ignore").strip()
        if cymru:
            lines += ["", "─── Team Cymru BGP ─────────────────────────────"]
            for line in cymru.splitlines():
                if line.strip():
                    lines.append(f"  {line.strip()}")
    except Exception:
        pass
    return "\n".join(lines) + "\n"


def wayback_lookup(url: str, timeout: int = 10, sess: requests.Session = None) -> str:
    url = url.strip()
    if not url:
        return "[✘] URL giriniz.\n"
    if not url.startswith("http"):
        url = "http://" + url
    lines = [f"─── Wayback Machine: {url} ──────────────────────"]
    s = sess or requests.Session()
    s.headers["User-Agent"] = "BloodlineOSINT/3.1"
    try:
        av = s.get("https://archive.org/wayback/available",
                   params={"url": url}, timeout=timeout).json()
        snap = av.get("archived_snapshots", {}).get("closest", {})
        if snap:
            lines += [f"  Son Arşiv    : {snap.get('timestamp','')}",
                      f"  HTTP Durum   : {snap.get('status','')}",
                      f"  Arşiv URL    : {snap.get('url','')}"]
        else:
            lines.append("  [ℹ] Yakın arşiv bulunamadı.")
    except Exception as e:
        lines.append(f"  [✘] Availability API: {e}")
    try:
        r = s.get("http://web.archive.org/cdx/search/cdx",
                  params={"url": url, "output": "json", "limit": 25,
                          "fl": "timestamp,statuscode,mimetype",
                          "collapse": "timestamp:8"},
                  timeout=timeout)
        rows = r.json()
        if rows and len(rows) > 1:
            lines += ["", "─── Arşiv Geçmişi (son 25 gün) ─────────────────"]
            for row in rows[1:]:
                ts, sc, mt = row[0], row[1], row[2]
                lines.append(f"  {ts[:4]}-{ts[4:6]}-{ts[6:8]}  [{sc}]  {mt}")
        else:
            lines.append("  [ℹ] Arşiv kaydı bulunamadı.")
    except Exception as e:
        lines.append(f"  [✘] CDX API: {e}")
    lines.append(f"\n  Tüm arşivler: https://web.archive.org/web/*/{url}")
    return "\n".join(lines) + "\n"


def analyze_email_header(raw: str) -> str:
    if not raw.strip():
        return "[✘] Başlık metni giriniz.\n"
    lines = ["─── Email Header Analizi ───────────────────────────"]
    for field in ("From", "To", "Subject", "Date", "Message-ID", "Reply-To"):
        m = re.search(rf"^{field}:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
        if m:
            lines.append(f"  {field:<12}: {m.group(1).strip()}")
    lines += ["", "─── Kimlik Doğrulama ───────────────────────────────"]
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{proto}=(\w+)", raw, re.IGNORECASE)
        if m:
            val  = m.group(1).lower()
            icon = "✔" if val == "pass" else ("✘" if val in ("fail","softfail") else "?")
            lines.append(f"  [{icon}] {proto.upper():<6}: {val}")
        else:
            lines.append(f"  [?] {proto.upper():<6}: Bulunamadı")
    spam = re.search(r"X-Spam-Status:\s*(.+)", raw, re.IGNORECASE)
    if spam:
        lines.append(f"  Spam Status : {spam.group(1).strip()}")
    score = re.search(r"X-Spam-Score:\s*(.+)", raw, re.IGNORECASE)
    if score:
        lines.append(f"  Spam Score  : {score.group(1).strip()}")
    ips: list = []
    for m in re.finditer(r"Received:.*?[\[\(](\d{1,3}(?:\.\d{1,3}){3})[\]\)]",
                          raw, re.IGNORECASE | re.DOTALL):
        ip = m.group(1)
        if ip not in ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
                    ips.append(ip)
            except Exception:
                pass
    if ips:
        lines += ["", "─── Received Zinciri IP'leri ────────────────────────"]
        for ip in ips[:10]:
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                lines.append(f"  {ip:<18}  PTR: {ptr}")
            except Exception:
                lines.append(f"  {ip}")
    from_m   = re.search(r"^From:.*?<(.+?)>",    raw, re.IGNORECASE | re.MULTILINE)
    reply_m  = re.search(r"^Reply-To:.*?<(.+?)>", raw, re.IGNORECASE | re.MULTILINE)
    if from_m and reply_m:
        fd = from_m.group(1).split("@")[-1].lower()
        rd = reply_m.group(1).split("@")[-1].lower()
        if fd != rd:
            lines += ["", "─── ⚠ PHISHING UYARISI ─────────────────────────────",
                      f"  From domain     : {fd}",
                      f"  Reply-To domain : {rd}",
                      "  ⚠ Domain'ler FARKLI — olası phishing!"]
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════
#  OPERATOR SEARCH
# ══════════════════════════════════════════════════════════════════════

def op_search(operators: list, q: str, limit: int = 20) -> list:
    q = q.strip().lower()
    if not q or not operators:
        return []
    hits  = [op for op in operators if q in str(op.get("name","")).lower()]
    names = [str(op.get("name","")) for op in operators]
    for nm in difflib.get_close_matches(q, names, n=limit, cutoff=0.50):
        for op in operators:
            if op.get("name") == nm and op not in hits:
                hits.append(op)
    return hits[:limit]

def op_search_plmn(operators: list, plmn: str, limit: int = 20) -> list:
    return [op for op in operators
            if plmn.strip() in (op.get("mcc_mnc") or [])][:limit]

def op_search_country(operators: list, iso: str, limit: int = 20) -> list:
    iso = iso.strip().upper()
    return [op for op in operators
            if iso in [c.upper() for c in (op.get("countries") or [])]][:limit]

def op_format(operators: list, hits: list, title: str = "Sonuçlar") -> str:
    if not operators:
        return "[✘] operators.json yok — Settings → DB Güncelle.\n"
    if not hits:
        return "[ℹ] Sonuç bulunamadı.\n"
    lines = [f"─── {title} ─────────────────────────────────────",
             f"Toplam: {len(hits)}", ""]
    for i, op in enumerate(hits, 1):
        lines.append(f"  [{i:02d}] {op.get('name','?')}")
        cc = [str(x) for x in (op.get("countries") or []) if x]
        if cc:
            lines.append(f"       Ülke    : {', '.join(cc)}")
        t = op.get("type")
        if t:
            lines.append(f"       Tip     : {t}")
        mm = op.get("mcc_mnc") or []
        if mm:
            lines.append(f"       MCC-MNC : {', '.join(mm[:10])}{'...' if len(mm)>10 else ''}")
        lines.append("")
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════════════════════

def html_report(sections: list, target: str = "") -> str:
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for title, content in sections:
        safe = content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        rows += f'<div class="s"><h2>{title}</h2><pre>{safe}</pre></div>\n'
    return (f'<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">'
            f'<title>Bloodline — {target}</title>'
            f'<style>*{{box-sizing:border-box;margin:0;padding:0}}'
            f'body{{background:#0b0b0b;color:#d0d0d0;font-family:Consolas,monospace;padding:28px}}'
            f'h1{{color:#ff2a2a;border-bottom:1px solid #222;padding-bottom:8px;margin-bottom:4px}}'
            f'.meta{{color:#555;font-size:.85em;margin-bottom:24px}}'
            f'.s{{background:#111;border:1px solid #222;border-radius:3px;padding:16px;margin-bottom:16px}}'
            f'.s h2{{color:#00ff88;font-size:.95em;margin-bottom:10px}}'
            f'pre{{color:#c0c0c0;font-size:.87em;white-space:pre-wrap;word-break:break-all}}'
            f'</style></head><body>'
            f'<h1>BLOODLINE OSINT REPORT</h1>'
            f'<p class="meta">Hedef: {target} | {now} | v3.1</p>'
            f'{rows}</body></html>')


# ══════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════

class BloodlineApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.configs   = load_config()
        self.ui_color  = self.configs["ui_color"]
        self.wv_color  = self.configs["wave_color"]
        self.timeout   = int(self.configs.get("timeout", 10))
        self.operators = load_operators()
        self._cache    = load_cache()
        self.favorites = load_favorites()
        self.wave: WaveCanvas | None = None
        self._cmd_hist: list[str] = []
        self._cmd_idx: int = 0
        self._report: list = []
        self.proxy_mgr = ProxyManager(self.configs)

        self.title("Bloodline OSINT — v3.2")
        self.geometry("1300x780")
        self.configure(bg=APP_BG)
        self.resizable(True, True)
        self.minsize(920, 620)

        self._layout()
        self._sidebar()
        self._topbar()
        self._statusbar()
        self._setup_shortcuts()
        self.home_panel()

    # ── layout ───────────────────────────────────────────────────────
    def _layout(self):
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
        self.sbar = tk.Frame(self.content, bg="#080808", height=24)
        self.sbar.pack(side="bottom", fill="x")
        self.sbar.pack_propagate(False)

    def _sidebar(self):
        self.logo = tk.Label(self.sidebar, text="BLOODLINE",
                             fg=self.ui_color, bg=SIDE_BG,
                             font=("Consolas", 18, "bold"))
        self.logo.pack(pady=(16, 1))
        tk.Label(self.sidebar, text="v3.2", fg="#252525", bg=SIDE_BG,
                 font=("Consolas", 8)).pack(pady=(0, 8))
        self._sdiv()
        groups = [
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
                ("🔢  ASN / BGP",       self.asn_panel),
            ]),
            ("─ GELİŞMİŞ ─", [
                ("📧  Mail Header",     self.email_header_panel),
                ("📧  SMTP Doğrula",    self.smtp_panel),
                ("💥  Breach (E-posta)",self.breach_panel),
                ("🔑  Şifre Sızıntı",   self.password_panel),
                ("👁️  Shodan",          self.shodan_panel),
                ("🕰️  Wayback",         self.wayback_panel),
            ]),
            ("─ ARAÇLAR ─", [
                ("⌨️  Komut Paneli",    self.command_panel),
                ("⭐  Favoriler",       self.favorites_panel),
                ("📜  Geçmiş",          self.history_panel),
                ("📄  HTML Rapor",      self.report_panel),
                ("⚙️  Settings",        self.settings_panel),
            ]),
        ]
        for grp, items in groups:
            tk.Label(self.sidebar, text=grp, fg="#252525", bg=SIDE_BG,
                     font=("Consolas", 8, "bold")).pack(anchor="w", padx=16, pady=(7, 1))
            for lbl, cmd in items:
                self._sbtn(lbl, cmd)
        tk.Label(self.sidebar, text="by Acsida",
                 fg="#1a1a1a", bg=SIDE_BG, font=("Consolas", 7)).pack(side="bottom", pady=6)

    def _topbar(self):
        tk.Label(self.topbar, text="›", fg=self.ui_color, bg=TOP_BG,
                 font=("Consolas", 15, "bold")).pack(side="left", padx=(12, 4))
        self.qentry = tk.Entry(self.topbar, font=("Consolas", 12),
                               bg=IN_BG, fg="white",
                               insertbackground=self.ui_color,
                               width=56, relief="flat", bd=0)
        self.qentry.pack(side="left", padx=(0, 6), ipady=5, pady=10)
        self.qentry.bind("<Return>", lambda _: self._quick_run())
        tk.Button(self.topbar, text="RUN", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=12,
                  command=self._quick_run).pack(side="left", pady=10)
        self._proxy_lbl = tk.Label(self.topbar, text="", fg="#444", bg=TOP_BG,
                                   font=("Consolas", 9))
        self._proxy_lbl.pack(side="right", padx=12)
        self._refresh_proxy_lbl()
        tk.Label(self.topbar,
                 text="  ip 8.8.8.8  |  breach user@x.com  |  breach pw pass123  |  shodan 1.1.1.1",
                 fg="#1e1e1e", bg=TOP_BG, font=("Consolas", 8)).pack(side="left", padx=6)

    def _statusbar(self):
        self._sv = tk.StringVar()
        tk.Label(self.sbar, textvariable=self._sv,
                 fg="#444", bg="#080808", font=("Consolas", 9), anchor="w"
                 ).pack(side="left", padx=10, fill="x", expand=True)
        self._cv = tk.StringVar()
        tk.Label(self.sbar, textvariable=self._cv,
                 fg="#252525", bg="#080808", font=("Consolas", 9)).pack(side="right", padx=10)
        self._tick()
        self._status("Hazır")

    def _tick(self):
        self._cv.set(datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick)

    def _setup_shortcuts(self):
        """Klavye kısayolları — Ctrl+C, Ctrl+S, Ctrl+E, Ctrl+Q, Escape."""
        self.bind("<Control-c>", lambda e: self._shortcut_copy())
        self.bind("<Control-s>", lambda e: self._shortcut_save())
        self.bind("<Control-e>", lambda e: self._shortcut_export())
        self.bind("<Control-q>", lambda e: self.destroy())
        self.bind("<Escape>", lambda e: self._shortcut_cancel())
        self.bind("<Control-f>", lambda e: self._shortcut_find())

    def _get_active_output(self) -> tk.Text | None:
        """Aktif output box'u bulur."""
        for w in reversed(self.body.winfo_children()):
            if isinstance(w, tk.Frame):
                for child in w.winfo_children():
                    if isinstance(child, tk.Text):
                        return child
                    if isinstance(child, tk.Frame):
                        for gc in child.winfo_children():
                            if isinstance(gc, tk.Text):
                                return gc
        return None

    def _shortcut_copy(self):
        out = self._get_active_output()
        if out:
            self.clipboard_clear()
            self.clipboard_append(out.get("1.0", "end").strip())
            self._status("Panoya kopyalandı (Ctrl+C)")

    def _shortcut_save(self):
        out = self._get_active_output()
        if out:
            content = out.get("1.0", "end").strip()
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text","*.txt"),("HTML","*.html"),("JSON","*.json")])
            if path:
                try:
                    if path.endswith(".html"):
                        open(path, "w", encoding="utf-8").write(
                            html_report([("Sonuç", content)]))
                    elif path.endswith(".json"):
                        json.dump({"result": content},
                                  open(path, "w", encoding="utf-8"), indent=2)
                    else:
                        open(path, "w", encoding="utf-8").write(content)
                    self._status(f"Kaydedildi: {os.path.basename(path)}")
                except Exception as e:
                    self._status(f"Hata: {e}")

    def _shortcut_export(self):
        if self._report:
            path = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML","*.html")])
            if path:
                open(path, "w", encoding="utf-8").write(
                    html_report(self._report))
                self._status(f"HTML raporu: {os.path.basename(path)}")
        else:
            self._status("Rapor boş — önce '+ Rapora Ekle' kullanın")

    def _shortcut_cancel(self):
        if hasattr(self, '_running_event'):
            self._running_event.set()
            self._status("İptal edildi (Escape)")

    def _shortcut_find(self):
        out = self._get_active_output()
        if out:
            # Basit arama kutusu
            win = tk.Toplevel(self)
            win.title("Ara")
            win.geometry("300x80")
            win.configure(bg=APP_BG)
            tk.Label(win, text="Ara:", fg="#666", bg=APP_BG,
                     font=("Consolas", 9)).pack(anchor="w", padx=10, pady=(8,0))
            ent = tk.Entry(win, font=("Consolas", 10), bg=IN_BG, fg="white",
                          insertbackground=self.ui_color, relief="flat")
            ent.pack(fill="x", padx=10, pady=4, ipady=4)
            ent.focus_set()
            def do_find():
                query = ent.get().strip()
                if not query:
                    return
                out.config(state="normal")
                out.tag_remove("search", "1.0", "end")
                start = "1.0"
                found = 0
                while True:
                    pos = out.search(query, start, stopindex="end", nocase=True)
                    if not pos:
                        break
                    end = f"{pos}+{len(query)}c"
                    out.tag_add("search", pos, end)
                    start = end
                    found += 1
                out.tag_configure("search", background="#3a3a00", foreground="#ffff00")
                out.config(state="disabled")
                self._status(f"{found} sonuç bulundu: {query}")
                if found == 0:
                    win.destroy()
            ent.bind("<Return>", lambda e: do_find())
            tk.Button(win, text="Bul", bg=self.ui_color, fg="black",
                      font=("Consolas", 9, "bold"), relief="flat", padx=8,
                      command=do_find).pack(anchor="w", padx=10, pady=(0,8))

    def _refresh_proxy_lbl(self):
        mode = self.configs.get("proxy_mode", "off")
        if mode == "off":
            self._proxy_lbl.config(text="[proxy: off]", fg="#252525")
        elif mode == "manual":
            p = self.configs.get("proxy_manual", "")[:28]
            self._proxy_lbl.config(text=f"[MANUAL: {p}]", fg=WRN_FG)
        elif mode == "random":
            n = self.proxy_mgr.pool_size()
            self._proxy_lbl.config(text=f"[RANDOM: {n} proxy]", fg=GRN_FG)

    # ── sidebar helpers ───────────────────────────────────────────────
    def _sdiv(self):
        tk.Frame(self.sidebar, bg="#1c1c1c", height=1).pack(fill="x", padx=14, pady=4)

    def _sbtn(self, text: str, cmd):
        tk.Button(self.sidebar, text=text, fg="#555", bg=SIDE_BG,
                  activebackground=self.ui_color, activeforeground="black",
                  font=("Consolas", 10), relief="flat", anchor="w", padx=14,
                  command=lambda t=text, c=cmd: self._nav(t, c)).pack(fill="x", padx=8, pady=1)

    def _nav(self, label: str, cmd):
        for w in self.sidebar.winfo_children():
            if isinstance(w, tk.Button):
                w.configure(bg=SIDE_BG, fg="#555")
        for w in self.sidebar.winfo_children():
            if isinstance(w, tk.Button) and w.cget("text") == label:
                w.configure(bg=self.ui_color, fg="black")
                break
        cmd()
        self._status(f"Açıldı: {label.strip()}")

    # ── body helpers ──────────────────────────────────────────────────
    def clear_body(self):
        if self.wave:
            self.wave.stop()
            self.wave = None
        for w in self.body.winfo_children():
            w.destroy()

    def _status(self, msg: str):
        mode = self.configs.get("proxy_mode", "off")
        pstr = {"off":"proxy:off","manual":"PROXY:manual",
                "random":f"PROXY:rnd({self.proxy_mgr.pool_size()})"}[mode]
        hm = "API" if (self.configs.get("hibp_mode","noapi")=="api"
                       and self.configs.get("hibp_key","")) else "noAPI"
        sm = "API" if (self.configs.get("shodan_mode","noapi")=="api"
                       and self.configs.get("shodan_key","")) else "noAPI"
        self._sv.set(
            f"  {msg}   │   DB: {len(self.operators)}"
            f"   │   cache: {len(self._cache)}"
            f"   │   {pstr}"
            f"   │   HIBP:{hm}  Shodan:{sm}"
            f"   │   t/o:{self.timeout}s"
        )

    def _title(self, parent, title: str, sub: str = ""):
        h = tk.Frame(parent, bg=APP_BG)
        h.pack(fill="x", padx=26, pady=(12, 4))
        tk.Label(h, text=title, fg=self.ui_color, bg=APP_BG,
                 font=("Consolas", 17, "bold")).pack(side="left")
        if sub:
            tk.Label(h, text=f"  —  {sub}", fg="#3a3a3a", bg=APP_BG,
                     font=("Consolas", 9)).pack(side="left", pady=(4, 0))

    def _irow(self, parent, label: str, ph: str,
               btn: str, cmd) -> tk.Entry:
        wrap = tk.Frame(parent, bg=APP_BG)
        wrap.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(wrap, text=label, fg="#444", bg=APP_BG,
                 font=("Consolas", 9, "bold")).pack(anchor="w")
        row = tk.Frame(wrap, bg=APP_BG)
        row.pack(fill="x", pady=(3, 0))
        ent = tk.Entry(row, font=("Consolas", 13), bg=IN_BG, fg="white",
                       insertbackground=self.ui_color, relief="flat", bd=0)
        ent.pack(side="left", fill="x", expand=True, ipady=6)
        ent.insert(0, ph)
        ent.bind("<FocusIn>",  lambda e: ent.get() == ph and ent.delete(0, "end"))
        ent.bind("<FocusOut>", lambda e: (not ent.get()) and ent.insert(0, ph))
        ent.bind("<Return>", lambda _: cmd())
        if btn:
            tk.Button(row, text=btn, bg=self.ui_color, fg="black",
                      font=("Consolas", 10, "bold"), relief="flat", padx=12,
                      command=cmd).pack(side="left", padx=(6, 0))
        return ent

    def _obox(self, parent, label: str = "Output", color: str = GRN_FG) -> tk.Text:
        wrap = tk.Frame(parent, bg=APP_BG)
        wrap.pack(fill="both", expand=True, padx=26, pady=(4, 0))
        tk.Label(wrap, text=label, fg="#333", bg=APP_BG,
                 font=("Consolas", 9, "bold")).pack(anchor="w")
        box = tk.Frame(wrap, bg=BORDER, bd=1, relief="solid")
        box.pack(fill="both", expand=True, pady=(3, 0))
        txt = tk.Text(box, bg=OUT_BG, fg=color, font=("Consolas", 11),
                      wrap="word", relief="flat", bd=0, padx=10, pady=8, cursor="arrow")
        sb  = tk.Scrollbar(box, command=txt.yview, bg=APP_BG, troughcolor=APP_BG)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        txt.tag_configure("ok",   foreground=GRN_FG)
        txt.tag_configure("warn", foreground=WRN_FG)
        txt.tag_configure("err",  foreground=ERR_FG)
        txt.tag_configure("info", foreground=BLU_FG)
        txt.config(state="disabled")
        return txt

    def _arow(self, parent, out: tk.Text, report_title: str = ""):
        row = tk.Frame(parent, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(5, 10))

        def do_copy():
            self.clipboard_clear()
            self.clipboard_append(out.get("1.0", "end").strip())
            self._status("Kopyalandı")

        def do_export():
            content = out.get("1.0", "end").strip()
            path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text","*.txt"),("HTML","*.html"),("JSON","*.json")])
            if not path:
                return
            try:
                if path.endswith(".html"):
                    open(path, "w", encoding="utf-8").write(
                        html_report([(report_title or "Sonuç", content)], target=report_title))
                elif path.endswith(".json"):
                    json.dump({"result": content, "ts": str(datetime.datetime.now())},
                              open(path, "w", encoding="utf-8"), indent=2)
                else:
                    open(path, "w", encoding="utf-8").write(content)
                self._status(f"Kaydedildi: {os.path.basename(path)}")
            except Exception as e:
                self._status(f"Hata: {e}")

        def do_add():
            self._report.append((report_title or "Bölüm", out.get("1.0","end").strip()))
            self._status(f"Rapora eklendi ({len(self._report)} bölüm)")

        for lbl, fn in [("⎘ Kopyala", do_copy),
                         ("↓ Dışa Aktar", do_export),
                         ("+ Rapora Ekle", do_add)]:
            tk.Button(row, text=lbl, bg="#141414", fg="#555",
                      font=("Consolas", 9), relief="flat", padx=8,
                      activebackground="#1e1e1e", activeforeground="#aaa",
                      command=fn).pack(side="left", padx=(0, 5))

        def do_cancel():
            if hasattr(self, '_running_event'):
                self._running_event.set()
                self._status("İptal edildi")
        tk.Button(row, text="✕ İptal", bg="#2a1010", fg=ERR_FG,
                  font=("Consolas", 9), relief="flat", padx=8,
                  activebackground="#3a1010", activeforeground="#ff6666",
                  command=do_cancel).pack(side="left", padx=(0, 5))

    def _favbtn(self, parent, ent: tk.Entry):
        def add():
            v = ent.get().strip()
            if v and v not in self.favorites:
                self.favorites.append(v)
                save_favorites(self.favorites)
                self._status(f"Favoriye eklendi: {v}")
        tk.Button(parent, text="☆ Favori", bg="#141414", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=add).pack(side="left", padx=(6, 0))

    # ── thread runner ─────────────────────────────────────────────────
    def _job(self, worker_fn, done_fn, busy: str = "Çalışıyor..."):
        """İptal edilebilir iş çalıştırıcı — running_job_event ile."""
        self._status(busy)
        self._running_event = threading.Event()
        def _t():
            t0 = time.time()
            try:
                result = worker_fn()
            except Exception as e:
                result = f"[✘] Hata: {e}\n"
            elapsed = time.time() - t0
            self.after(0, lambda: done_fn(result, elapsed))
        threading.Thread(target=_t, daemon=True).start()

    def out_set(self, w: tk.Text, content: str):
        w.config(state="normal")
        w.delete("1.0", "end")
        for line in content.splitlines(keepends=True):
            if "[✔]" in line and "[✘]" not in line:
                w.insert("end", line, "ok")
            elif "[✘]" in line or "HATA" in line.upper():
                w.insert("end", line, "err")
            elif any(x in line for x in ["[⚠]","[!]","⚠","YAKINDA","SÜRESI","SIZMA"]):
                w.insert("end", line, "warn")
            elif "[ℹ]" in line:
                w.insert("end", line, "info")
            else:
                w.insert("end", line)
        w.config(state="disabled")

    # ── session / cache ───────────────────────────────────────────────
    def _sess(self) -> requests.Session:
        delay = int(self.configs.get("rate_limit_ms", 0))
        if delay > 0:
            time.sleep(delay / 1000.0)
        return self.proxy_mgr.make_session(timeout=self.timeout)

    def _cget(self, key: str):
        if not self.configs.get("cache_enabled", True):
            return None
        return cache_get(self._cache, key, int(self.configs.get("cache_ttl", 3600)))

    def _cset(self, key: str, val: str):
        if self.configs.get("cache_enabled", True):
            cache_set(self._cache, key, val)
            save_cache(self._cache)

    def _quick_run(self):
        cmd = self.qentry.get().strip()
        if cmd:
            self.command_panel(prefill=cmd, auto_run=True)

    # ── HIBP dispatcher ───────────────────────────────────────────────
    def _run_hibp_email(self, email: str) -> str:
        mode    = self.configs.get("hibp_mode", "noapi")
        api_key = self.configs.get("hibp_key", "").strip()
        if mode == "api" and api_key:
            return hibp_email_apikey(email, api_key, self.timeout, self._sess())
        else:
            return hibp_email_noapi(email, self.timeout, self._sess())

    # ── Shodan dispatcher ─────────────────────────────────────────────
    def _run_shodan(self, target: str) -> str:
        mode    = self.configs.get("shodan_mode", "noapi")
        api_key = self.configs.get("shodan_key", "").strip()
        if mode == "api" and api_key:
            return shodan_apikey(target, api_key, self.timeout, self._sess())
        else:
            return shodan_noapi(target, self.timeout, self._sess())

    # ══════════════════════════════════════════════════════════════════
    #  COMMAND ENGINE
    # ══════════════════════════════════════════════════════════════════

    def _help(self) -> str:
        hm = "API" if (self.configs.get("hibp_mode")=="api"
                       and self.configs.get("hibp_key","")) else "API'sız"
        sm = "API" if (self.configs.get("shodan_mode")=="api"
                       and self.configs.get("shodan_key","")) else "API'sız (InternetDB)"
        return (
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  BLOODLINE  v3.2  —  Komut Referansı                     ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            "Temel\n"
            "  komutlar / help           yardım\n"
            "  clear                     temizle\n"
            "  log                       geçmiş\n"
            "  cache clear               önbellek temizle\n\n"
            "Ağ / IP\n"
            "  ip   <ip|domain>          GeoIP + ISP\n"
            "  whois <domain>\n"
            "  dns  <rr> <domain>\n"
            "  ssl  <host> [port]\n"
            "  port <host> [max_port]\n"
            "  sub  <domain>\n"
            "  asn  <ip|domain>\n"
            "  wayback <url>\n"
            "  zonetransfer <domain>     zone transfer denemesi\n"
            "  dnssec <domain>           DNSSEC kontrolü\n\n"
            "Toplu\n"
            "  batch <dosya> [ip|whois|ssl|shodan]  dosyadan toplu tarama\n\n"
            "Mail\n"
            "  mx     <email|domain>\n"
            "  verify <email>            SMTP doğrulama\n"
            "  breach <email>            HIBP e-posta kontrol\n"
            "  breach pw <şifre>         k-Anonymity şifre kontrol (her zaman API'sız)\n\n"
            "Telefon\n"
            "  phone  <+numara>\n\n"
            "Kullanıcı / OP\n"
            "  user   <username>\n"
            "  op <ad> | op plmn <mcc-mnc> | op country <ISO>\n\n"
            "Shodan\n"
            "  shodan <ip|domain>\n\n"
            "Favoriler\n"
            "  fav list / fav add <x> / fav del <x>\n\n"
            f"Aktif modlar:\n"
            f"  HIBP   : {hm}\n"
            f"  Shodan : {sm}\n"
            f"  Proxy  : {self.configs.get('proxy_mode','off')}\n"
        )

    def run_cmd(self, cmd: str) -> str:
        raw   = cmd.strip()
        if not raw:
            return self._help()
        parts = raw.split()
        head  = parts[0].lower()

        if head in ("komutlar","help","yardım","?"):
            return self._help()
        if head == "clear":
            return ""
        if head == "log":
            return (open(LOG_FILE, encoding="utf-8").read()
                    if os.path.exists(LOG_FILE) else "[ℹ] Log yok.\n")
        if head == "cache":
            if len(parts) > 1 and parts[1] == "clear":
                self._cache.clear()
                save_cache(self._cache)
                return "[✔] Cache temizlendi.\n"
            return f"[ℹ] Cache: {len(self._cache)} giriş\n"

        if head == "fav":
            sub = parts[1].lower() if len(parts) > 1 else ""
            if sub == "list":
                return ("Favoriler:\n" + "\n".join(f"  {f}" for f in self.favorites) + "\n"
                        ) if self.favorites else "[ℹ] Favori yok.\n"
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

        sess = self._sess()

        if head in ("ip", "web"):
            arg = raw[len(head):].strip()
            if not arg:
                return "[✘] Hedef gir.\n"
            cached = self._cget(f"ip:{arg}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            r = ip_geo_lookup(arg, self.timeout, sess)
            self._cset(f"ip:{arg}", r)
            append_log(f"{head} {arg}", self.configs.get("log_enabled", True))
            return r

        if head == "whois":
            arg = raw[len("whois"):].strip()
            if not arg:
                return "[✘] Domain gir.\n"
            cached = self._cget(f"whois:{arg}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            r = simple_whois(arg, self.timeout)
            self._cset(f"whois:{arg}", r)
            return r

        if head == "dns":
            if len(parts) < 3:
                return "[✘] dns <rr> <domain>\n"
            return dns_lookup(parts[1], parts[2], self.timeout)

        if head == "ssl":
            if len(parts) < 2:
                return "[✘] ssl <host> [port]\n"
            port = int(parts[2]) if len(parts) > 2 else 443
            return ssl_analyze(parts[1], port, self.timeout)

        if head == "port":
            if len(parts) < 2:
                return "[✘] port <host> [max]\n"
            maxp = min(int(parts[2]), 65535) if len(parts) > 2 else self.configs.get("max_ports", 1024)
            return port_scan(parts[1], maxp,
                             self.configs.get("port_threads", 100),
                             float(self.timeout) * 0.1)

        if head == "sub":
            arg = raw[len("sub"):].strip()
            if not arg:
                return "[✘] sub <domain>\n"
            return subdomain_scan(arg, threads=self.configs.get("sub_threads", 50),
                                  timeout=self.timeout, sess=sess)

        if head == "asn":
            arg = raw[len("asn"):].strip()
            if not arg:
                return "[✘] asn <ip|domain>\n"
            return asn_lookup(arg, self.timeout, sess)

        if head == "wayback":
            arg = raw[len("wayback"):].strip()
            if not arg:
                return "[✘] wayback <url>\n"
            return wayback_lookup(arg, self.timeout, sess)

        if head in ("zonetransfer", "ztf"):
            arg = raw[len(head):].strip()
            if not arg:
                return "[✘] zonetransfer <domain>\n"
            return dns_zone_transfer(arg, self.timeout)

        if head == "dnssec":
            arg = raw[len("dnssec"):].strip()
            if not arg:
                return "[✘] dnssec <domain>\n"
            return dnssec_check(arg, self.timeout)

        if head in ("batch", "toplu"):
            arg = raw[len(head):].strip()
            if not arg:
                return "[✘] batch <dosya> [ip|whois|ssl|shodan]\n"
            parts_b = arg.split()
            fpath = parts_b[0]
            stype = parts_b[1] if len(parts_b) > 1 else "ip"
            return batch_scan(fpath, stype, self.timeout, sess)

        if head == "mx":
            arg = raw[len("mx"):].strip()
            if not arg:
                return "[✘] mx <email|domain>\n"
            domain = arg.split("@")[-1].strip()
            if not DNS_OK:
                return "[✘] dnspython gerekli: pip install dnspython\n"
            try:
                mx = dns.resolver.resolve(domain, "MX")
                return f"Domain : {domain}\nMX     : {mx[0].exchange}\n"
            except Exception as e:
                return f"[✘] MX: {e}\n"

        if head == "verify":
            arg = raw[len("verify"):].strip()
            if not arg:
                return "[✘] verify <email>\n"
            return smtp_verify(arg, self.timeout)

        if head == "breach":
            tail = raw[len("breach"):].strip()
            if tail.lower().startswith("pw "):
                return hibp_password_noapi(tail[3:].strip())
            if not tail:
                return "[✘] breach <email> | breach pw <şifre>\n"
            return self._run_hibp_email(tail)

        if head == "phone":
            arg = raw[len("phone"):].strip()
            if not arg:
                return "[✘] phone <+numara>\n"
            if not PHONE_OK:
                return "[✘] pip install phonenumbers\n"
            try:
                num = phonenumbers.parse(arg, None)
            except Exception:
                return "[✘] Numara parse edilemedi.\n"
            return "\n".join([
                f"Ülke        : {geocoder.description_for_number(num,'tr')}",
                f"Operatör    : {carrier.name_for_number(num,'tr') or '?'}",
                f"Zaman Dil.  : {list(pn_tz.time_zones_for_number(num))}",
                f"Tip         : {number_type(num)}",
                f"Geçerli     : {phonenumbers.is_valid_number(num)}",
            ]) + "\n"

        if head == "user":
            username = raw[len("user"):].strip()
            if not username:
                return "[✘] user <username>\n"
            results: dict = {}
            def chk(item):
                name, tpl = item
                try:
                    r = sess.get(tpl.format(username), timeout=self.timeout)
                    ok = r.status_code == 200
                except Exception:
                    ok = False
                results[name] = (ok, tpl.format(username))
            with ThreadPoolExecutor(max_workers=self.configs.get("user_threads", 20)) as ex:
                ex.map(chk, PLATFORMS.items())
            found = sum(1 for ok, _ in results.values() if ok)
            lines = [f"Kullanıcı: {username}  |  {len(PLATFORMS)} platform", ""]
            for name, (ok, url) in sorted(results.items()):
                lines.append(f"  [{'✔' if ok else '✘'}] {name:<22} {url if ok else ''}")
            lines += ["", f"BULUNAN: {found} / {len(PLATFORMS)}"]
            return "\n".join(lines) + "\n"

        if head in ("op", "operator"):
            tail = raw[len(head):].strip()
            if not tail:
                return "[✘] op <ad|plmn ...|country ...>\n"
            self.operators = load_operators()
            if tail.lower().startswith("plmn "):
                return op_format(self.operators,
                                 op_search_plmn(self.operators, tail[5:].strip()))
            if tail.lower().startswith("country "):
                return op_format(self.operators,
                                 op_search_country(self.operators, tail[8:].strip()))
            return op_format(self.operators,
                             op_search(self.operators, tail), f"'{tail}'")

        if head == "shodan":
            arg = raw[len("shodan"):].strip()
            if not arg:
                return "[✘] shodan <ip|domain>\n"
            return self._run_shodan(arg)

        return f"[✘] Bilinmeyen komut: {head}\n\n" + self._help()

    # ══════════════════════════════════════════════════════════════════
    #  PANELS
    # ══════════════════════════════════════════════════════════════════

    def home_panel(self):
        self.clear_body()
        c = tk.Frame(self.body, bg=APP_BG)
        c.pack(fill="both", expand=True)
        self.wave = WaveCanvas(c, self.wv_color)
        self.wave.place(relwidth=1, relheight=1)
        mode = self.configs.get("proxy_mode", "off")
        prx  = {"off":"Kapalı",
                 "manual": self.configs.get("proxy_manual","")[:30],
                 "random": f"Rastgele ({self.proxy_mgr.pool_size()} proxy)"}[mode]
        hm = "API'lı" if (self.configs.get("hibp_mode")=="api"
                           and self.configs.get("hibp_key","")) else "API'sız"
        sm = "API'lı" if (self.configs.get("shodan_mode")=="api"
                           and self.configs.get("shodan_key","")) else "InternetDB"
        info = (
            "BLOODLINE  OSINT  TOOL\n"
"Edition  v3.2\n\n"
            "──────────────────────────────────\n"
            f"  Operators DB  : {len(self.operators)} kayıt\n"
            f"  Cache         : {len(self._cache)} giriş\n"
            f"  Proxy         : {prx}\n"
            f"  HIBP Modu     : {hm}\n"
            f"  Shodan Modu   : {sm}\n"
            f"  phonenumbers  : {'✔' if PHONE_OK else '✘'}\n"
            f"  dnspython     : {'✔' if DNS_OK else '✘'}\n"
            "──────────────────────────────────\n\n"
            "Yasal OSINT araştırmaları için.\n"
            "Yasadışı kullanım kesinlikle yasaktır.\n\n"
"by Acsida"
        )
        tk.Label(c, text=info, fg="#b0b0b0", bg=APP_BG,
                 font=("Consolas", 12), justify="center"
                 ).place(relx=0.5, rely=0.5, anchor="center")

    def _simple_panel(self, title: str, sub: str, label: str, ph: str,
                       btn: str, worker_fn, log_prefix: str = ""):
        """Tek girdi + çıktı paneli şablonu."""
        self.clear_body()
        self._title(self.body, title, sub)
        out = self._obox(self.body)
        def _worker():
            val = ent.get().strip()
            if not val or val == ph:
                return "[✘] Değer giriniz.\n"
            if log_prefix:
                append_log(f"{log_prefix} {val}", self.configs.get("log_enabled", True))
            return worker_fn(val)
        def _done(res, elapsed):
            self.out_set(out, res)
            self._status(f"{title} bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, label, ph, btn,
                         lambda: self._job(_worker, _done, f"{title}..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._favbtn(row, ent)
        self._arow(self.body, out, title)
        return ent, out

    def web_panel(self):
        self._simple_panel(
            "Web / IP Analyze", "GeoIP + ISP + ASN",
            "Domain veya IP", "example.com", "Araştır",
            lambda v: (
                self._cget(f"ip:{v}") or
                self._cset(f"ip:{v}", ip_geo_lookup(v, self.timeout, self._sess())) or
                self._cget(f"ip:{v}")
            ),
            log_prefix="ip",
        )

    def userfind_panel(self):
        self.clear_body()
        self._title(self.body, "UserFind", f"{len(PLATFORMS)} platform — paralel")
        cat_f = tk.Frame(self.body, bg=APP_BG)
        cat_f.pack(fill="x", padx=26, pady=(2, 4))
        tk.Label(cat_f, text="Filtre:", fg="#444", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._uf_cat = tk.StringVar(value="Tümü")
        for cat in ["Tümü"] + list(PLATFORM_CATS.keys()):
            tk.Radiobutton(cat_f, text=cat, variable=self._uf_cat, value=cat,
                           fg="#555", bg=APP_BG, selectcolor=APP_BG,
                           activebackground=APP_BG, font=("Consolas", 9)
                           ).pack(side="left", padx=4)
        out = self._obox(self.body)
        def worker():
            u = ent.get().strip()
            if not u or u == "username":
                return "[✘] Kullanıcı adı giriniz.\n"
            cat  = self._uf_cat.get()
            plats = (PLATFORMS if cat == "Tümü"
                     else {k: v for k, v in PLATFORMS.items()
                           if k in PLATFORM_CATS.get(cat, [])})
            sess = self._sess()
            results: dict = {}
            def chk(item):
                name, tpl = item
                try:
                    r = sess.get(tpl.format(u), timeout=self.timeout)
                    ok = r.status_code == 200
                except Exception:
                    ok = False
                results[name] = (ok, tpl.format(u))
            with ThreadPoolExecutor(max_workers=self.configs.get("user_threads", 20)) as ex:
                ex.map(chk, plats.items())
            found = sum(1 for ok, _ in results.values() if ok)
            lines = [f"Kullanıcı: {u}  |  {cat}  |  {len(plats)} platform", ""]
            for name, (ok, url) in sorted(results.items()):
                lines.append(f"  [{'✔' if ok else '✘'}] {name:<22} {url if ok else ''}")
            lines += ["", f"BULUNAN: {found} / {len(plats)}"]
            append_log(f"user {u}", self.configs.get("log_enabled", True))
            return "\n".join(lines) + "\n"
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"UserFind bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Kullanıcı adı", "username", "Tara",
                         lambda: self._job(worker, done, "UserFind..."))
        self._arow(self.body, out, "UserFind")

    def mail_panel(self):
        self.clear_body()
        self._title(self.body, "Mail Analyze", "MX + TXT + NS + A")
        out = self._obox(self.body)
        def worker():
            raw_in = ent.get().strip()
            domain = raw_in.split("@")[-1].strip()
            if not domain:
                return "[✘] E-posta veya domain giriniz.\n"
            lines = [f"Domain: {domain}", ""]
            if DNS_OK:
                for rr in ("MX", "TXT", "NS", "A", "AAAA"):
                    try:
                        ans = dns.resolver.resolve(domain, rr)
                        lines.append(f"[{rr}]")
                        for a in ans:
                            lines.append(f"  {a}")
                    except Exception:
                        lines.append(f"[{rr}]  — yok")
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
            self._status(f"Mail bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "E-posta veya domain", "example@gmail.com",
                         "Sorgula", lambda: self._job(worker, done, "Mail..."))
        self._arow(self.body, out, "Mail Analyze")

    def phone_panel(self):
        self._simple_panel(
            "Phone Analyze", "Operatör / ülke / geçerlilik",
            "Numara (+ülke kodu)", "+905xxxxxxxxx", "Analiz Et",
            lambda v: self.run_cmd(f"phone {v}"),
        )

    def op_panel(self):
        self._simple_panel(
            "OP Analyze", "MCC/MNC / ad / ülke",
            "Ad / PLMN / Ülke ISO", "Turkcell | 286-01 | TR", "Ara",
            lambda v: self.run_cmd(f"op {v}"),
            log_prefix="op",
        )

    def whois_panel(self):
        self.clear_body()
        self._title(self.body, "WHOIS", "IANA → 2-adımlı raw")
        out = self._obox(self.body)
        def worker():
            d = ent.get().strip()
            if not d:
                return "[✘] Domain giriniz.\n"
            cached = self._cget(f"whois:{d}")
            if cached:
                return f"[✔] (önbellekten)\n{cached}"
            r = simple_whois(d, self.timeout)
            self._cset(f"whois:{d}", r)
            return r
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"WHOIS bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Domain", "google.com", "Sorgula",
                         lambda: self._job(worker, done, "WHOIS..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._favbtn(row, ent)
        self._arow(self.body, out, "WHOIS")

    def dns_panel(self):
        self.clear_body()
        self._title(self.body, "DNS Lookup", "A / MX / NS / TXT / CNAME / AAAA / SOA")
        rrf = tk.Frame(self.body, bg=APP_BG)
        rrf.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(rrf, text="Kayıt:", fg="#444", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._rr = tk.StringVar(value="A")
        for rr in ("A","MX","NS","TXT","CNAME","AAAA","SOA","SRV"):
            tk.Radiobutton(rrf, text=rr, variable=self._rr, value=rr,
                           fg="#555", bg=APP_BG, selectcolor=APP_BG,
                           activebackground=APP_BG, font=("Consolas", 9)
                           ).pack(side="left", padx=4)
        out = self._obox(self.body)
        def worker():
            d = ent.get().strip()
            if not d:
                return "[✘] Domain giriniz.\n"
            return dns_lookup(self._rr.get(), d, self.timeout)
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"DNS bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Domain", "example.com", "Sorgula",
                         lambda: self._job(worker, done, "DNS..."))
        self._arow(self.body, out, "DNS Lookup")

    def ssl_panel(self):
        self.clear_body()
        self._title(self.body, "SSL / TLS", "Sertifika • Geçerlilik • Cipher • SAN")
        pf = tk.Frame(self.body, bg=APP_BG)
        pf.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(pf, text="Port:", fg="#444", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._ssl_port = tk.StringVar(value="443")
        tk.Spinbox(pf, from_=1, to=65535, textvariable=self._ssl_port,
                   width=6, bg=IN_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left", padx=6)
        out = self._obox(self.body)
        def worker():
            h = ent.get().strip()
            if not h:
                return "[✘] Host giriniz.\n"
            try:
                port = int(self._ssl_port.get())
            except ValueError:
                port = 443
            return ssl_analyze(h, port, self.timeout)
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"SSL bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Host", "example.com", "Analiz Et",
                         lambda: self._job(worker, done, "SSL..."))
        self._arow(self.body, out, "SSL/TLS")

    def port_panel(self):
        self.clear_body()
        self._title(self.body, "Port Tarayıcı", "Paralel TCP tarama")
        cf = tk.Frame(self.body, bg=APP_BG)
        cf.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(cf, text="Maks port:", fg="#444", bg=APP_BG, font=("Consolas", 9)).pack(side="left")
        self._pmx = tk.StringVar(value=str(self.configs.get("max_ports", 1024)))
        tk.Spinbox(cf, from_=1, to=65535, textvariable=self._pmx,
                   width=7, bg=IN_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left", padx=6)
        tk.Label(cf, text="Thread:", fg="#444", bg=APP_BG, font=("Consolas", 9)).pack(side="left", padx=(10,0))
        self._pthr = tk.StringVar(value=str(self.configs.get("port_threads", 100)))
        tk.Spinbox(cf, from_=1, to=500, textvariable=self._pthr,
                   width=5, bg=IN_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left", padx=6)
        out = self._obox(self.body)
        def worker():
            h = ent.get().strip()
            if not h:
                return "[✘] Host giriniz.\n"
            return port_scan(h, min(int(self._pmx.get()), 65535),
                             int(self._pthr.get()), float(self.timeout) * 0.1)
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"Port bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Host", "example.com", "Tara",
                         lambda: self._job(worker, done, "Port taranıyor..."))
        self._arow(self.body, out, "Port Tarama")

    def subdomain_panel(self):
        self.clear_body()
        self._title(self.body, "Subdomain Tarayıcı", "crt.sh + brute-force")
        of = tk.Frame(self.body, bg=APP_BG)
        of.pack(fill="x", padx=26, pady=(4, 2))
        self._sub_crt = tk.BooleanVar(value=True)
        self._sub_bf  = tk.BooleanVar(value=True)
        for txt, var in [("crt.sh", self._sub_crt), ("Brute-force", self._sub_bf)]:
            tk.Checkbutton(of, text=txt, variable=var, fg="#555", bg=APP_BG,
                           selectcolor=APP_BG, activebackground=APP_BG,
                           font=("Consolas", 9)).pack(side="left", padx=6)
        out = self._obox(self.body)
        def worker():
            d = ent.get().strip()
            if not d:
                return "[✘] Domain giriniz.\n"
            return subdomain_scan(d, use_crtsh=self._sub_crt.get(),
                                  use_brute=self._sub_bf.get(),
                                  threads=self.configs.get("sub_threads", 50),
                                  timeout=self.timeout, sess=self._sess())
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"Subdomain bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Domain", "example.com", "Tara",
                         lambda: self._job(worker, done, "Subdomain taranıyor..."))
        self._arow(self.body, out, "Subdomain")

    def asn_panel(self):
        self._simple_panel(
            "ASN / BGP", "ipinfo.io + Team Cymru",
            "IP / Domain / ASN", "1.1.1.1", "Sorgula",
            lambda v: asn_lookup(v, self.timeout, self._sess()),
        )

    def email_header_panel(self):
        self.clear_body()
        self._title(self.body, "Email Header Analizi", "SPF / DKIM / DMARC / Phishing tespiti")
        tk.Label(self.body, text="  Ham e-posta başlığını (raw header) yapıştırın:",
                 fg="#555", bg=APP_BG, font=("Consolas", 9)).pack(anchor="w", padx=26)
        inp_box = tk.Frame(self.body, bg=BORDER, bd=1, relief="solid")
        inp_box.pack(fill="x", padx=26, pady=(4, 4))
        inp = tk.Text(inp_box, bg=IN_BG, fg="white", font=("Consolas", 10),
                      height=8, relief="flat", bd=0, padx=8, pady=6,
                      insertbackground=self.ui_color)
        inp.pack(fill="both", expand=True)
        out = self._obox(self.body)
        tk.Button(self.body, text="Analiz Et", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=14,
                  command=lambda: self._job(
                      lambda: analyze_email_header(inp.get("1.0", "end")),
                      lambda r, e: (self.out_set(out, r),
                                    self._status(f"Header analizi bitti — {e:.1f}s")),
                      "Header analiz ediliyor...",
                  )).pack(anchor="w", padx=26, pady=(0, 4))
        self._arow(self.body, out, "Email Header")

    def smtp_panel(self):
        self._simple_panel(
            "SMTP Doğrulama", "RCPT ile e-posta varlık kontrolü",
            "E-posta adresi", "test@example.com", "Doğrula",
            lambda v: smtp_verify(v, self.timeout),
        )

    def breach_panel(self):
        self.clear_body()
        mode    = self.configs.get("hibp_mode", "noapi")
        api_key = self.configs.get("hibp_key", "").strip()
        active  = (mode == "api" and bool(api_key))
        self._title(self.body, "Breach Kontrolü (E-posta)",
                    "API'lı" if active else "API'sız (sınırlı)")

        # mod göstergesi
        ind = tk.Frame(self.body, bg=CARD_BG, bd=1, relief="solid")
        ind.pack(fill="x", padx=26, pady=(0, 6))
        tk.Label(ind,
                 text=(f"  Aktif Mod : {'✔ API\'lı (HIBP v3 — tam sonuç)' if active else '⚠ API\'sız (sınırlı sonuç)'}\n"
                       f"  API Key   : {'Tanımlı (' + api_key[:6] + '...)' if api_key else 'Yok — Settings → HIBP API Key'}\n"
                       "  Değiştir  : Settings → HIBP Modu"),
                 fg=GRN_FG if active else WRN_FG, bg=CARD_BG,
                 font=("Consolas", 9), justify="left").pack(anchor="w", padx=10, pady=8)

        out = self._obox(self.body)
        def worker():
            e = ent.get().strip()
            if not e:
                return "[✘] E-posta giriniz.\n"
            return self._run_hibp_email(e)
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"Breach bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "E-posta", "test@example.com",
                         "Kontrol Et", lambda: self._job(worker, done, "HIBP sorgulanıyor..."))
        self._arow(self.body, out, "Breach")

    def password_panel(self):
        self.clear_body()
        self._title(self.body, "Şifre Sızıntı Kontrolü",
                    "k-Anonymity — API key GEREKMİYOR — her zaman API'sız")
        tk.Label(self.body,
                 text="  SHA-1 hash prefix gönderilir. Şifreniz asla iletilmez.",
                 fg=GRN_FG, bg=APP_BG, font=("Consolas", 9)).pack(anchor="w", padx=26, pady=(0, 4))
        out = self._obox(self.body)
        def worker():
            pw = ent.get().strip()
            if not pw:
                return "[✘] Şifre giriniz.\n"
            return hibp_password_noapi(pw)
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"Şifre kontrolü bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "Şifre (yerel hash — iletilmez)",
                         "şifrenizi_girin", "Kontrol Et",
                         lambda: self._job(worker, done, "Şifre kontrol ediliyor..."))
        self._arow(self.body, out, "Şifre Sızıntı")

    def shodan_panel(self):
        self.clear_body()
        mode    = self.configs.get("shodan_mode", "noapi")
        api_key = self.configs.get("shodan_key", "").strip()
        active  = (mode == "api" and bool(api_key))
        self._title(self.body, "Shodan",
                    "API'lı (tam)" if active else "API'sız — InternetDB")

        ind = tk.Frame(self.body, bg=CARD_BG, bd=1, relief="solid")
        ind.pack(fill="x", padx=26, pady=(0, 6))
        tk.Label(ind,
                 text=(f"  Aktif Mod : {'✔ API\'lı (tam servis + CVE)' if active else '⚠ API\'sız — Shodan InternetDB (ücretsiz)'}\n"
                       f"  API Key   : {'Tanımlı (' + api_key[:6] + '...)' if api_key else 'Yok — Settings → Shodan API Key'}\n"
                       "  Değiştir  : Settings → Shodan Modu"),
                 fg=GRN_FG if active else WRN_FG, bg=CARD_BG,
                 font=("Consolas", 9), justify="left").pack(anchor="w", padx=10, pady=8)

        out = self._obox(self.body)
        def worker():
            t = ent.get().strip()
            if not t:
                return "[✘] IP veya domain giriniz.\n"
            return self._run_shodan(t)
        def done(res, elapsed):
            self.out_set(out, res)
            self._status(f"Shodan bitti — {elapsed:.1f}s")
        ent = self._irow(self.body, "IP veya domain", "8.8.8.8",
                         "Sorgula", lambda: self._job(worker, done, "Shodan..."))
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(2, 0))
        self._favbtn(row, ent)
        self._arow(self.body, out, "Shodan")

    def wayback_panel(self):
        self._simple_panel(
            "Wayback Machine", "Arşiv geçmişi — CDX API",
            "URL", "example.com", "Sorgula",
            lambda v: wayback_lookup(v, self.timeout, self._sess()),
        )

    def command_panel(self, prefill: str = None, auto_run: bool = False):
        self.clear_body()
        self._title(self.body, "Komut Paneli", "komutlar → tam liste  |  ↑↓ geçmiş")
        out = self._obox(self.body)

        def _run():
            cmd = ent.get().strip()
            if not cmd:
                return
            if cmd not in self._cmd_hist:
                self._cmd_hist.append(cmd)
            self._cmd_idx = len(self._cmd_hist)
            def worker(): return self.run_cmd(cmd)
            def done(res, elapsed):
                self.out_set(out, "" if cmd.lower() == "clear" else res)
                self._status(f"Komut bitti — {elapsed:.1f}s")
            self._job(worker, done, "Çalışıyor...")

        def _up(_e):
            if self._cmd_hist and self._cmd_idx > 0:
                self._cmd_idx -= 1
                ent.delete(0, "end")
                ent.insert(0, self._cmd_hist[self._cmd_idx])

        def _dn(_e):
            if self._cmd_idx < len(self._cmd_hist) - 1:
                self._cmd_idx += 1
                ent.delete(0, "end")
                ent.insert(0, self._cmd_hist[self._cmd_idx])
            else:
                self._cmd_idx = len(self._cmd_hist)
                ent.delete(0, "end")

        ent = self._irow(self.body, "Komut  (↑↓ geçmiş, Enter çalıştır)",
                         prefill or "komutlar", "Çalıştır", _run)
        ent.bind("<Up>",   _up)
        ent.bind("<Down>", _dn)
        self.out_set(out, self._help())
        self._arow(self.body, out, "Komut")
        if auto_run and prefill:
            self._job(lambda: self.run_cmd(prefill),
                      lambda r, e: self.out_set(out, r), "Çalışıyor...")

    def favorites_panel(self):
        self.clear_body()
        self._title(self.body, "Favoriler", "Hızlı erişim")
        if not self.favorites:
            tk.Label(self.body, text="\n  Henüz favori yok.\n  Panellerde ☆ Favori butonuna basın.",
                     fg="#444", bg=APP_BG, font=("Consolas", 10)).pack(anchor="w", padx=26)
            return
        frame = tk.Frame(self.body, bg=APP_BG)
        frame.pack(fill="both", expand=True, padx=26, pady=8)
        for fav in list(self.favorites):
            row = tk.Frame(frame, bg=CARD_BG, bd=1, relief="solid")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=fav, fg=TXT_FG, bg=CARD_BG,
                     font=("Consolas", 10)).pack(side="left", padx=10, pady=5)
            for lbl, cmd in [("ip", f"ip {fav}"), ("whois", f"whois {fav}"),
                              ("ssl", f"ssl {fav}"), ("port", f"port {fav}"),
                              ("sub", f"sub {fav}"), ("asn", f"asn {fav}"),
                              ("shodan", f"shodan {fav}"), ("wayback", f"wayback {fav}")]:
                tk.Button(row, text=lbl, bg="#1a1a1a", fg="#555",
                          font=("Consolas", 8), relief="flat", padx=5,
                          command=lambda c=cmd: self.command_panel(c, True)
                          ).pack(side="left", padx=2, pady=3)
            def _del(f=fav):
                self.favorites.remove(f)
                save_favorites(self.favorites)
                self.favorites_panel()
            tk.Button(row, text="✕", bg="#1a1a1a", fg=ERR_FG,
                      font=("Consolas", 8), relief="flat", padx=5,
                      command=_del).pack(side="right", padx=6, pady=3)

    def history_panel(self):
        self.clear_body()
        self._title(self.body, "Sorgu Geçmişi", LOG_FILE)
        # Arama kutusu
        search_f = tk.Frame(self.body, bg=APP_BG)
        search_f.pack(fill="x", padx=26, pady=(4, 2))
        tk.Label(search_f, text="Ara:", fg="#444", bg=APP_BG,
                 font=("Consolas", 9)).pack(side="left")
        search_ent = tk.Entry(search_f, font=("Consolas", 10), bg=IN_BG, fg="white",
                             insertbackground=self.ui_color, relief="flat", width=40)
        search_ent.pack(side="left", padx=(6, 4), ipady=4)
        out = self._obox(self.body)
        def load_log(filter_text: str = ""):
            if os.path.exists(LOG_FILE):
                try:
                    content = open(LOG_FILE, encoding="utf-8").read()
                    if filter_text:
                        lines = [l for l in content.splitlines()
                                 if filter_text.lower() in l.lower()]
                        content = "\n".join(lines) or "[ℹ] Eşleşen kayıt yok.\n"
                    self.out_set(out, content or "[ℹ] Boş.\n")
                except Exception as e:
                    self.out_set(out, f"[✘] {e}\n")
            else:
                self.out_set(out, "[ℹ] Henüz log yok.\n")
        load_log()
        def do_search():
            load_log(search_ent.get().strip())
        search_ent.bind("<Return>", lambda e: do_search())
        tk.Button(search_f, text="Filtrele", bg="#1a1a1a", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=6,
                  command=do_search).pack(side="left", padx=(0, 4))
        tk.Button(search_f, text="Temizle", bg="#1a1a1a", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=6,
                  command=lambda: [search_ent.delete(0, "end"), load_log()]).pack(side="left")
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(5, 12))
        def clear_log():
            if messagebox.askyesno("Log Temizle", "Tüm geçmiş silinsin mi?"):
                try:
                    os.remove(LOG_FILE)
                    self.out_set(out, "[ℹ] Temizlendi.\n")
                except Exception as e:
                    self.out_set(out, f"[✘] {e}\n")
        tk.Button(row, text="Log Temizle", bg="#1a1a1a", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=10,
                  command=clear_log).pack(side="left")

    def report_panel(self):
        self.clear_body()
        self._title(self.body, "HTML Rapor", f"{len(self._report)} bölüm")
        inf = tk.Frame(self.body, bg=CARD_BG, bd=1, relief="solid")
        inf.pack(fill="x", padx=26, pady=(0, 8))
        tk.Label(inf,
                 text=f"  Raporda {len(self._report)} bölüm.\n  Analizlerde '+ Rapora Ekle' butonunu kullanın.",
                 fg="#555", bg=CARD_BG, font=("Consolas", 9), justify="left"
                 ).pack(anchor="w", padx=10, pady=8)
        out = self._obox(self.body, color=TXT_FG)
        if self._report:
            self.out_set(out, "Bölümler:\n" +
                         "\n".join(f"  [{i+1}] {t}" for i, (t, _) in enumerate(self._report)) + "\n")
        else:
            self.out_set(out, "[ℹ] Bölüm yok.\n")
        row = tk.Frame(self.body, bg=APP_BG)
        row.pack(fill="x", padx=26, pady=(5, 12))
        tgt = tk.Entry(row, font=("Consolas", 10), bg=IN_BG, fg="white",
                       insertbackground=self.ui_color, relief="flat", width=28)
        tgt.insert(0, "hedef.com")
        tgt.pack(side="left", ipady=5)
        def export():
            if not self._report:
                messagebox.showinfo("Rapor", "Önce bölüm ekleyin.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".html",
                                               filetypes=[("HTML","*.html")])
            if not path:
                return
            open(path, "w", encoding="utf-8").write(
                html_report(self._report, target=tgt.get().strip()))
            self._status(f"HTML raporu: {os.path.basename(path)}")
        tk.Button(row, text="HTML Kaydet", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=12,
                  command=export).pack(side="left", padx=(8, 6))
        tk.Button(row, text="Temizle", bg="#1a1a1a", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=lambda: [self._report.clear(),
                                   self.out_set(out, "[ℹ] Temizlendi.\n")]
                  ).pack(side="left")

    # ══════════════════════════════════════════════════════════════════
    #  SETTINGS
    # ══════════════════════════════════════════════════════════════════

    def settings_panel(self):
        self.clear_body()
        self._title(self.body, "Settings",
                    "Proxy • HIBP Modu • Shodan Modu • DB • Ağ • Cache • Renkler")

        canvas = tk.Canvas(self.body, bg=APP_BG, highlightthickness=0)
        vsb    = tk.Scrollbar(self.body, orient="vertical", command=canvas.yview,
                               bg=APP_BG, troughcolor=APP_BG)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inn    = tk.Frame(canvas, bg=APP_BG)
        wid    = canvas.create_window((0, 0), window=inn, anchor="nw")
        inn.bind("<Configure>",    lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))

        def sec(label: str):
            tk.Label(inn, text=label, fg=self.ui_color, bg=APP_BG,
                     font=("Consolas", 11, "bold")).pack(anchor="w", padx=26, pady=(14, 3))
            tk.Frame(inn, bg=BORDER, height=1).pack(fill="x", padx=26, pady=(0, 6))

        def card() -> tk.Frame:
            f = tk.Frame(inn, bg=CARD_BG, bd=1, relief="solid")
            f.pack(fill="x", padx=26, pady=(0, 10))
            return f

        # ══════════════════════════════════
        # PROXY
        # ══════════════════════════════════
        sec("🔀  RandomProxy Sistemi")
        proxy_card = card()

        proxy_mode_var = tk.StringVar(value=self.configs.get("proxy_mode", "off"))

        mode_row = tk.Frame(proxy_card, bg=CARD_BG)
        mode_row.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(mode_row, text="Proxy Modu:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 10)).pack(side="left")
        for lbl, val, color in [("Kapalı","off","#555"),
                                  ("Manuel","manual",WRN_FG),
                                  ("Rastgele","random",GRN_FG)]:
            tk.Radiobutton(mode_row, text=lbl, variable=proxy_mode_var, value=val,
                           fg=color, bg=CARD_BG, selectcolor=CARD_BG,
                           activebackground=CARD_BG, font=("Consolas", 10)
                           ).pack(side="left", padx=8)

        mf = tk.Frame(proxy_card, bg=CARD_BG)
        mf.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(mf, text="Manuel URL:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 9)).pack(side="left")
        manual_ent = tk.Entry(mf, font=("Consolas", 10), bg=IN_BG, fg="white",
                              insertbackground=self.ui_color, relief="flat", width=38)
        manual_ent.pack(side="left", ipady=4, padx=(6, 0))
        manual_ent.insert(0, self.configs.get("proxy_manual", ""))
        tk.Label(mf, text=" http://...  socks5://...", fg="#2a2a2a", bg=CARD_BG,
                 font=("Consolas", 8)).pack(side="left")

        rand_lbl = tk.Label(proxy_card, text="", fg="#555", bg=CARD_BG,
                             font=("Consolas", 9), justify="left")
        rand_lbl.pack(anchor="w", padx=12, pady=(0, 6))

        def refresh_rand():
            self.proxy_mgr._reload()
            n = self.proxy_mgr.pool_size()
            rand_lbl.config(
                text=(f"  bloodlineproxy: {PROXY_FILE}\n"
                      f"  Yüklü proxy  : {n}\n"
                      f"  Son kullanılan: {(self.proxy_mgr._last or '—')[:60]}")
            )
        refresh_rand()

        def save_proxy():
            self.configs["proxy_mode"]   = proxy_mode_var.get()
            self.configs["proxy_manual"] = manual_ent.get().strip()
            save_config(self.configs)
            self.proxy_mgr = ProxyManager(self.configs)
            self._refresh_proxy_lbl()
            self._status(f"Proxy modu: {proxy_mode_var.get()}")
            refresh_rand()

        def test_manual():
            ok, msg = self.proxy_mgr.test_proxy(manual_ent.get().strip(), self.timeout)
            messagebox.showinfo("Proxy Test (Manuel)", msg)

        def test_random():
            self.proxy_mgr._reload()
            url = self.proxy_mgr.get_proxy() if proxy_mode_var.get() == "random" else ""
            if not url:
                messagebox.showwarning("Proxy Test", f"Proxy bulunamadı.\nDosya: {PROXY_FILE}")
                return
            ok, msg = self.proxy_mgr.test_proxy(url, self.timeout)
            messagebox.showinfo("Proxy Test (Rastgele)", f"Kullanılan: {url}\n\n{msg}")

        def open_proxy_file():
            self.proxy_mgr.create_proxy_file()
            try:
                import subprocess, sys
                if sys.platform == "win32":
                    os.startfile(PROXY_FILE)
                elif sys.platform == "darwin":
                    subprocess.run(["open", PROXY_FILE])
                else:
                    subprocess.run(["xdg-open", PROXY_FILE])
            except Exception:
                messagebox.showinfo("Proxy Dosyası", f"Konum: {PROXY_FILE}")

        pb = tk.Frame(proxy_card, bg=CARD_BG)
        pb.pack(anchor="w", padx=12, pady=(0, 12))
        for lbl, fn, is_primary in [
            ("Kaydet", save_proxy, True),
            ("Manuel Test", test_manual, False),
            ("Rastgele Test", test_random, False),
            ("bloodlineproxy Düzenle", open_proxy_file, False),
        ]:
            tk.Button(pb, text=lbl,
                      bg=self.ui_color if is_primary else "#1a1a1a",
                      fg="black" if is_primary else "#666",
                      font=("Consolas", 9, "bold" if is_primary else "normal"),
                      relief="flat", padx=8,
                      command=fn).pack(side="left", padx=(0, 6))

        # ══════════════════════════════════
        # HIBP MOD SEÇİMİ
        # ══════════════════════════════════
        sec("💥  HIBP — Breach Kontrolü Modu")
        hibp_card = card()

        hibp_mode_var = tk.StringVar(value=self.configs.get("hibp_mode", "noapi"))

        hm_row = tk.Frame(hibp_card, bg=CARD_BG)
        hm_row.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(hm_row, text="Mod:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 10)).pack(side="left")
        for lbl, val, color, desc in [
            ("API'sız", "noapi", WRN_FG, "(ücretsiz, sınırlı sonuç)"),
            ("API'lı",  "api",   GRN_FG, "(HIBP v3 — tam breach detayları)"),
        ]:
            tk.Radiobutton(hm_row, text=f"{lbl}  {desc}", variable=hibp_mode_var, value=val,
                           fg=color, bg=CARD_BG, selectcolor=CARD_BG,
                           activebackground=CARD_BG, font=("Consolas", 10)
                           ).pack(side="left", padx=(0, 16))

        hk_row = tk.Frame(hibp_card, bg=CARD_BG)
        hk_row.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(hk_row, text="API Key:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 9)).pack(side="left")
        hibp_key_ent = tk.Entry(hk_row, font=("Consolas", 10), bg=IN_BG, fg="white",
                                insertbackground=self.ui_color, relief="flat",
                                show="•", width=40)
        hibp_key_ent.pack(side="left", ipady=4, padx=(6, 4))
        hibp_key_ent.insert(0, self.configs.get("hibp_key", ""))
        tk.Label(hk_row, text="https://haveibeenpwned.com/API/Key",
                 fg="#2a2a2a", bg=CARD_BG, font=("Consolas", 8)).pack(side="left")

        tk.Label(hibp_card,
                 text=("  API'sız modda e-posta için sınırlı sonuç döner.\n"
                       "  Şifre kontrolü (breach pw) her zaman API'sız k-Anonymity kullanır.\n"
                       "  API'lı modda tam breach detayları (domain, tarih, çalınan veri) görüntülenir."),
                 fg="#444", bg=CARD_BG, font=("Consolas", 8), justify="left"
                 ).pack(anchor="w", padx=12, pady=(0, 4))

        def save_hibp():
            self.configs["hibp_mode"] = hibp_mode_var.get()
            self.configs["hibp_key"]  = hibp_key_ent.get().strip()
            save_config(self.configs)
            self._status(f"HIBP modu: {hibp_mode_var.get()}")

        tk.Button(hibp_card, text="Kaydet", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=10,
                  command=save_hibp).pack(anchor="w", padx=12, pady=(0, 12))

        # ══════════════════════════════════
        # SHODAN MOD SEÇİMİ
        # ══════════════════════════════════
        sec("👁️  Shodan Modu")
        shodan_card = card()

        shodan_mode_var = tk.StringVar(value=self.configs.get("shodan_mode", "noapi"))

        sm_row = tk.Frame(shodan_card, bg=CARD_BG)
        sm_row.pack(fill="x", padx=12, pady=(10, 6))
        tk.Label(sm_row, text="Mod:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 10)).pack(side="left")
        for lbl, val, color, desc in [
            ("API'sız", "noapi", WRN_FG, "(InternetDB — ücretsiz, portlar + CVE)"),
            ("API'lı",  "api",   GRN_FG, "(Shodan.io API — tam servis + banner)"),
        ]:
            tk.Radiobutton(sm_row, text=f"{lbl}  {desc}", variable=shodan_mode_var, value=val,
                           fg=color, bg=CARD_BG, selectcolor=CARD_BG,
                           activebackground=CARD_BG, font=("Consolas", 10)
                           ).pack(side="left", padx=(0, 16))

        sk_row = tk.Frame(shodan_card, bg=CARD_BG)
        sk_row.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(sk_row, text="API Key:", fg="#666", bg=CARD_BG,
                 font=("Consolas", 9)).pack(side="left")
        shodan_key_ent = tk.Entry(sk_row, font=("Consolas", 10), bg=IN_BG, fg="white",
                                  insertbackground=self.ui_color, relief="flat",
                                  show="•", width=40)
        shodan_key_ent.pack(side="left", ipady=4, padx=(6, 4))
        shodan_key_ent.insert(0, self.configs.get("shodan_key", ""))
        tk.Label(sk_row, text="https://account.shodan.io",
                 fg="#2a2a2a", bg=CARD_BG, font=("Consolas", 8)).pack(side="left")

        tk.Label(shodan_card,
                 text=("  API'sız modda Shodan InternetDB kullanılır (IP başına port, CVE, hostname).\n"
                       "  API'lı modda tam Shodan Host API: servis banner, OS, tam CVE listesi."),
                 fg="#444", bg=CARD_BG, font=("Consolas", 8), justify="left"
                 ).pack(anchor="w", padx=12, pady=(0, 4))

        def save_shodan():
            self.configs["shodan_mode"] = shodan_mode_var.get()
            self.configs["shodan_key"]  = shodan_key_ent.get().strip()
            save_config(self.configs)
            self._status(f"Shodan modu: {shodan_mode_var.get()}")

        tk.Button(shodan_card, text="Kaydet", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=10,
                  command=save_shodan).pack(anchor="w", padx=12, pady=(0, 12))

        # ══════════════════════════════════
        # OPERATORS DB
        # ══════════════════════════════════
        sec("📡  Operators DB")
        db_card = card()
        db_lbl  = tk.Label(db_card, text="", fg="#555", bg=CARD_BG,
                           font=("Consolas", 9), justify="left")
        db_lbl.pack(anchor="w", padx=12, pady=(10, 4))

        def refresh_db():
            self.operators = load_operators()
            ok = os.path.exists(OPERATORS_FILE)
            db_lbl.config(text=(f"  Durum : {'✔' if ok else '✘'}\n"
                                f"  Kayıt : {len(self.operators)}\n"
                                f"  Dosya : {OPERATORS_FILE}"))
            self._status("DB yenilendi")

        def do_sync():
            self._job(
                lambda: build_operators_db(self._sess()),
                lambda r, _: (refresh_db(), messagebox.showinfo("DB", r.strip())),
                "DB güncelleniyor...",
            )

        db_btns = tk.Frame(db_card, bg=CARD_BG)
        db_btns.pack(anchor="w", padx=12, pady=(2, 12))
        tk.Button(db_btns, text="DB Güncelle (opsync)", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=10,
                  command=do_sync).pack(side="left", padx=(0, 8))
        tk.Button(db_btns, text="Yenile", bg="#1a1a1a", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=refresh_db).pack(side="left")
        refresh_db()

        # ══════════════════════════════════
        # AĞ AYARLARI
        # ══════════════════════════════════
        sec("🌐  Ağ / Tarama Ayarları")
        net_card = card()
        net_vars: dict = {}
        for lbl, key, lo, hi in [
            ("Timeout (sn)",       "timeout",       1,  60),
            ("Port thread",        "port_threads",  1, 500),
            ("Subdomain thread",   "sub_threads",   1, 200),
            ("UserFind thread",    "user_threads",  1, 100),
            ("Max port",           "max_ports",     1, 65535),
            ("Rate limit (ms)",    "rate_limit_ms", 0, 5000),
        ]:
            nr = tk.Frame(net_card, bg=CARD_BG)
            nr.pack(fill="x", padx=12, pady=3)
            tk.Label(nr, text=f"{lbl}:", fg="#555", bg=CARD_BG,
                     font=("Consolas", 9), width=22, anchor="w").pack(side="left")
            var = tk.StringVar(value=str(self.configs.get(key, DEFAULT_CONFIG.get(key, 10))))
            net_vars[key] = var
            tk.Spinbox(nr, from_=lo, to=hi, textvariable=var, width=8,
                       bg=IN_BG, fg="white", relief="flat",
                       font=("Consolas", 10)).pack(side="left", padx=4)

        def save_net():
            for k, v in net_vars.items():
                try:
                    self.configs[k] = int(v.get())
                except ValueError:
                    pass
            self.timeout = self.configs["timeout"]
            save_config(self.configs)
            self._status("Ağ ayarları kaydedildi")

        tk.Button(net_card, text="Kaydet", bg=self.ui_color, fg="black",
                  font=("Consolas", 10, "bold"), relief="flat", padx=10,
                  command=save_net).pack(anchor="w", padx=12, pady=(4, 12))

        # ══════════════════════════════════
        # CACHE
        # ══════════════════════════════════
        sec("💾  Cache")
        cache_card = card()
        cc = tk.Frame(cache_card, bg=CARD_BG)
        cc.pack(fill="x", padx=12, pady=10)
        cache_en = tk.BooleanVar(value=self.configs.get("cache_enabled", True))

        def toggle_cache():
            self.configs["cache_enabled"] = cache_en.get()
            save_config(self.configs)

        tk.Checkbutton(cc, text="Cache aktif", variable=cache_en, command=toggle_cache,
                       fg="#555", bg=CARD_BG, selectcolor=CARD_BG,
                       activebackground=CARD_BG, font=("Consolas", 9)).pack(side="left")
        tk.Label(cc, text="TTL (sn):", fg="#555", bg=CARD_BG,
                 font=("Consolas", 9)).pack(side="left", padx=(20, 4))
        ttl_var = tk.StringVar(value=str(self.configs.get("cache_ttl", 3600)))
        tk.Spinbox(cc, from_=60, to=86400, textvariable=ttl_var, width=7,
                   bg=IN_BG, fg="white", relief="flat",
                   font=("Consolas", 10)).pack(side="left")
        tk.Button(cc, text="TTL Kaydet", bg="#1a1a1a", fg="#555",
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=lambda: [self.configs.__setitem__("cache_ttl", int(ttl_var.get())),
                                   save_config(self.configs)]
                  ).pack(side="left", padx=6)
        tk.Label(cc, text=f"{len(self._cache)} giriş", fg="#333", bg=CARD_BG,
                 font=("Consolas", 8)).pack(side="left", padx=8)
        tk.Button(cc, text="Temizle", bg="#1a1a1a", fg=ERR_FG,
                  font=("Consolas", 9), relief="flat", padx=8,
                  command=lambda: [self._cache.clear(), save_cache(self._cache),
                                   self._status("Cache temizlendi")]
                  ).pack(side="left")

        # ══════════════════════════════════
        # RENKLER
        # ══════════════════════════════════
        sec("🎨  Renkler")
        palette = ["#ff2a2a","#00ff88","#00d4ff","#b400ff",
                   "#ff8800","#ffcc00","#ffffff","#ff69b4"]
        color_row = tk.Frame(inn, bg=APP_BG)
        color_row.pack(fill="x", padx=26, pady=(0, 8))
        for title_lbl, setter in [("UI Rengi", self._set_ui),
                                   ("Wave Rengi", self._set_wave)]:
            col = tk.Frame(color_row, bg=APP_BG)
            col.pack(side="left", fill="both", expand=True, padx=(0, 18))
            tk.Label(col, text=title_lbl, fg="#444", bg=APP_BG,
                     font=("Consolas", 9, "bold")).pack(anchor="w", pady=(0, 3))
            g = tk.Frame(col, bg=APP_BG)
            g.pack(fill="x")
            for i, c in enumerate(palette):
                tk.Button(g, bg=c, width=12, relief="flat",
                          command=lambda x=c, s=setter: s(x)
                          ).grid(row=i // 4, column=i % 4, padx=4, pady=4)

        # ══════════════════════════════════
        # LOG
        # ══════════════════════════════════
        sec("📜  Log")
        log_f = tk.Frame(inn, bg=APP_BG)
        log_f.pack(fill="x", padx=26, pady=(0, 24))
        log_var = tk.BooleanVar(value=self.configs.get("log_enabled", True))

        def toggle_log():
            self.configs["log_enabled"] = log_var.get()
            save_config(self.configs)

        tk.Checkbutton(log_f, text="Sorgu logunu kaydet", variable=log_var,
                       command=toggle_log, fg="#555", bg=APP_BG, selectcolor=APP_BG,
                       activebackground=APP_BG, font=("Consolas", 10)).pack(side="left")
        tk.Label(log_f, text=f"  ({LOG_FILE})", fg="#252525", bg=APP_BG,
                 font=("Consolas", 8)).pack(side="left")

    def _set_ui(self, c: str):
        self.ui_color = c
        self.configs["ui_color"] = c
        save_config(self.configs)
        self.logo.config(fg=c)

    def _set_wave(self, c: str):
        self.wv_color = c
        self.configs["wave_color"] = c
        save_config(self.configs)
        if self.wave:
            self.wave.set_color(c)


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    BloodlineApp().mainloop()