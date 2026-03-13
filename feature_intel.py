"""
Feature Intel - Competitive Intelligence & Unreleased Feature Detection System
===============================================================================
Monitors tech companies for new/upcoming features, product changes, and unreleased
capabilities — similar to what TestingCatalog does manually.

Detection Methods:
1. Web App JS Bundle Monitoring - Detect new feature flags in JavaScript bundles
2. Documentation Diffing - Track changes to developer docs and changelogs
3. DNS/Subdomain Discovery - Find new subdomains hinting at upcoming products
4. App Store Version Tracking - Monitor app updates and changelogs
5. GitHub/Open Source Monitoring - Track commits, PRs, and releases
6. Chrome Flags / Feature Flags Monitoring - Detect new experimental features
7. Regulatory Filing Monitoring - FCC filings for new hardware
8. API Endpoint Discovery - Detect new/changed API endpoints
9. Sitemap Diffing - Find new pages before they're linked

Discord webhook alerts for all detections.
"""

import os
import gc
import sys
import json
import time
import hashlib
import logging
import re
import sqlite3
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# ─── Configuration ──────────────────────────────────────────────────────────

DISCORD_WEBHOOKS = [
    "https://discordapp.com/api/webhooks/919672540237017138/Zga2QHBVwPUKXbCMNQ6hRXSsJaW8d136pOZNheRz1SK0YS5GIRnpjsGdN7trPul-zeXo",
    "https://discordapp.com/api/webhooks/1474594868188811324/MvUYf1OwB-2lAbPT5YkbjXTOeL2UAXAIXJfXokKEUyMv5MApg2B7OQ5HhQR_bgA8kr1B",
]
# Can also add via env var (comma-separated)
if os.getenv("DISCORD_WEBHOOK_URLS"):
    DISCORD_WEBHOOKS.extend(os.getenv("DISCORD_WEBHOOK_URLS").split(","))

CHECK_INTERVAL_MINUTES = int(os.getenv("CHECK_INTERVAL_MINUTES", "30"))

# Persistent DB: Use Railway volume if available, otherwise local
# Set RAILWAY_VOLUME_MOUNT_PATH=/data in Railway, then DB lives at /data/feature_intel.db
# This survives redeploys so you don't re-baseline every time you push code
_volume_path = os.getenv("RAILWAY_VOLUME_MOUNT_PATH", "")
if _volume_path and os.path.isdir(_volume_path):
    DB_PATH = os.path.join(_volume_path, "feature_intel.db")
    print(f"[FeatureIntel] Using persistent volume DB: {DB_PATH}")
else:
    DB_PATH = os.getenv("DB_PATH", "feature_intel.db")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
REQUEST_TIMEOUT = 15
MAX_WORKERS = 5

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(open(sys.stdout.fileno(), mode='w', encoding='utf-8', closefd=False)),
        logging.FileHandler("feature_intel.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("FeatureIntel")

# Suppress noisy third-party loggers
logging.getLogger("androguard").setLevel(logging.WARNING)
logging.getLogger("loguru").setLevel(logging.WARNING)
try:
    from loguru import logger as _loguru
    _loguru.disable("androguard")
except ImportError:
    pass

# ─── Database ───────────────────────────────────────────────────────────────

def init_db():
    """Initialize SQLite database for tracking state."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS content_hashes (
            monitor_type TEXT,
            target_id TEXT,
            content_hash TEXT,
            last_content TEXT,
            updated_at TEXT,
            PRIMARY KEY (monitor_type, target_id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_type TEXT,
            target_id TEXT,
            detection_type TEXT,
            title TEXT,
            details TEXT,
            detected_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS feature_flags (
            source TEXT,
            flag_name TEXT,
            first_seen TEXT,
            last_seen TEXT,
            PRIMARY KEY (source, flag_name)
        )
    """)

    conn.commit()
    return conn


def get_stored_hash(conn, monitor_type, target_id):
    """Get previously stored content hash."""
    c = conn.cursor()
    c.execute(
        "SELECT content_hash, last_content FROM content_hashes WHERE monitor_type=? AND target_id=?",
        (monitor_type, target_id),
    )
    row = c.fetchone()
    return (row[0], row[1]) if row else (None, None)


def store_hash(conn, monitor_type, target_id, content_hash, content=""):
    """Store content hash for future comparison."""
    c = conn.cursor()
    c.execute(
        """INSERT OR REPLACE INTO content_hashes (monitor_type, target_id, content_hash, last_content, updated_at)
           VALUES (?, ?, ?, ?, ?)""",
        (monitor_type, target_id, content_hash, content[:50000], datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def log_detection(conn, monitor_type, target_id, detection_type, title, details):
    """Log a detection event."""
    c = conn.cursor()
    c.execute(
        """INSERT INTO detections (monitor_type, target_id, detection_type, title, details, detected_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (monitor_type, target_id, detection_type, title, details, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


# ─── Discord Notifications ──────────────────────────────────────────────────

def send_discord_alert(title, description, fields=None, color=0x00FF88, url=None):
    """Send Discord webhook notification to ALL configured webhooks."""
    if not DISCORD_WEBHOOKS:
        logger.warning("No Discord webhooks configured")
        return

    embed = {
        "title": f"🔍 {title}",
        "description": description[:4000],
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "Feature Intel"},
    }

    if url:
        embed["url"] = url
    if fields:
        embed["fields"] = fields[:25]

    payload = {"embeds": [embed]}

    for webhook_url in DISCORD_WEBHOOKS:
        webhook_url = webhook_url.strip()
        if not webhook_url:
            continue
        try:
            resp = requests.post(webhook_url, json=payload, timeout=10)
            if resp.status_code == 429:
                retry_after = resp.json().get("retry_after", 5)
                time.sleep(retry_after)
                requests.post(webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Discord alert failed ({webhook_url[:60]}...): {e}")
        time.sleep(0.5)  # small delay between webhooks to avoid rate limits


# ─── HTTP Helpers ───────────────────────────────────────────────────────────

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


def fetch_url(url, timeout=REQUEST_TIMEOUT):
    """Fetch URL with error handling."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp
    except Exception as e:
        logger.debug(f"Failed to fetch {url}: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 1: Deep Web App JS String Extraction (TestingCatalog Method)
# Downloads every JS bundle from a web app, extracts ALL human-readable
# strings (UI labels, feature names, button text, error messages, menus,
# tooltips, descriptions), and diffs them over time. When new strings
# appear like "Photoshoot", "Copilot Advisors" — that's an unreleased
# feature being developed.
# ═══════════════════════════════════════════════════════════════════════════

# Noise strings to filter out of JS bundle analysis
JS_STRING_NOISE = {
    # Common JS/framework tokens
    "undefined", "null", "true", "false", "object", "function", "string",
    "number", "boolean", "symbol", "bigint", "default", "export", "import",
    "return", "module", "require", "prototype", "constructor", "length",
    "value", "index", "type", "name", "data", "error", "message", "status",
    "result", "callback", "promise", "resolve", "reject", "then", "catch",
    "async", "await", "class", "extends", "super", "this", "new", "get",
    "set", "delete", "typeof", "instanceof", "void", "yield", "static",
    "const", "var", "let", "break", "continue", "switch", "case", "throw",
    "try", "finally", "debugger", "with", "label", "enum", "implements",
    "interface", "package", "private", "protected", "public",
    # Common CSS/HTML tokens that leak into JS
    "div", "span", "input", "button", "select", "option", "form", "img",
    "href", "src", "alt", "title", "placeholder", "aria-label", "role",
    "hidden", "disabled", "checked", "selected", "required", "readonly",
    "click", "change", "submit", "focus", "blur", "keydown", "keyup",
    "mousedown", "mouseup", "mouseover", "mouseout", "touchstart",
    "scroll", "resize", "load", "unload", "beforeunload",
    "block", "inline", "flex", "grid", "none", "auto", "inherit",
    "relative", "absolute", "fixed", "sticky", "center", "left", "right",
    "bold", "italic", "normal", "pointer", "default", "text",
    # HTTP/network
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    "Content-Type", "Authorization", "Accept", "application/json",
    "text/html", "text/plain", "multipart/form-data",
}

# Regex to detect strings that are NOT useful UI text
JS_NOISE_PATTERNS = [
    r'^[\da-f]{6,}$',           # hex hashes
    r'^#[\da-fA-F]{3,8}$',      # hex colors
    r'^[\d.]+px$',              # pixel values
    r'^[\d.]+rem$',             # rem values
    r'^[\d.]+em$',              # em values
    r'^[\d.]+%$',               # percentages
    r'^rgba?\(',                # rgba colors
    r'^hsla?\(',                # hsla colors
    r'^data:',                  # data URIs
    r'^https?://',              # URLs
    r'^/[a-z]',                 # URL paths
    r'^\.',                     # CSS class selectors
    r'^[A-Za-z0-9+/]{40,}',    # base64/encoded data
    r'^\d+(\.\d+)*$',          # version numbers or pure numbers
    r'^[a-z]{1,2}$',           # single/two letter vars
    r'^[A-Z]{1,2}$',           # single/two letter constants
    r'^_',                      # internal/private vars
    r'^\$',                     # jQuery/special vars
    r'^@@',                     # Symbol references
    r'^\w+\.\w+\.\w+\.\w+',   # deeply nested property paths
    r'^[a-z]+[A-Z][a-z]+[A-Z][a-zA-Z]*$',  # camelCase code variables (3+ humps, single word only)
    r'^\{[\{\[]',               # JSON/template syntax
    r'^<[a-zA-Z]',              # HTML tags
    r'^svg\s',                  # SVG paths
    r'^M[\d\s,.-]+$',           # SVG path data
    r'^[a-f0-9]{32,}$',        # MD5/SHA hashes
    r'^[A-Za-z0-9_-]+={1,2}$', # base64 padding
    r'^\w+:\w+:\w+',           # namespaced keys
    r'^\d{10,}$',              # timestamps/big numbers
    r'^[,;]\w+:',              # minified JS artifacts between strings
    r'^\w+[,;]$',              # trailing comma/semicolon artifacts
    r'^[,.:;!?]',              # strings starting with punctuation
]

# Patterns that STRONGLY indicate unreleased / hidden features
UI_INTEREST_PATTERNS = [
    r'coming soon',
    r'not yet available',
    r'not available yet',
    r'under development',
    r'in development',
    r'will be available',
    r'available soon',
    r'new feature',
    r'try the new',
    r'introducing',
    r'launching soon',
    r'early access',
    r'sneak peek',
    r'behind the scenes',
    r'internal[_ ]only',
    r'dogfood',
    r'canary',
    r'experimental',
    r'prototype',
    r'unreleased',
    r'\bbeta\b',
    r'\bpreview\b',
    r'feature[_ ]flag',
    r'roll[_ ]?out',
    r'enabled[_ ]for',
    r'disabled[_ ]for',
    r'% of users',
    r'A/B test',
    r'experiment[_ ]?id',
]


def extract_js_urls_deep(html, base_url):
    """
    Extract ALL JavaScript bundle URLs from HTML including:
    - Regular <script src> tags
    - Webpack chunk loading patterns
    - Dynamic import() references
    - Preload/prefetch links
    - Inline script references to chunk URLs
    """
    soup = BeautifulSoup(html, "html.parser")
    js_urls = set()

    # 1. Standard <script src> tags
    for script in soup.find_all("script", src=True):
        src = script["src"]
        full_url = urljoin(base_url, src)
        js_urls.add(full_url)

    # 2. Preload/prefetch links for JS
    for link in soup.find_all("link", rel=lambda x: x and ("preload" in x or "prefetch" in x or "modulepreload" in x)):
        href = link.get("href", "")
        if href and (".js" in href or "chunk" in href.lower()):
            js_urls.add(urljoin(base_url, href))

    # 3. Extract chunk URLs from inline scripts
    for script in soup.find_all("script", src=False):
        text = script.string or ""
        # Webpack chunk patterns: "static/js/chunk-abc123.js"
        chunk_matches = re.findall(r'["\']([^"\']*?(?:chunk|bundle|vendor|main|app|index)[^"\']*?\.js[^"\']*?)["\']', text, re.IGNORECASE)
        for chunk in chunk_matches:
            if not chunk.startswith("http"):
                chunk = urljoin(base_url, chunk)
            js_urls.add(chunk)

        # Next.js _buildManifest / _ssgManifest patterns
        next_chunks = re.findall(r'["\'](_next/static/[^"\']+\.js)["\']', text)
        for chunk in next_chunks:
            js_urls.add(urljoin(base_url, "/" + chunk))

        # Generic path patterns ending in .js
        generic_js = re.findall(r'["\'](/[^"\']*?\.(?:js|mjs))["\']', text)
        for path in generic_js:
            js_urls.add(urljoin(base_url, path))

    # Filter out tracking/analytics scripts
    skip_keywords = [
        "analytics", "gtag", "gtm", "pixel", "tracking", "hotjar",
        "sentry", "datadog", "segment", "mixpanel", "amplitude",
        "intercom", "hubspot", "marketo", "pardot", "drift",
        "google-analytics", "googletagmanager", "facebook",
        "twitter", "linkedin", "pinterest", "snap",
        "clarity", "fullstory", "logrocket", "heap",
        "recaptcha", "hcaptcha", "turnstile",
    ]

    filtered = set()
    for url in js_urls:
        url_lower = url.lower()
        if not any(kw in url_lower for kw in skip_keywords):
            filtered.add(url)

    return filtered


def extract_strings_from_js(js_content):
    """
    Extract all human-readable strings from minified JavaScript.
    Returns a set of cleaned, meaningful strings.
    """
    strings = set()

    # Extract double-quoted strings
    for match in re.finditer(r'"((?:[^"\\]|\\.){3,})"', js_content):
        strings.add(match.group(1))

    # Extract single-quoted strings
    for match in re.finditer(r"'((?:[^'\\]|\\.){3,})'", js_content):
        strings.add(match.group(1))

    # Extract template literal content (simplified - no nested expressions)
    for match in re.finditer(r'`((?:[^`\\]|\\.){3,})`', js_content):
        text = match.group(1)
        # Clean template expressions ${...}
        text = re.sub(r'\$\{[^}]*\}', '...', text)
        if len(text.strip()) >= 3:
            strings.add(text.strip())

    return strings


def filter_ui_strings(raw_strings):
    """
    Filter extracted strings to keep only likely UI text / feature names.
    Returns dict of {string: category} where category helps prioritize.
    """
    compiled_noise = [re.compile(p) for p in JS_NOISE_PATTERNS]
    compiled_interest = [re.compile(p, re.IGNORECASE) for p in UI_INTEREST_PATTERNS]

    results = {}

    for s in raw_strings:
        s = s.strip()

        # Length filters
        if len(s) < 4 or len(s) > 500:
            continue

        # Skip known noise tokens
        if s.lower() in JS_STRING_NOISE or s in JS_STRING_NOISE:
            continue

        # Skip strings matching noise patterns
        is_noise = False
        for pattern in compiled_noise:
            if pattern.search(s):
                is_noise = True
                break
        if is_noise:
            continue

        # Skip strings that are mostly non-alpha (code/data)
        alpha_ratio = sum(1 for c in s if c.isalpha()) / max(len(s), 1)
        if alpha_ratio < 0.5:
            continue

        # Skip strings with too many special code characters
        code_chars = sum(1 for c in s if c in '{}[]();<>=!&|^~@#$%')
        if code_chars > 3:
            continue

        # Categorize
        category = "string"

        # Check if it matches high-interest patterns (unreleased indicators)
        for pattern in compiled_interest:
            if pattern.search(s):
                category = "high_interest"
                break

        # Only further categorize if not already high_interest
        if category != "high_interest":
            # Multi-word strings with spaces are likely UI text
            word_count = len(s.split())
            if word_count >= 3:
                category = "ui_text"
            # Title Case strings (2+ words) = feature names, menu labels
            elif word_count >= 2 and s[0].isupper():
                category = "feature_name"
            # Single capitalized words that aren't common code tokens
            elif word_count == 1 and s[0].isupper() and len(s) >= 5:
                category = "proper_noun"
            # Short strings with no spaces = probably code tokens, skip
            elif word_count == 1 and len(s) < 8:
                continue

        results[s] = category

    return results


def monitor_js_bundles(conn, targets):
    """
    Deep JS string extraction monitor (TestingCatalog method).
    
    Downloads all JS bundles from target web apps, extracts every
    human-readable string, and diffs against previous scans to detect
    new UI text, feature names, and product hints.
    
    targets: list of dicts with keys:
        - name: display name
        - url: web app URL to scan
        - keywords: optional priority keywords
    """
    logger.info(f"=== Deep JS Bundle Scanner ({len(targets)} targets) ===")

    for idx, target in enumerate(targets, 1):
        name = target["name"]
        url = target["url"]
        priority_keywords = [kw.lower() for kw in target.get("keywords", [])]

        logger.info(f"  [{idx}/{len(targets)}] Scanning: {name} ({url})")

        # 1. Fetch the page
        resp = fetch_url(url)
        if not resp:
            continue

        # 2. Find all JS bundle URLs
        js_urls = extract_js_urls_deep(resp.text, url)
        logger.info(f"    Found {len(js_urls)} JS bundles")

        # 3. Download and extract strings from each bundle
        all_strings = {}
        bundles_fetched = 0
        for js_url in list(js_urls)[:30]:  # cap at 30 bundles per target
            js_resp = fetch_url(js_url, timeout=10)
            if not js_resp or len(js_resp.text) < 100:
                continue
            bundles_fetched += 1

            raw = extract_strings_from_js(js_resp.text)
            filtered = filter_ui_strings(raw)
            all_strings.update(filtered)

        logger.info(f"    Fetched {bundles_fetched} bundles, extracted {len(all_strings)} UI strings")

        if not all_strings:
            continue

        # 4. Create a stable hash of all current strings
        current_keys = sorted(all_strings.keys())
        strings_hash = hashlib.sha256(json.dumps(current_keys).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "js_deep", name)

        # 5. Compare against previous scan
        if old_hash and strings_hash != old_hash:
            old_strings = set(json.loads(old_content)) if old_content else set()
            new_strings = set(current_keys) - old_strings
            removed_strings = old_strings - set(current_keys)

            if new_strings:
                # Categorize and prioritize new strings
                high_interest = []
                keyword_matches = []
                feature_names = []
                ui_text = []

                for s in new_strings:
                    cat = all_strings.get(s, "string")

                    # Check priority keywords
                    s_lower = s.lower()
                    if priority_keywords and any(kw in s_lower for kw in priority_keywords):
                        keyword_matches.append(s)
                    elif cat == "high_interest":
                        high_interest.append(s)
                    elif cat == "feature_name":
                        feature_names.append(s)
                    elif cat == "ui_text":
                        ui_text.append(s)

                # Build alert
                alert_parts = []
                if keyword_matches:
                    alert_parts.append("**Keyword Matches:**\n" + "\n".join(f"* `{s[:120]}`" for s in sorted(keyword_matches)[:10]))
                if high_interest:
                    alert_parts.append("**High Interest:**\n" + "\n".join(f"* `{s[:120]}`" for s in sorted(high_interest)[:10]))
                if feature_names:
                    alert_parts.append("**Feature Names:**\n" + "\n".join(f"* `{s[:120]}`" for s in sorted(feature_names)[:15]))
                if ui_text:
                    alert_parts.append("**New UI Text:**\n" + "\n".join(f"* `{s[:120]}`" for s in sorted(ui_text)[:15]))

                if alert_parts:
                    total_interesting = len(keyword_matches) + len(high_interest) + len(feature_names) + len(ui_text)
                    details = "\n\n".join(alert_parts)
                    send_discord_alert(
                        f"Unreleased Features: {name}",
                        f"**{total_interesting} new strings detected** in JS bundles ({len(new_strings)} total new)\n\n{details}",
                        color=0x00FF88,
                        url=url,
                    )
                    log_detection(conn, "js_deep", name, "new_strings",
                                  f"{total_interesting} interesting strings",
                                  details[:2000])
                    logger.info(f"    -> {total_interesting} interesting new strings for {name}")

            if removed_strings and len(removed_strings) < 200:
                # Large removals = redesign/rebuild, not interesting
                notable_removed = [s for s in removed_strings
                                   if len(s.split()) >= 2 and s[0].isupper()]
                if notable_removed:
                    removed_list = "\n".join(f"* ~~`{s[:100]}`~~" for s in sorted(notable_removed)[:10])
                    send_discord_alert(
                        f"Removed Strings: {name}",
                        f"**{len(notable_removed)} notable strings removed** (feature launched, killed, or renamed?)\n\n{removed_list}",
                        color=0xFFA500,
                        url=url,
                    )

        # 6. Store current state
        store_hash(conn, "js_deep", name, strings_hash, json.dumps(current_keys[:5000]))

        if not old_hash:
            logger.info(f"    Baseline stored: {len(all_strings)} strings for {name}")


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 2: Documentation & Changelog Diffing
# ═══════════════════════════════════════════════════════════════════════════

def extract_text_content(html):
    """Extract meaningful text from HTML for diffing."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    # Normalize whitespace
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    return "\n".join(lines)


def diff_text(old_text, new_text):
    """Simple line-level diff returning added and removed lines."""
    old_lines = set(old_text.split("\n"))
    new_lines = set(new_text.split("\n"))
    added = new_lines - old_lines
    removed = old_lines - new_lines
    return added, removed


def monitor_docs(conn, targets):
    """
    Monitor documentation pages for changes.
    
    targets: list of dicts with keys:
        - name: display name
        - urls: list of doc page URLs to monitor
        - keywords: optional keywords that make changes more interesting
    """
    logger.info("=== Documentation Monitor ===")

    for target in targets:
        name = target["name"]
        urls = target.get("urls", [])
        keywords = [kw.lower() for kw in target.get("keywords", [])]

        for url in urls:
            target_id = f"{name}:{hashlib.md5(url.encode()).hexdigest()[:8]}"
            resp = fetch_url(url)
            if not resp:
                continue

            text_content = extract_text_content(resp.text)
            content_hash = hashlib.sha256(text_content.encode()).hexdigest()
            old_hash, old_content = get_stored_hash(conn, "docs", target_id)

            if old_hash and content_hash != old_hash:
                added, removed = diff_text(old_content or "", text_content)

                if not added and not removed:
                    store_hash(conn, "docs", target_id, content_hash, text_content)
                    continue

                # Check if changes contain interesting keywords
                interesting_additions = []
                for line in added:
                    if any(kw in line.lower() for kw in keywords) or len(line) > 20:
                        interesting_additions.append(line)

                if interesting_additions:
                    sample = "\n".join(f"+ {line[:150]}" for line in list(interesting_additions)[:10])
                    send_discord_alert(
                        f"Doc Change: {name}",
                        f"**{len(added)} lines added, {len(removed)} removed**\n\n```diff\n{sample}\n```",
                        color=0x3498DB,
                        url=url,
                    )
                    log_detection(conn, "docs", target_id, "doc_change", f"Changes in {name}", sample[:1000])
                    logger.info(f"  → Doc change detected: {name} ({url})")
                elif added:
                    logger.info(f"  → Minor doc change: {name} ({len(added)} lines added)")

            store_hash(conn, "docs", target_id, content_hash, text_content)


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 3: Sitemap Monitoring (New Pages = New Features)
# ═══════════════════════════════════════════════════════════════════════════

def parse_sitemap(xml_content, base_url):
    """Parse sitemap XML and extract URLs."""
    urls = set()
    soup = BeautifulSoup(xml_content, "xml")

    # Handle sitemap index
    for sitemap in soup.find_all("sitemap"):
        loc = sitemap.find("loc")
        if loc:
            sub_resp = fetch_url(loc.text.strip())
            if sub_resp:
                urls.update(parse_sitemap(sub_resp.text, base_url))

    # Handle regular sitemap
    for url_tag in soup.find_all("url"):
        loc = url_tag.find("loc")
        if loc:
            urls.add(loc.text.strip())

    return urls


def monitor_sitemaps(conn, targets):
    """
    Monitor sitemaps for new pages.
    
    targets: list of dicts with keys:
        - name: display name
        - sitemap_url: URL of the sitemap.xml
        - interesting_patterns: regex patterns for URLs that are particularly interesting
    """
    logger.info("=== Sitemap Monitor ===")

    for target in targets:
        name = target["name"]
        sitemap_url = target["sitemap_url"]
        patterns = target.get("interesting_patterns", [])

        resp = fetch_url(sitemap_url)
        if not resp:
            continue

        current_urls = parse_sitemap(resp.text, sitemap_url)
        urls_hash = hashlib.sha256(json.dumps(sorted(current_urls)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "sitemap", name)

        if old_hash and urls_hash != old_hash:
            old_urls = set(json.loads(old_content)) if old_content else set()
            new_urls = current_urls - old_urls
            removed_urls = old_urls - current_urls

            if new_urls:
                # Check for interesting new pages
                interesting = []
                for url in new_urls:
                    is_interesting = not patterns  # if no patterns, all are interesting
                    for pat in patterns:
                        if re.search(pat, url, re.IGNORECASE):
                            is_interesting = True
                            break
                    if is_interesting:
                        interesting.append(url)

                if interesting:
                    url_list = "\n".join(f"• {u}" for u in list(interesting)[:15])
                    send_discord_alert(
                        f"New Pages: {name}",
                        f"**{len(interesting)} new pages** found in sitemap\n\n{url_list}",
                        color=0x9B59B6,
                        url=sitemap_url,
                    )
                    log_detection(conn, "sitemap", name, "new_pages", f"{len(interesting)} new pages", url_list)
                    logger.info(f"  → {len(interesting)} new pages for {name}")

        store_hash(conn, "sitemap", name, urls_hash, json.dumps(list(current_urls)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 4: GitHub Release & PR Monitoring
# ═══════════════════════════════════════════════════════════════════════════

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")


def github_api(endpoint):
    """Make a GitHub API request."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        resp = requests.get(f"https://api.github.com{endpoint}", headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        logger.debug(f"GitHub API {resp.status_code} for {endpoint}")
    except Exception as e:
        logger.debug(f"GitHub API error: {e}")
    return None


def monitor_github(conn, targets):
    """
    Monitor GitHub repos for releases, PRs, and commits.
    
    targets: list of dicts with keys:
        - name: display name
        - repo: owner/repo format
        - watch: list of "releases", "prs", "commits"
        - keywords: optional keywords to filter PRs/commits
    """
    logger.info("=== GitHub Monitor ===")

    for target in targets:
        name = target["name"]
        repo = target["repo"]
        watch = target.get("watch", ["releases"])
        keywords = [kw.lower() for kw in target.get("keywords", [])]

        # Monitor releases
        if "releases" in watch:
            releases = github_api(f"/repos/{repo}/releases?per_page=5")
            if releases:
                latest = releases[0]
                release_id = f"{repo}:release:{latest['id']}"
                old_hash, _ = get_stored_hash(conn, "github_release", repo)
                new_hash = str(latest["id"])

                if old_hash and new_hash != old_hash:
                    send_discord_alert(
                        f"New Release: {name}",
                        f"**{latest['tag_name']}** — {latest['name'] or 'No title'}\n\n{(latest.get('body') or '')[:500]}",
                        color=0x2ECC71,
                        url=latest["html_url"],
                    )
                    log_detection(conn, "github_release", repo, "release", latest["tag_name"], latest.get("body", "")[:1000])
                    logger.info(f"  → New release: {name} {latest['tag_name']}")

                store_hash(conn, "github_release", repo, new_hash)

        # Monitor PRs for feature hints
        if "prs" in watch:
            prs = github_api(f"/repos/{repo}/pulls?state=all&sort=created&direction=desc&per_page=20")
            if prs:
                pr_ids = [str(pr["id"]) for pr in prs]
                prs_hash = hashlib.sha256(json.dumps(pr_ids).encode()).hexdigest()
                old_hash, old_content = get_stored_hash(conn, "github_prs", repo)

                if old_hash and prs_hash != old_hash:
                    old_ids = set(json.loads(old_content)) if old_content else set()
                    new_prs = [pr for pr in prs if str(pr["id"]) not in old_ids]

                    interesting_prs = []
                    for pr in new_prs:
                        title_lower = pr["title"].lower()
                        if not keywords or any(kw in title_lower for kw in keywords):
                            interesting_prs.append(pr)

                    if interesting_prs:
                        pr_list = "\n".join(
                            f"• **{pr['title'][:80]}** (#{pr['number']})"
                            for pr in interesting_prs[:10]
                        )
                        send_discord_alert(
                            f"New PRs: {name}",
                            f"**{len(interesting_prs)} interesting PRs**\n\n{pr_list}",
                            color=0xE67E22,
                            url=f"https://github.com/{repo}/pulls",
                        )

                store_hash(conn, "github_prs", repo, prs_hash, json.dumps(pr_ids))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 5: App Store Version Monitoring
# ═══════════════════════════════════════════════════════════════════════════

def get_ios_app_info(app_id):
    """Get iOS app info from iTunes API."""
    try:
        resp = requests.get(
            f"https://itunes.apple.com/lookup?id={app_id}&country=us",
            timeout=15,
        )
        data = resp.json()
        if data.get("resultCount", 0) > 0:
            return data["results"][0]
    except Exception as e:
        logger.debug(f"iTunes API error: {e}")
    return None


def get_ios_apps_batch(app_ids):
    """Batch lookup up to 200 iOS apps in one API call."""
    results = {}
    # iTunes API supports comma-separated IDs
    for chunk_start in range(0, len(app_ids), 150):
        chunk = app_ids[chunk_start:chunk_start + 150]
        ids_str = ",".join(str(aid) for aid in chunk)
        try:
            resp = requests.get(
                f"https://itunes.apple.com/lookup?id={ids_str}&country=us",
                timeout=20,
            )
            data = resp.json()
            for app in data.get("results", []):
                track_id = str(app.get("trackId", ""))
                if track_id:
                    results[track_id] = app
        except Exception as e:
            logger.debug(f"iTunes batch API error: {e}")
    return results


def monitor_app_store(conn, targets):
    """
    Monitor iOS App Store for version changes.
    Uses batch API to check all apps in 1 call instead of 61.
    
    targets: list of dicts with keys:
        - name: display name
        - app_id: iTunes app ID (numeric)
    """
    logger.info(f"=== App Store Monitor ({len(targets)} apps, batch) ===")

    # Batch fetch all apps at once
    app_ids = [t["app_id"] for t in targets]
    id_to_name = {t["app_id"]: t["name"] for t in targets}
    all_apps = get_ios_apps_batch(app_ids)
    logger.info(f"    Fetched {len(all_apps)}/{len(app_ids)} apps in batch")

    for i, target in enumerate(targets, 1):
        name = target["name"]
        app_id = target["app_id"]

        info = all_apps.get(str(app_id))
        if not info:
            continue

        version = info.get("version", "")
        release_notes = info.get("releaseNotes", "")
        version_hash = hashlib.sha256(f"{version}:{release_notes}".encode()).hexdigest()
        old_hash, _ = get_stored_hash(conn, "app_store", name)

        if old_hash and version_hash != old_hash:
            changelog = release_notes[:1500] if release_notes else "No release notes provided"
            send_discord_alert(
                f"iOS Update: {name} v{version}",
                f"**`{info.get('bundleId', '')}`** updated to **v{version}**\n\n**What's New:**\n{changelog}",
                fields=[
                    {"name": "Size", "value": f"{int(info.get('fileSizeBytes', 0)) / 1_000_000:.1f} MB", "inline": True},
                    {"name": "Store", "value": f"[App Store]({info.get('trackViewUrl', '')})", "inline": True},
                ],
                color=0x1ABC9C,
                url=info.get("trackViewUrl", ""),
            )
            log_detection(conn, "app_store", name, "version_update", f"v{version}", release_notes[:1000])
            logger.info(f"  → App update: {name} v{version}")

        store_hash(conn, "app_store", name, version_hash)


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 6: Google Play Store Monitoring (via google-play-scraper)
# ═══════════════════════════════════════════════════════════════════════════

def get_play_store_info(package_name):
    """
    Get Google Play Store app info using google-play-scraper library.
    This uses Google's internal API (not HTML scraping) so it reliably
    returns version, changelog, ratings, etc.
    """
    try:
        from google_play_scraper import app as gps_app
        info = gps_app(package_name, lang="en", country="us")
        return {
            "url": f"https://play.google.com/store/apps/details?id={package_name}",
            "version": info.get("version", ""),
            "whats_new": (info.get("recentChanges") or "").strip(),
            "updated": str(info.get("updated", "")),
            "installs": info.get("installs", ""),
            "score": info.get("score", 0),
            # Hash version + changelog for change detection
            "content_hash": hashlib.sha256(
                f"{info.get('version', '')}:{info.get('recentChanges', '')}".encode()
            ).hexdigest()[:16],
        }
    except Exception as e:
        logger.debug(f"Play Store scraper error for {package_name}: {e}")
        return None


def monitor_play_store(conn, targets):
    """
    Monitor Google Play Store for app changes using google-play-scraper.
    
    targets: list of dicts with keys:
        - name: display name
        - package: Android package name
    """
    logger.info(f"=== Play Store Monitor ({len(targets)} apps) ===")

    for i, target in enumerate(targets, 1):
        name = target["name"]
        package = target["package"]

        info = get_play_store_info(package)
        if not info:
            continue

        old_hash, old_content = get_stored_hash(conn, "play_store", name)

        if old_hash and info["content_hash"] != old_hash:
            old_version = old_content if old_content else "unknown"
            version_str = f"**{old_version} → {info['version']}**\n\n" if info.get("version") else ""
            
            # Always show changelog section
            if info["whats_new"]:
                changelog = f"**What's New:**\n{info['whats_new'][:1500]}"
            else:
                changelog = "**What's New:**\nNo changelog provided by developer"

            send_discord_alert(
                f"Play Store Update: {name}",
                f"**`{package}`** has been updated\n\n{version_str}{changelog}",
                fields=[
                    {"name": "Version", "value": info.get("version", "—"), "inline": True},
                    {"name": "Updated", "value": info.get("updated", "—")[:10], "inline": True},
                    {"name": "Store", "value": f"[Google Play]({info['url']})", "inline": True},
                ],
                color=0x4CAF50,
                url=info["url"],
            )
            log_detection(conn, "play_store", name, "play_update",
                          f"v{info.get('version', '?')}", info["whats_new"][:1000])
            logger.info(f"  → Play Store update: {name} v{info.get('version', '?')}")

            # Trigger APK deep analysis on version change
            try:
                analyze_apk_strings(conn, name, package, info.get("version", "?"))
            except Exception as e:
                logger.debug(f"  APK analysis skipped for {name}: {e}")

        store_hash(conn, "play_store", name, info["content_hash"], info.get("version", ""))

        # If no APK string baseline exists yet, create one (one-time per app)
        if not old_hash:  # First time seeing this app
            try:
                old_apk_hash, _ = get_stored_hash(conn, "apk_strings", package)
                if not old_apk_hash:
                    analyze_apk_strings(conn, name, package, info.get("version", "?"))
            except Exception as e:
                logger.debug(f"  APK baseline skipped for {name}: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 6b: APK String Extractor (TestingCatalog methodology)
# When Play Store detects a version change, download the APK, decompile it,
# extract ALL UI strings from resources, and diff against previous version.
# This is how leakers find unreleased features months before launch.
# ═══════════════════════════════════════════════════════════════════════════

def download_apk(package_name, dest_path):
    """
    Download APK from multiple mirror sources.
    Returns True if download succeeded.
    """
    sources = [
        # APKPure direct download
        {
            "name": "APKPure",
            "url": f"https://d.apkpure.com/b/APK/{package_name}?version=latest",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/vnd.android.package-archive",
            },
        },
        # APKPure alternative endpoint
        {
            "name": "APKPure-alt",
            "url": f"https://d.apkpure.net/b/APK/{package_name}?version=latest",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36",
            },
        },
        # Uptodown (need to scrape download link)
        {
            "name": "APKCombo",
            "url": f"https://download.apkcombo.com/en/{package_name}/{package_name}.apk",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
        },
    ]

    for source in sources:
        try:
            logger.debug(f"    Trying APK download from {source['name']}...")
            resp = session.get(
                source["url"],
                headers=source.get("headers", {}),
                timeout=120,
                stream=True,
                allow_redirects=True,
            )

            # Check if we got an actual APK (not HTML error page)
            content_type = resp.headers.get("content-type", "")
            if resp.status_code == 200 and (
                "android" in content_type
                or "octet-stream" in content_type
                or "application/zip" in content_type
                or resp.headers.get("content-length", "0") > "1000000"
            ):
                with open(dest_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)

                file_size = os.path.getsize(dest_path)
                if file_size > 500_000:  # APKs are at least 500KB
                    logger.info(f"    Downloaded APK from {source['name']} ({file_size // 1024 // 1024}MB)")
                    return True
                else:
                    os.remove(dest_path)
        except Exception as e:
            logger.debug(f"    {source['name']} failed: {e}")
            continue

    return False


def extract_strings_from_apk(apk_path):
    """
    Extract ALL string resources from an APK using androguard.
    Returns dict of {string_name: string_value} for English locale.
    """
    try:
        from androguard.core.apk import APK as AndroAPK
    except ImportError:
        logger.debug("    androguard not installed, skipping APK analysis")
        return {}

    try:
        apk = AndroAPK(apk_path)
        arsc = apk.get_android_resources()

        if not arsc:
            return {}

        strings = {}

        # Get strings for all packages, preferring English/default locale
        for package_name in arsc.get_packages_names():
            # Try English locales first, then default
            locales_to_try = []
            available_locales = arsc.get_locales(package_name)
            for loc in ["en", "en-US", "en-GB", "\x00\x00", ""]:
                if loc in available_locales:
                    locales_to_try.append(loc)

            if not locales_to_try and available_locales:
                locales_to_try = [list(available_locales)[0]]

            for locale in locales_to_try[:1]:  # Just use best locale
                try:
                    resolved = arsc.get_resolved_strings()
                    if package_name in resolved:
                        for loc_key, str_dict in resolved[package_name].items():
                            if loc_key in ["en", "en-US", "en-GB", "", "\x00\x00"]:
                                for str_name, str_value in str_dict.items():
                                    if str_value and isinstance(str_value, str) and len(str_value) >= 3:
                                        strings[str_name] = str_value
                except Exception:
                    pass

        # Also extract from raw string resources as fallback
        try:
            string_resources = arsc.get_string_resources(arsc.get_packages_names()[0])
            if string_resources:
                for item in string_resources:
                    name = item.get("name", "")
                    value = item.get("value", "")
                    if name and value and isinstance(value, str) and len(value) >= 3:
                        strings[name] = value
        except Exception:
            pass

        return strings

    except Exception as e:
        logger.debug(f"    APK parsing error: {e}")
        return {}


def filter_apk_strings(raw_strings):
    """
    Filter APK string resources to find interesting UI text.
    Returns dict of {display_string: category}.
    
    Categories:
    - high_interest: Unreleased feature indicators
    - feature_name: Title Case feature names
    - ui_text: User-facing sentences
    """
    if not raw_strings:
        return {}

    # Noise string name patterns (the resource key, not the value)
    noise_name_patterns = re.compile(
        r"^(content_desc|accessibility|abc_|mtrl_|material_|design_|nav_|"
        r"common_|error_|debug_|test_|mock_|legacy_|deprecated_|"
        r"font_|color_|dimen_|style_|attr_|layout_|menu_|drawable_)",
        re.IGNORECASE,
    )

    # Interest patterns (in the string VALUE)
    interest_patterns = re.compile(
        r"(coming soon|not yet available|beta|preview|experimental|"
        r"early access|rolling out|limited availability|try the new|"
        r"upgrade to|upgrade your|new feature|behind the scenes|"
        r"A/B test|feature flag|gradual rollout|% of users|"
        r"canary|dogfood|internal only|staff only|employee preview|"
        r"connector|integration|plugin|extension|agent|"
        r"introducing|now available|just launched)",
        re.IGNORECASE,
    )

    # Noise value patterns
    noise_value_patterns = re.compile(
        r"(^https?://|^[0-9.]+$|^#[0-9a-fA-F]+$|^[{}\[\]<>]|"
        r"^\w+\.\w+\.\w+|^@\w+/|^res/|^android\.|"
        r"^[a-f0-9]{16,}$|^\s*$|^\.+$|^-+$|"
        r"^(true|false|null|none|undefined|ok|cancel|yes|no|done|close|back|next|save|delete|edit|share|copy|paste)$)",
        re.IGNORECASE,
    )

    filtered = {}

    for str_name, str_value in raw_strings.items():
        value = str_value.strip()

        # Skip noise by resource name
        if noise_name_patterns.match(str_name):
            continue

        # Skip noise by value
        if noise_value_patterns.match(value):
            continue

        # Skip very short or very long strings
        if len(value) < 4 or len(value) > 500:
            continue

        # Skip if mostly non-alphabetic
        alpha_count = sum(1 for c in value if c.isalpha())
        if alpha_count / max(len(value), 1) < 0.4:
            continue

        # Skip format strings that are mostly placeholders
        if value.count("%") > 2 or value.count("{") > 3:
            continue

        # Categorize
        if interest_patterns.search(value):
            filtered[value] = "high_interest"
        elif re.match(r"^[A-Z][a-z]+(?: [A-Z][a-z]+)+$", value):
            # Title Case multi-word: likely a feature name
            if value not in {"Got It", "Sign In", "Sign Up", "Log In", "Log Out",
                            "Next Step", "Go Back", "Learn More", "Read More",
                            "Try Again", "View All", "See All", "Show More",
                            "Not Now", "No Thanks"}:
                filtered[value] = "feature_name"
        elif len(value.split()) >= 4 and value[0].isupper():
            # Multi-word sentences: real UI copy
            filtered[value] = "ui_text"

    return filtered


def analyze_apk_strings(conn, app_name, package_name, version):
    """
    Full APK analysis pipeline:
    1. Download APK from mirrors
    2. Extract string resources
    3. Diff against stored strings
    4. Alert on new interesting strings
    """
    logger.info(f"    🔍 APK deep analysis: {app_name} ({package_name})")

    # Use volume path for temp APK storage if available
    volume_path = os.getenv("RAILWAY_VOLUME_MOUNT_PATH", "")
    if volume_path and os.path.isdir(volume_path):
        tmp_dir = os.path.join(volume_path, "apk_tmp")
    else:
        tmp_dir = "/tmp/apk_tmp"
    os.makedirs(tmp_dir, exist_ok=True)

    apk_path = os.path.join(tmp_dir, f"{package_name}.apk")

    try:
        # Step 1: Download
        if not download_apk(package_name, apk_path):
            logger.info(f"    Could not download APK for {app_name}")
            return

        # Step 2: Extract strings
        raw_strings = extract_strings_from_apk(apk_path)
        if not raw_strings:
            logger.info(f"    No strings extracted from {app_name} APK")
            return

        logger.info(f"    Extracted {len(raw_strings)} raw strings from APK")

        # Step 3: Filter to interesting UI strings
        filtered = filter_apk_strings(raw_strings)
        logger.info(f"    Filtered to {len(filtered)} interesting strings")

        if not filtered:
            return

        # Step 4: Diff against stored strings
        current_strings = set(filtered.keys())
        strings_hash = hashlib.sha256(json.dumps(sorted(current_strings)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "apk_strings", package_name)

        if old_hash and strings_hash != old_hash:
            old_strings = set(json.loads(old_content)) if old_content else set()
            new_strings = current_strings - old_strings
            removed_strings = old_strings - current_strings

            if new_strings:
                # Group by category
                high = [s for s in new_strings if filtered.get(s) == "high_interest"]
                features = [s for s in new_strings if filtered.get(s) == "feature_name"]
                ui = [s for s in new_strings if filtered.get(s) == "ui_text"]

                lines = []
                if high:
                    lines.append("**🔥 High Interest:**")
                    lines.extend(f"* {s}" for s in sorted(high)[:15])
                if features:
                    lines.append("**⭐ Feature Names:**")
                    lines.extend(f"* {s}" for s in sorted(features)[:15])
                if ui:
                    lines.append("**📝 New UI Text:**")
                    lines.extend(f"* {s}" for s in sorted(ui)[:20])

                alert_body = "\n".join(lines)

                send_discord_alert(
                    f"🔍 APK Strings: {app_name} v{version}",
                    f"**{len(new_strings)} new UI strings** found in APK decompilation\n\n{alert_body}",
                    color=0xE91E63,
                    url=f"https://play.google.com/store/apps/details?id={package_name}",
                )
                log_detection(conn, "apk_strings", app_name, "new_strings",
                              f"{len(new_strings)} strings", alert_body[:1500])
                logger.info(f"    🔥 {len(new_strings)} new APK strings for {app_name}!")

            if removed_strings and len(removed_strings) < 100:
                send_discord_alert(
                    f"🔍 APK Removed: {app_name} v{version}",
                    f"**{len(removed_strings)} strings removed** (feature launched or killed?)\n\n"
                    + "\n".join(f"* ~~{s}~~" for s in sorted(removed_strings)[:15]),
                    color=0xFF9800,
                    url=f"https://play.google.com/store/apps/details?id={package_name}",
                )

        elif not old_hash:
            logger.info(f"    Baseline stored: {len(filtered)} APK strings for {app_name}")

        # Store current strings
        store_hash(conn, "apk_strings", package_name, strings_hash,
                   json.dumps(list(current_strings)))

    finally:
        # Clean up memory from APK analysis
        for var in ['raw_strings', 'filtered', 'current_strings', 'old_strings',
                     'new_strings', 'removed_strings']:
            if var in dir():
                try:
                    exec(f"del {var}")
                except:
                    pass
        gc.collect()
        # Always clean up APK to save disk
        if os.path.exists(apk_path):
            os.remove(apk_path)
            logger.debug(f"    Cleaned up APK: {apk_path}")



# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 7: Chrome Flags / Platform Feature Flags
# ═══════════════════════════════════════════════════════════════════════════

CHROMIUM_FLAGS_URL = "https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/flag-metadata.json?format=TEXT"


def monitor_chrome_flags(conn):
    """Monitor Chromium source for new experimental flags."""
    logger.info("=== Chrome Flags Monitor ===")

    resp = fetch_url(CHROMIUM_FLAGS_URL)
    if not resp:
        # Fallback: check the flags descriptions
        resp = fetch_url("https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/flag_descriptions.cc?format=TEXT")
        if not resp:
            return

    import base64
    try:
        content = base64.b64decode(resp.text).decode("utf-8", errors="replace")
    except Exception:
        content = resp.text

    content_hash = hashlib.sha256(content.encode()).hexdigest()
    old_hash, old_content = get_stored_hash(conn, "chrome_flags", "main")

    if old_hash and content_hash != old_hash:
        # Try to find new flag names
        flag_names = set(re.findall(r'"([a-z][a-z0-9-]+)"', content))
        old_flags = set(json.loads(old_content)) if old_content else set()
        new_flags = flag_names - old_flags

        if new_flags:
            flag_list = "\n".join(f"• `{f}`" for f in sorted(new_flags)[:20])
            send_discord_alert(
                "New Chrome Flags",
                f"**{len(new_flags)} new experimental flags** detected\n\n{flag_list}",
                color=0xFFC107,
                url="https://chromestatus.com/features",
            )
            log_detection(conn, "chrome_flags", "main", "new_flags", f"{len(new_flags)} flags", flag_list)
            logger.info(f"  → {len(new_flags)} new Chrome flags")

        store_hash(conn, "chrome_flags", "main", content_hash, json.dumps(list(flag_names)))
    elif not old_hash:
        flag_names = set(re.findall(r'"([a-z][a-z0-9-]+)"', content))
        store_hash(conn, "chrome_flags", "main", content_hash, json.dumps(list(flag_names)))
        logger.info(f"  → Baseline: {len(flag_names)} Chrome flags stored")


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 8: DNS / Subdomain Discovery
# ═══════════════════════════════════════════════════════════════════════════

# Common subdomains that hint at new products/features
SUBDOMAIN_WORDLIST = [
    "api", "beta", "alpha", "dev", "staging", "preview", "canary", "next",
    "lab", "labs", "experiment", "test", "new", "v2", "v3", "studio",
    "pro", "plus", "premium", "enterprise", "dashboard", "console",
    "app", "mobile", "agent", "ai", "ml", "chat", "assistant",
    "docs", "developer", "developers", "build", "create", "design",
    "analytics", "insights", "reports", "search", "marketplace",
]


def check_subdomain(domain, subdomain):
    """Check if a subdomain resolves."""
    import socket
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(fqdn, None)
        return fqdn
    except (socket.gaierror, socket.timeout):
        return None


def monitor_subdomains(conn, targets):
    """
    Monitor domains for new subdomains.
    
    targets: list of dicts with keys:
        - name: display name
        - domain: base domain to check
        - extra_subdomains: optional additional subdomain prefixes to check
    """
    logger.info("=== Subdomain Monitor ===")

    for target in targets:
        name = target["name"]
        domain = target["domain"]
        extra = target.get("extra_subdomains", [])
        wordlist = SUBDOMAIN_WORDLIST + extra

        resolved = set()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_subdomain, domain, sub): sub
                for sub in wordlist
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resolved.add(result)

        resolved_hash = hashlib.sha256(json.dumps(sorted(resolved)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "subdomains", name)

        if old_hash and resolved_hash != old_hash:
            old_subs = set(json.loads(old_content)) if old_content else set()
            new_subs = resolved - old_subs

            if new_subs:
                sub_list = "\n".join(f"• `{s}`" for s in sorted(new_subs))
                send_discord_alert(
                    f"New Subdomains: {name}",
                    f"**{len(new_subs)} new subdomains** discovered\n\n{sub_list}",
                    color=0xE91E63,
                    url=f"https://{domain}",
                )
                log_detection(conn, "subdomains", name, "new_subdomain", f"{len(new_subs)} new", sub_list)
                logger.info(f"  → {len(new_subs)} new subdomains for {name}")

        store_hash(conn, "subdomains", name, resolved_hash, json.dumps(list(resolved)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 9: Generic Page Change Monitor (Changelog, Blog, Status Pages)
# ═══════════════════════════════════════════════════════════════════════════

def monitor_pages(conn, targets):
    """
    Simple page change monitor for changelogs, blogs, status pages.
    
    targets: list of dicts with keys:
        - name: display name
        - url: page URL
        - selector: optional CSS selector to narrow monitoring scope
    """
    logger.info("=== Page Change Monitor ===")

    for i, target in enumerate(targets, 1):
        name = target["name"]
        url = target["url"]
        selector = target.get("selector", None)
        if i % 10 == 0 or i == len(targets):
            logger.info(f"    Pages [{i}/{len(targets)}]: {name}")

        resp = fetch_url(url)
        if not resp:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        if selector:
            elements = soup.select(selector)
            content = "\n".join(el.get_text(strip=True) for el in elements)
        else:
            content = extract_text_content(resp.text)

        content_hash = hashlib.sha256(content.encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "page_change", name)

        if old_hash and content_hash != old_hash:
            added, removed = diff_text(old_content or "", content)
            if added:
                sample = "\n".join(f"+ {line[:120]}" for line in list(added)[:8])
                send_discord_alert(
                    f"Page Updated: {name}",
                    f"**{len(added)} new lines detected**\n\n```diff\n{sample}\n```",
                    color=0x607D8B,
                    url=url,
                )
                log_detection(conn, "page_change", name, "page_update", f"Updated: {name}", sample[:1000])
                logger.info(f"  → Page change: {name}")

        store_hash(conn, "page_change", name, content_hash, content)


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 10: FCC Equipment Authorization Filings
# Companies MUST file with FCC before releasing hardware devices.
# Apple, Google, Meta, Samsung all file weeks before announcement.
# ═══════════════════════════════════════════════════════════════════════════

# FCC Grantee Codes for major companies (first 3 chars of FCC ID)
FCC_GRANTEE_CODES = {
    "BCG": "Apple (AAPL)",
    "A3L": "Samsung",
    "YCVQ2": "Google (GOOGL)",
    "2AGOZ": "Meta/Oculus (META)",
    "2AFIW": "Meta Reality Labs (META)",
    "C3K": "Microsoft (MSFT)",
    "2ABYE": "Amazon Devices (AMZN)",
    "Z4G": "Amazon Lab126 (AMZN)",
    "VOB": "NVIDIA (NVDA)",
    "2ABCB": "Tesla (TSLA)",
    "2AC7Z": "SpaceX/Starlink",
    "PY7": "Sony/PlayStation",
    "RLUW": "Nintendo",
    "BEJEP": "Qualcomm (QCOM)",
    "Q87": "Samsung Electronics",
    "R7PEA": "Broadcom (AVGO)",
    "2ADNG": "Snap Inc (SNAP)",
    "2AA3B": "Sonos",
    "2AHDO": "Roku (ROKU)",
    "2AC23": "Rivian (RIVN)",
    "2ADZM": "Ring/Amazon (AMZN)",
}


def monitor_fcc(conn, grantee_codes=None):
    """
    Monitor FCC Equipment Authorization for new device filings.
    Uses the FCC Equipment Authorization Search API.
    """
    logger.info("=== FCC Equipment Authorization Monitor ===")

    if grantee_codes is None:
        grantee_codes = FCC_GRANTEE_CODES

    for i, (code, company) in enumerate(grantee_codes.items(), 1):
        logger.info(f"    FCC [{i}/{len(grantee_codes)}]: {company}")
        # FCC OET Equipment Authorization search
        url = f"https://apps.fcc.gov/oetcf/eas/reports/GenericSearch.cfm?RequestTimeout=500&calession=&id_grantee={code}&id_product_code=&applicant_name=&grant_date_from=&grant_date_to=&comments=&application_purpose=&grant_code=&id_fcc=&facility_id=&fcc_search_type=&show_records=10"
        resp = fetch_url(url)
        if not resp:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        # Extract filing entries from the results table
        rows = soup.find_all("tr")
        filings = []
        for row in rows:
            cells = row.find_all("td")
            if len(cells) >= 4:
                text = " | ".join(c.get_text(strip=True) for c in cells[:6])
                if code.upper() in text.upper() or len(cells) >= 5:
                    filings.append(text[:300])

        if not filings:
            continue

        filings_hash = hashlib.sha256(json.dumps(filings[:20]).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "fcc", code)

        if old_hash and filings_hash != old_hash:
            old_filings = set(json.loads(old_content)) if old_content else set()
            new_filings = [f for f in filings[:20] if f not in old_filings]

            if new_filings:
                details = "\n".join(f"* {f[:150]}" for f in new_filings[:8])
                send_discord_alert(
                    f"FCC Filing: {company}",
                    f"**{len(new_filings)} new device filing(s)** detected\n\n{details}",
                    fields=[
                        {"name": "Grantee Code", "value": code, "inline": True},
                        {"name": "Company", "value": company, "inline": True},
                    ],
                    color=0xFF5722,
                    url=url,
                )
                log_detection(conn, "fcc", code, "new_filing", f"FCC: {company}", details[:1000])
                logger.info(f"  -> New FCC filing: {company} ({len(new_filings)} filings)")

        store_hash(conn, "fcc", code, filings_hash, json.dumps(filings[:20]))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 11: USPTO Trademark Filings (TSDR)
# New product names are trademarked before launch. Catches codenames,
# product names, and service brands weeks/months before announcement.
# ═══════════════════════════════════════════════════════════════════════════

USPTO_OWNERS = {
    "Apple Inc.": "AAPL",
    "Google LLC": "GOOGL",
    "Alphabet Inc.": "GOOGL",
    "Microsoft Corporation": "MSFT",
    "Meta Platforms": "META",
    "Amazon Technologies": "AMZN",
    "Amazon.com": "AMZN",
    "NVIDIA Corporation": "NVDA",
    "Tesla, Inc.": "TSLA",
    "Salesforce": "CRM",
    "Adobe Inc.": "ADBE",
    "Oracle": "ORCL",
    "Palantir Technologies": "PLTR",
    "Snowflake Inc.": "SNOW",
    "CrowdStrike": "CRWD",
    "Coinbase": "COIN",
    "Snap Inc.": "SNAP",
    "Pinterest": "PINS",
    "Block, Inc.": "XYZ",
    "Shopify": "SHOP",
    "Uber Technologies": "UBER",
    "Airbnb": "ABNB",
    "Netflix": "NFLX",
    "Spotify": "SPOT",
    "Roblox": "RBLX",
    "Unity Technologies": "U",
    "Qualcomm": "QCOM",
    "Broadcom": "AVGO",
    "Intel Corporation": "INTC",
    "Advanced Micro Devices": "AMD",
    "Cloudflare": "NET",
    "Datadog": "DDOG",
    "MongoDB": "MDB",
    "Twilio": "TWLO",
    "Atlassian": "TEAM",
    "HubSpot": "HUBS",
    "ServiceNow": "NOW",
    "Workday": "WDAY",
    "Intuit": "INTU",
    "Palo Alto Networks": "PANW",
    "Fortinet": "FTNT",
    "Zscaler": "ZS",
    "SentinelOne": "S",
    "Okta": "OKTA",
    "Zoom Video": "ZM",
    "DocuSign": "DOCU",
    "Dropbox": "DBX",
    "DoorDash": "DASH",
    "Robinhood": "HOOD",
    "PayPal": "PYPL",
    "Reddit": "RDDT",
    "Duolingo": "DUOL",
    "AppLovin": "APP",
    "Trade Desk": "TTD",
    "Rivian": "RIVN",
    "Lucid Motors": "LCID",
    "C3.ai": "AI",
    "SoundHound": "SOUN",
    "UiPath": "PATH",
    "IonQ": "IONQ",
    "Rigetti": "RGTI",
    "Anthropic": "Private",
    "OpenAI": "Private",
    "xAI": "Private",
    "Perplexity": "Private",
}


def monitor_trademarks(conn, owners=None):
    """
    Monitor USPTO TESS for new trademark filings by tech companies.
    """
    logger.info("=== USPTO Trademark Monitor ===")

    if owners is None:
        owners = USPTO_OWNERS

    total_owners = len(owners)
    for i, (owner_name, ticker) in enumerate(owners.items(), 1):
        logger.info(f"    Trademark [{i}/{total_owners}]: {owner_name}")
        # USPTO TESS search by owner name
        search_url = f"https://tmsearch.uspto.gov/bin/gate.exe?f=searchss&state=4810:1.1.1&p_s_PARA1=&p_taession=&BackReference=&p_L=50&p_plural=yes&p_s_PARA2={requests.utils.quote(owner_name)}&p_s_PARA1=&p_op_ALL=AND&a_default=search&a_search=Submit+Query&a_search=Submit"
        resp = fetch_url(search_url)
        if not resp:
            # Fallback: try the simpler TESS search
            tess_url = f"https://tmsearch.uspto.gov/bin/showfield?f=tess&state=4810:1.1.1&p_search=searchss&p_s_PARA2={requests.utils.quote(owner_name)}&p_L=50"
            resp = fetch_url(tess_url)
            if not resp:
                continue

        soup = BeautifulSoup(resp.text, "html.parser")
        # Look for trademark entries
        text_content = soup.get_text()
        # Extract serial numbers and mark names
        serial_matches = re.findall(r'(\d{8})\s*[-]\s*([A-Z][A-Z0-9\s\.\-]+)', text_content)
        marks = [(s, m.strip()) for s, m in serial_matches if len(m.strip()) > 1]

        if not marks:
            # Try alternate pattern
            marks_alt = re.findall(r'(?:Word Mark|Mark)[\s:]+([A-Z][A-Z0-9\s]+)', text_content)
            marks = [(str(i), m.strip()) for i, m in enumerate(marks_alt) if len(m.strip()) > 2]

        if not marks:
            continue

        marks_hash = hashlib.sha256(json.dumps(marks[:30]).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "trademark", owner_name)

        if old_hash and marks_hash != old_hash:
            old_marks = set(tuple(m) for m in json.loads(old_content)) if old_content else set()
            new_marks = [m for m in marks[:30] if tuple(m) not in old_marks]

            if new_marks:
                mark_list = "\n".join(f"* **{m[1]}** (SN: {m[0]})" for m in new_marks[:10])
                send_discord_alert(
                    f"New Trademark: {owner_name} ({ticker})",
                    f"**{len(new_marks)} new trademark filing(s)**\n\n{mark_list}",
                    color=0x9C27B0,
                    url="https://tmsearch.uspto.gov/",
                )
                log_detection(conn, "trademark", owner_name, "new_trademark", f"{len(new_marks)} marks", mark_list[:1000])
                logger.info(f"  -> New trademark: {owner_name} ({len(new_marks)} marks)")

        store_hash(conn, "trademark", owner_name, marks_hash, json.dumps(marks[:30]))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 12: Certificate Transparency Logs (crt.sh)
# When companies register new SSL certs, they appear in public CT logs.
# This reveals new subdomains/services BEFORE they launch.
# (How people discovered Apple Vision Pro, Google Bard, etc.)
# ═══════════════════════════════════════════════════════════════════════════

def monitor_ct_logs(conn, targets):
    """
    Monitor Certificate Transparency logs via crt.sh for new certificates.
    Aggressively filters infrastructure noise - only alerts on subdomains
    that suggest new products, features, partnerships, or acquisitions.
    """
    logger.info("=== Certificate Transparency Monitor ===")

    # Infrastructure noise - these subdomains are never interesting
    CT_NOISE_KEYWORDS = [
        # CDN / Static
        "cdn", "static", "assets", "asset", "media.", "img.", "images.",
        "photos", "photo-", "video.", "fonts", "css.", "resources",
        # Load balancing / Infra
        "lb-", "lb.", "wl-", "haproxy", "nginx", "proxy", "gateway.", "gateway-",
        "edge-", "node-", "replica", "shard", "cluster",
        # Email
        "mail", "smtp", "imap", "pop3", "mx.", "email", "postfix", "dkim",
        "spf.", "dmarc", "bounce",
        # Monitoring / Ops
        "monitor", "metrics", "logging.", "grafana", "prometheus",
        "sentry", "health.", "ping.", "-ping.", "heartbeat", "nagios",
        # CI/CD / Dev / Staging
        "ci.", "ci-", "cd.", "cd-", "build.", "build-", "deploy", "staging",
        "stg.", "stg-",
        "qa.", "qa-", "uat.", "uat-", "test.", "test-", "testing",
        "sandbox", "dev.", "dev-", "dev1", "dev2", "dev3", "dev4", "dev5",
        "preprod", "pre-prod", "canary.", "internal.", "corp.",
        # DNS / Network
        "ns1", "ns2", "ns3", "dns.", "vpn.", "vpn-", "bastion", "jump",
        # Auth
        "sso.", "auth.", "oauth.", "login.", "signin.", "idp.", "saml",
        # Tracking / Analytics
        "track", "pixel.", "/pixel",
        "beacon", "analytics", "telemetry", "collect.",
        # Storage / DB
        "db.", "db-", "redis.", "mongo.", "mysql.", "postgres.", "elastic.",
        "kafka.", "rabbit.", "memcache", "s3.",
        # Common known subdomains (not interesting)
        "www.", "api.", "api-", "admin.", "console.", "dashboard.",
        "docs.", "help.", "support.", "billing", "invoic",
        "careers", "jobs.", "ir.", "investor", "status.",
        # Delivery/logistics (DoorDash-type noise)
        "dropoff", "fulfillment", "handoff", "delivery-",
        "dasher", "driver.", "courier", "merchant-",
        # Container / Registry
        "autopush", "gcr.", "ecr.", "registry.",
        "cache.", "varnish", "fastly", "prism",
    ]

    CT_NOISE_REGEX = re.compile(
        r"^[0-9]"                       # Starts with number (7kx9f, 3abc)
        r"|^ip-\d+"                     # IP-based
        r"|^i-[a-f0-9]+"               # Instance IDs
        r"|^ec2-"                       # AWS
        r"|-\d{8,}"                    # Timestamp in name
        r"|-[a-f0-9]{8,}$"            # Trailing hash
        r"|^[a-z]-[a-z0-9]{4,}$"      # Single letter + hash (a-b3x9f)
        r"|^[a-z]{2,3}[0-9]{2,}$"     # Short prefix + numbers (ns1, stg42)
        r"|^[a-z]{2,6}[0-9]{2,}$"     # Letters then 2+ digits (zgqup72, abc123)
    )

    for target in targets:
        tname = target["name"]
        domain = target["domain"]

        try:
            resp = session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json", "exclude": "expired"},
                timeout=20
            )
            if resp.status_code != 200:
                continue
            certs = resp.json()
        except Exception:
            continue

        cert_names = set()
        for cert in certs[:200]:
            cn = cert.get("common_name") or ""
            name_value = cert.get("name_value") or ""
            for n in [cn] + name_value.split("\n"):
                if not n:
                    continue
                n = n.strip().lower()
                if n and n.endswith(domain.lower()) and "*" not in n:
                    cert_names.add(n)

        if not cert_names:
            continue

        names_hash = hashlib.sha256(json.dumps(sorted(cert_names)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "ct_logs", tname)

        if old_hash and names_hash != old_hash:
            old_names = set(json.loads(old_content)) if old_content else set()
            new_names = cert_names - old_names

            if new_names:
                interesting = []
                for n in new_names:
                    subdomain = n.replace(f".{domain.lower()}", "")

                    # Skip noise keywords
                    if any(noise in subdomain for noise in CT_NOISE_KEYWORDS):
                        continue

                    # Skip auto-generated names
                    if CT_NOISE_REGEX.search(subdomain):
                        continue

                    # Skip very short subdomains
                    if len(subdomain) < 3:
                        continue

                    # Skip deeply nested (infra-like)
                    if subdomain.count(".") > 2:
                        continue

                    # Skip short alphanumeric strings that look like hashes
                    # (low vowel ratio = probably random, e.g. "zgqup7", "bxkrf3")
                    if re.match(r"^[a-z0-9]{4,8}$", subdomain):
                        vowels = sum(1 for c in subdomain if c in "aeiou")
                        if vowels / len(subdomain) < 0.25:
                            continue

                    interesting.append(n)

                if interesting:
                    name_list = "\n".join(f"* `{n}`" for n in sorted(interesting)[:15])
                    link = f"https://crt.sh/?q=%25.{domain}"
                    send_discord_alert(
                        f"New SSL Certs: {tname}",
                        f"**{len(interesting)} new certificate(s)** found in CT logs\n\n{name_list}",
                        color=0x00BCD4,
                        url=link,
                    )
                    log_detection(conn, "ct_logs", tname, "new_cert",
                                  f"{len(interesting)} certs", name_list[:1000])
                    logger.info(f"  -> New CT certs: {tname} ({len(interesting)} new)")

        store_hash(conn, "ct_logs", tname, names_hash, json.dumps(list(cert_names)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 13: robots.txt Monitoring
# Companies add paths to robots.txt BEFORE pages go live.
# Reveals hidden URLs, unreleased products, and internal tools.
# ═══════════════════════════════════════════════════════════════════════════

def monitor_robots_txt(conn, targets):
    """
    Monitor robots.txt for new Disallow/Allow paths that hint at upcoming features.
    
    targets: list of dicts with keys:
        - name: display name
        - domain: full domain (e.g., "www.openai.com")
    """
    logger.info(f"=== robots.txt Monitor ({len(targets)} sites) ===")

    for i, target in enumerate(targets, 1):
        name = target["name"]
        domain = target["domain"]

        url = f"https://{domain}/robots.txt"
        resp = fetch_url(url)
        if not resp:
            continue

        content = resp.text
        # Extract all paths from Disallow/Allow directives
        paths = set()
        for line in content.split("\n"):
            line = line.strip()
            match = re.match(r'(?:Dis)?[Aa]llow:\s*(.+)', line)
            if match:
                path = match.group(1).strip()
                if path and path != "/" and path != "*":
                    paths.add(path)
            # Also capture Sitemap URLs
            match = re.match(r'[Ss]itemap:\s*(.+)', line)
            if match:
                paths.add(f"SITEMAP: {match.group(1).strip()}")

        if not paths:
            continue

        paths_hash = hashlib.sha256(json.dumps(sorted(paths)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "robots_txt", name)

        if old_hash and paths_hash != old_hash:
            old_paths = set(json.loads(old_content)) if old_content else set()
            new_paths = paths - old_paths
            removed_paths = old_paths - paths

            if new_paths:
                path_list = "\n".join(f"+ `{p}`" for p in sorted(new_paths)[:15])
                send_discord_alert(
                    f"robots.txt Changed: {name}",
                    f"**{len(new_paths)} new path(s)** added\n\n```diff\n{path_list}\n```",
                    color=0x795548,
                    url=url,
                )
                log_detection(conn, "robots_txt", name, "new_paths", f"{len(new_paths)} paths", path_list[:1000])
                logger.info(f"  -> robots.txt change: {name} ({len(new_paths)} new paths)")

            if removed_paths:
                removed_list = "\n".join(f"- `{p}`" for p in sorted(removed_paths)[:15])
                send_discord_alert(
                    f"robots.txt Removed: {name}",
                    f"**{len(removed_paths)} path(s) removed** (may be going live)\n\n```diff\n{removed_list}\n```",
                    color=0xFF9800,
                    url=url,
                )

        store_hash(conn, "robots_txt", name, paths_hash, json.dumps(list(paths)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 14: SEC EDGAR 8-K Filings
# Material events, acquisitions, product announcements, executive changes.
# 8-K filings are required for material events within 4 business days.
# ═══════════════════════════════════════════════════════════════════════════

SEC_COMPANY_CIKS = {
    "AAPL": "0000320193",
    "GOOGL": "0001652044",
    "MSFT": "0000789019",
    "META": "0001326801",
    "AMZN": "0001018724",
    "NVDA": "0001045810",
    "TSLA": "0001318605",
    "NFLX": "0001065280",
    "CRM": "0001108524",
    "ADBE": "0000796343",
    "ORCL": "0001341439",
    "AMD": "0000002488",
    "INTC": "0000050863",
    "PLTR": "0001321655",
    "SNOW": "0001640147",
    "CRWD": "0001535527",
    "NET": "0001477333",
    "DDOG": "0001561550",
    "SHOP": "0001594805",
    "COIN": "0001679788",
    "HOOD": "0001783879",
    "UBER": "0001543151",
    "ABNB": "0001559720",
    "SNAP": "0001564408",
    "PINS": "0001562088",
    "RDDT": "0001713445",
    "SPOT": "0001639920",
    "RBLX": "0001315098",
    "ZM": "0001585521",
    "PYPL": "0001633917",
    "DASH": "0001792789",
    "PANW": "0001327567",
    "ZS": "0001713683",
    "OKTA": "0001660134",
    "MDB": "0001441816",
    "TWLO": "0001447669",
    "ESTC": "0001707753",
    "TEAM": "0001650372",
    "NOW": "0001373715",
    "WDAY": "0001327811",
    "INTU": "0000896878",
    "QCOM": "0000804328",
    "AVGO": "0001649338",
    "ARM": "0001973239",
    "MU": "0000723125",
    "DUOL": "0001562088",
    "APP": "0001498547",
    "TTD": "0001671933",
    "IONQ": "0001812364",
    "S": "0001804220",
    "FTNT": "0001262039",
    "DBX": "0001467623",
    "DOCU": "0001261654",
    "RIVN": "0001874178",
    "AI": "0001577526",
    "SOUN": "0001840856",
    "PATH": "0001734722",
    "ROKU": "0001428439",
    "TOST": "0001650164",
    "U": "0001810806",
    "HUBS": "0001404655",
    "CFLT": "0001816613",
    "GTLB": "0001653482",
    "DOCN": "0001582961",
}


def monitor_sec_filings(conn, cik_map=None):
    """
    Monitor SEC EDGAR for new 8-K filings (material events).
    Uses the EDGAR full-text search and recent filings RSS.
    """
    logger.info("=== SEC EDGAR 8-K Monitor ===")

    if cik_map is None:
        cik_map = SEC_COMPANY_CIKS

    headers = {
        "User-Agent": "FeatureIntel research@example.com",
        "Accept": "application/json",
    }

    total_ciks = len(cik_map)
    for i, (ticker, cik) in enumerate(cik_map.items(), 1):
        logger.info(f"    SEC [{i}/{total_ciks}]: {ticker}")
        # EDGAR API for recent filings
        url = f"https://efts.sec.gov/LATEST/search-index?q=%22{cik}%22&dateRange=custom&startdt={(datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')}&enddt={datetime.now(timezone.utc).strftime('%Y-%m-%d')}&forms=8-K"
        # Simpler approach: RSS feed
        rss_url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type=8-K&dateb=&owner=include&count=5&search_text=&action=getcompany&output=atom"
        try:
            resp = requests.get(rss_url, headers=headers, timeout=15)
            if resp.status_code != 200:
                continue
        except Exception:
            continue

        soup = BeautifulSoup(resp.text, "xml")
        entries = soup.find_all("entry")

        filings = []
        for entry in entries[:5]:
            title = entry.find("title")
            updated = entry.find("updated")
            link = entry.find("link")
            summary = entry.find("summary")
            if title:
                filings.append({
                    "title": title.get_text(strip=True),
                    "date": updated.get_text(strip=True) if updated else "",
                    "link": link.get("href", "") if link else "",
                    "summary": (summary.get_text(strip=True)[:300] if summary else ""),
                })

        if not filings:
            continue

        filings_hash = hashlib.sha256(json.dumps(filings).encode()).hexdigest()
        old_hash, _ = get_stored_hash(conn, "sec_8k", ticker)

        if old_hash and filings_hash != old_hash:
            filing_details = "\n".join(
                f"* **{f['title'][:100]}**\n  {f['date'][:10]} | [Link]({f['link']})"
                for f in filings[:5]
            )
            send_discord_alert(
                f"SEC 8-K Filing: {ticker}",
                f"**New material event filing**\n\n{filing_details}",
                color=0xF44336,
                url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type=8-K&dateb=&owner=include&count=10",
            )
            log_detection(conn, "sec_8k", ticker, "8k_filing", f"8-K: {ticker}", filing_details[:1000])
            logger.info(f"  -> New 8-K: {ticker}")

        store_hash(conn, "sec_8k", ticker, filings_hash)


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 15: npm/PyPI Package Publishing
# Companies publish SDK updates and internal packages that leak upcoming
# API features, new services, and product names.
# ═══════════════════════════════════════════════════════════════════════════

NPM_PACKAGES = {
    # OpenAI
    "openai": "OpenAI", "@openai/agents": "OpenAI",
    # Anthropic
    "@anthropic-ai/sdk": "Anthropic", "@anthropic-ai/bedrock-sdk": "Anthropic",
    # Google
    "@google/generative-ai": "Google (GOOGL)", "@google-cloud/aiplatform": "Google (GOOGL)",
    "@google-cloud/vertexai": "Google (GOOGL)",
    # Microsoft
    "@azure/openai": "Microsoft (MSFT)", "@microsoft/teams-js": "Microsoft (MSFT)",
    "@microsoft/microsoft-graph-client": "Microsoft (MSFT)",
    # Meta
    "@llama-stack/client": "Meta (META)", "@facebook/react": "Meta (META)",
    # AWS
    "@aws-sdk/client-bedrock-runtime": "Amazon (AMZN)", "@aws-sdk/client-bedrock": "Amazon (AMZN)",
    # Stripe
    "stripe": "Stripe",
    # Shopify
    "@shopify/hydrogen": "Shopify (SHOP)", "@shopify/cli": "Shopify (SHOP)",
    # Cloudflare
    "wrangler": "Cloudflare (NET)", "@cloudflare/ai": "Cloudflare (NET)",
    # Others
    "@slack/web-api": "Salesforce/Slack (CRM)",
    "@notionhq/client": "Notion",
    "@figma/plugin-typings": "Figma",
    "@supabase/supabase-js": "Supabase",
    "firebase": "Google (GOOGL)",
    "@vercel/sdk": "Vercel",
}

PYPI_PACKAGES = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google-generativeai": "Google (GOOGL)",
    "google-cloud-aiplatform": "Google (GOOGL)",
    "boto3": "Amazon (AMZN)",
    "azure-ai-inference": "Microsoft (MSFT)",
    "langchain": "LangChain",
    "langchain-core": "LangChain",
    "llama-index": "LlamaIndex",
    "transformers": "Hugging Face",
    "torch": "Meta/PyTorch (META)",
    "tensorflow": "Google (GOOGL)",
    "crewai": "CrewAI",
    "stripe": "Stripe",
    "snowflake-connector-python": "Snowflake (SNOW)",
    "databricks-sdk": "Databricks",
    "palantir-sdk": "Palantir (PLTR)",
    "salesforce-bulk": "Salesforce (CRM)",
    "crowdstrike-falconpy": "CrowdStrike (CRWD)",
}


def monitor_npm_packages(conn, packages=None):
    """Monitor npm registry for package version updates."""
    logger.info("=== npm Package Monitor ===")

    if packages is None:
        packages = NPM_PACKAGES

    for pkg_name, company in packages.items():
        url = f"https://registry.npmjs.org/{pkg_name}/latest"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception:
            continue

        version = data.get("version", "")
        description = data.get("description", "")
        # Check for interesting keywords in package description or dependencies
        deps = list(data.get("dependencies", {}).keys())

        version_hash = hashlib.sha256(f"{version}:{description}:{','.join(deps)}".encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "npm", pkg_name)

        if old_hash and version_hash != old_hash:
            old_version = old_content if old_content else "unknown"
            send_discord_alert(
                f"npm Update: {pkg_name} ({company})",
                f"**{old_version} -> {version}**\n\n{description[:500]}",
                fields=[
                    {"name": "Package", "value": f"[{pkg_name}](https://www.npmjs.com/package/{pkg_name})", "inline": True},
                    {"name": "New Deps", "value": ", ".join(deps[:10]) or "None", "inline": False},
                ],
                color=0xCB3837,
                url=f"https://www.npmjs.com/package/{pkg_name}",
            )
            log_detection(conn, "npm", pkg_name, "version_update", f"{pkg_name} {version}", description[:500])
            logger.info(f"  -> npm update: {pkg_name} {version}")

        store_hash(conn, "npm", pkg_name, version_hash, version)


def monitor_pypi_packages(conn, packages=None):
    """Monitor PyPI for package version updates."""
    logger.info("=== PyPI Package Monitor ===")

    if packages is None:
        packages = PYPI_PACKAGES

    for pkg_name, company in packages.items():
        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception:
            continue

        info = data.get("info", {})
        version = info.get("version", "")
        summary = info.get("summary", "")

        version_hash = hashlib.sha256(f"{version}:{summary}".encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "pypi", pkg_name)

        if old_hash and version_hash != old_hash:
            old_version = old_content if old_content else "unknown"
            send_discord_alert(
                f"PyPI Update: {pkg_name} ({company})",
                f"**{old_version} -> {version}**\n\n{summary[:500]}",
                color=0x3775A9,
                url=f"https://pypi.org/project/{pkg_name}/",
            )
            log_detection(conn, "pypi", pkg_name, "version_update", f"{pkg_name} {version}", summary[:500])
            logger.info(f"  -> PyPI update: {pkg_name} {version}")

        store_hash(conn, "pypi", pkg_name, version_hash, version)


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 16: Job Posting Monitor
# Companies hire for unannounced products months before launch.
# Job titles like "Sr. Engineer, Project Titan" or "Robotaxi Platform Lead"
# directly reveal product direction.
# ═══════════════════════════════════════════════════════════════════════════

def monitor_job_postings(conn, targets):
    """
    Monitor company career pages/APIs for revealing job postings.
    Uses Greenhouse, Lever, and direct career page scraping.
    
    targets: list of dicts with keys:
        - name: company name
        - ticker: stock ticker
        - greenhouse_id: Greenhouse board token (if applicable)
        - lever_id: Lever company slug (if applicable)
        - careers_url: Direct careers page URL (fallback)
        - keywords: list of keywords that signal interesting product directions
    """
    logger.info("=== Job Posting Monitor ===")

    for target in targets:
        name = target["name"]
        ticker = target.get("ticker", "")
        keywords = [kw.lower() for kw in target.get("keywords", [])]
        jobs = []

        # Greenhouse API (used by many tech companies)
        if target.get("greenhouse_id"):
            gh_url = f"https://boards-api.greenhouse.io/v1/boards/{target['greenhouse_id']}/jobs"
            try:
                resp = requests.get(gh_url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for job in data.get("jobs", []):
                        title = job.get("title", "")
                        location = job.get("location", {}).get("name", "")
                        dept = ""
                        if job.get("departments"):
                            dept = job["departments"][0].get("name", "")
                        jobs.append(f"{title} | {dept} | {location}")
            except Exception as e:
                logger.debug(f"Greenhouse error for {name}: {e}")

        # Lever API
        elif target.get("lever_id"):
            lever_url = f"https://api.lever.co/v0/postings/{target['lever_id']}"
            try:
                resp = requests.get(lever_url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for job in data:
                        title = job.get("text", "")
                        team = job.get("categories", {}).get("team", "")
                        location = job.get("categories", {}).get("location", "")
                        jobs.append(f"{title} | {team} | {location}")
            except Exception as e:
                logger.debug(f"Lever error for {name}: {e}")

        # Direct careers page scrape (fallback)
        elif target.get("careers_url"):
            resp = fetch_url(target["careers_url"])
            if resp:
                soup = BeautifulSoup(resp.text, "html.parser")
                # Extract job titles from common patterns
                for tag in soup.find_all(["a", "h2", "h3", "h4", "span", "div"]):
                    text = tag.get_text(strip=True)
                    # Heuristic: job titles are 20-120 chars, contain role words
                    if 20 < len(text) < 120 and any(w in text.lower() for w in
                        ["engineer", "manager", "director", "lead", "scientist",
                         "researcher", "designer", "analyst", "architect", "head of",
                         "vp of", "developer", "specialist", "strategist"]):
                        jobs.append(text)

        if not jobs:
            continue

        # Deduplicate
        jobs = list(dict.fromkeys(jobs))

        jobs_hash = hashlib.sha256(json.dumps(sorted(jobs)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "jobs", name)

        if old_hash and jobs_hash != old_hash:
            old_jobs = set(json.loads(old_content)) if old_content else set()
            new_jobs = [j for j in jobs if j not in old_jobs]

            # Filter for interesting keywords
            interesting_jobs = []
            for job in new_jobs:
                job_lower = job.lower()
                if not keywords or any(kw in job_lower for kw in keywords):
                    interesting_jobs.append(job)

            if interesting_jobs:
                job_list = "\n".join(f"* {j[:120]}" for j in interesting_jobs[:15])
                send_discord_alert(
                    f"New Job Postings: {name} ({ticker})",
                    f"**{len(interesting_jobs)} interesting new roles**\n\n{job_list}",
                    color=0x00BCD4,
                    url=target.get("careers_url", target.get("greenhouse_id", "")),
                )
                log_detection(conn, "jobs", name, "new_postings", f"{len(interesting_jobs)} new roles", job_list[:1000])
                logger.info(f"  -> {len(interesting_jobs)} new job postings: {name}")

        store_hash(conn, "jobs", name, jobs_hash, json.dumps(jobs))


# Default job monitoring targets
JOB_TARGETS = [
    {"name": "OpenAI", "ticker": "", "greenhouse_id": "openai", "keywords": ["robotics", "hardware", "search", "agent", "safety", "alignment", "government"]},
    {"name": "Anthropic", "ticker": "", "greenhouse_id": "anthropic", "keywords": ["agent", "safety", "enterprise", "government", "product", "hardware"]},
    {"name": "Google DeepMind", "ticker": "GOOGL", "lever_id": "deepmind", "keywords": ["gemini", "robotics", "agent", "hardware", "quantum"]},
    {"name": "Meta AI", "ticker": "META", "careers_url": "https://www.metacareers.com/jobs?q=AI&teams[0]=Artificial%20Intelligence", "keywords": ["llama", "ar", "vr", "robotics", "agent", "quest", "orion"]},
    {"name": "xAI", "ticker": "", "lever_id": "xai", "keywords": ["grok", "colossus", "inference", "data"]},
    {"name": "Tesla", "ticker": "TSLA", "greenhouse_id": "tesla", "keywords": ["optimus", "robot", "dojo", "fsd", "autopilot", "robotaxi", "energy"]},
    {"name": "Apple", "ticker": "AAPL", "careers_url": "https://jobs.apple.com/en-us/search?search=machine+learning", "keywords": ["siri", "intelligence", "vision", "spatial", "health", "car", "robotics"]},
    {"name": "NVIDIA", "ticker": "NVDA", "greenhouse_id": "nvidia", "keywords": ["blackwell", "rubin", "nim", "omniverse", "cosmos", "robotics", "ace"]},
    {"name": "Palantir", "ticker": "PLTR", "greenhouse_id": "palantir", "keywords": ["aip", "foundry", "defense", "agent", "warp"]},
    {"name": "CrowdStrike", "ticker": "CRWD", "greenhouse_id": "crowdstrike", "keywords": ["charlotte", "ai", "next-gen", "xdr"]},
    {"name": "Snowflake", "ticker": "SNOW", "greenhouse_id": "snowflake", "keywords": ["cortex", "arctic", "ai", "agent", "polaris"]},
    {"name": "Coinbase", "ticker": "COIN", "greenhouse_id": "coinbase", "keywords": ["base", "layer2", "agent", "defi", "staking", "derivatives"]},
    {"name": "Databricks", "ticker": "", "greenhouse_id": "databricks", "keywords": ["mosaic", "model", "agent", "governance"]},
    {"name": "Scale AI", "ticker": "", "lever_id": "scaleai", "keywords": ["government", "defense", "donovan", "auto"]},
    {"name": "Figma", "ticker": "", "greenhouse_id": "figma", "keywords": ["ai", "slides", "dev-mode", "component"]},
    {"name": "Stripe", "ticker": "", "greenhouse_id": "stripe", "keywords": ["crypto", "stablecoin", "banking", "identity", "issuing"]},
    {"name": "Perplexity", "ticker": "", "lever_id": "perplexity-ai", "keywords": ["enterprise", "finance", "agent", "ads"]},
]



# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 18: DNS TXT/CNAME Record Monitor
# Companies add DNS records for new services (Google Workspace verification,
# SPF for new email domains, CNAME for new product subdomains).
# ═══════════════════════════════════════════════════════════════════════════

def monitor_dns_records(conn, targets):
    """Monitor DNS TXT and CNAME records for changes revealing new services."""
    logger.info("=== DNS Record Monitor ===")

    import socket

    for target in targets:
        name = target["name"]
        domain = target["domain"]
        ticker = target.get("ticker", "")

        records = {}
        
        # Check TXT records via DNS-over-HTTPS (Google)
        for record_type in ["TXT", "CNAME", "MX", "NS"]:
            try:
                doh_url = f"https://dns.google/resolve?name={domain}&type={record_type}"
                resp = requests.get(doh_url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get("Answer", [])
                    for answer in answers:
                        rdata = answer.get("data", "")
                        records[f"{record_type}:{rdata[:200]}"] = rdata[:200]
            except Exception:
                pass

        # Also check common service-specific subdomains
        service_subs = ["_dmarc", "_mta-sts", "_domainkey", "selector1._domainkey", "selector2._domainkey"]
        for sub in service_subs:
            fqdn = f"{sub}.{domain}"
            try:
                doh_url = f"https://dns.google/resolve?name={fqdn}&type=TXT"
                resp = requests.get(doh_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    for answer in data.get("Answer", []):
                        rdata = answer.get("data", "")
                        records[f"TXT:{fqdn}:{rdata[:200]}"] = rdata[:200]
            except Exception:
                pass

        if not records:
            continue

        records_hash = hashlib.sha256(json.dumps(sorted(records.keys())).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "dns_records", name)

        if old_hash and records_hash != old_hash:
            old_records = set(json.loads(old_content)) if old_content else set()
            new_records = set(records.keys()) - old_records
            removed_records = old_records - set(records.keys())

            if new_records:
                rec_list = "\n".join(f"* `{r[:120]}`" for r in sorted(new_records)[:10])
                send_discord_alert(
                    f"DNS Record Change: {name} ({ticker})",
                    f"**{len(new_records)} new DNS record(s)**\n\n{rec_list}",
                    color=0x795548,
                    url=f"https://dns.google/query?name={domain}",
                )
                log_detection(conn, "dns_records", name, "new_record", f"{len(new_records)} records", rec_list[:1000])
                logger.info(f"  -> {len(new_records)} new DNS records: {name}")

        store_hash(conn, "dns_records", name, records_hash, json.dumps(list(records.keys())))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 19: arXiv Paper Monitor
# Company researchers publish papers on arXiv weeks/months before the
# corresponding product launches. A paper from Google on "efficient
# attention" often means a new Gemini model is coming.
# ═══════════════════════════════════════════════════════════════════════════

def monitor_arxiv(conn, targets):
    """Monitor arXiv for new papers from specific companies/authors."""
    logger.info("=== arXiv Paper Monitor ===")

    for target in targets:
        name = target["name"]
        ticker = target.get("ticker", "")
        query = target["query"]  # arXiv search query

        # arXiv API
        url = f"http://export.arxiv.org/api/query?search_query={query}&start=0&max_results=10&sortBy=submittedDate&sortOrder=descending"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                continue
        except Exception:
            continue

        soup = BeautifulSoup(resp.text, "xml")
        entries = soup.find_all("entry")

        papers = []
        for entry in entries:
            title = entry.find("title")
            summary = entry.find("summary")
            authors = entry.find_all("author")
            link = entry.find("id")
            published = entry.find("published")

            if title:
                author_names = ", ".join(a.find("name").get_text(strip=True) for a in authors[:5] if a.find("name"))
                papers.append({
                    "title": title.get_text(strip=True)[:200],
                    "authors": author_names[:200],
                    "link": link.get_text(strip=True) if link else "",
                    "date": published.get_text(strip=True)[:10] if published else "",
                    "summary": summary.get_text(strip=True)[:300] if summary else "",
                })

        if not papers:
            continue

        papers_hash = hashlib.sha256(json.dumps([p["title"] for p in papers]).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "arxiv", name)

        if old_hash and papers_hash != old_hash:
            old_titles = set(json.loads(old_content)) if old_content else set()
            new_papers = [p for p in papers if p["title"] not in old_titles]

            if new_papers:
                paper_list = "\n".join(
                    f"* **{p['title'][:100]}**\n  {p['authors'][:80]} | {p['date']}"
                    for p in new_papers[:8]
                )
                send_discord_alert(
                    f"New Papers: {name} ({ticker})",
                    f"**{len(new_papers)} new paper(s)** on arXiv\n\n{paper_list}",
                    color=0xB71C1C,
                    url=new_papers[0]["link"] if new_papers else "",
                )
                log_detection(conn, "arxiv", name, "new_paper", f"{len(new_papers)} papers", paper_list[:1000])
                logger.info(f"  -> {len(new_papers)} new arXiv papers: {name}")

        store_hash(conn, "arxiv", name, papers_hash, json.dumps([p["title"] for p in papers]))


# arXiv search queries by company (affiliations in paper metadata)
ARXIV_TARGETS = [
    {"name": "Google/DeepMind", "ticker": "GOOGL", "query": "all:google+AND+all:language+model+OR+all:deepmind"},
    {"name": "Meta FAIR", "ticker": "META", "query": "all:meta+AND+all:fair+AND+all:language+model"},
    {"name": "OpenAI", "ticker": "", "query": "all:openai+AND+all:language+model+OR+all:reasoning"},
    {"name": "Anthropic", "ticker": "", "query": "all:anthropic+AND+all:language+model+OR+all:safety"},
    {"name": "Microsoft Research", "ticker": "MSFT", "query": "all:microsoft+research+AND+all:language+model"},
    {"name": "Apple ML", "ticker": "AAPL", "query": "all:apple+AND+all:machine+learning+AND+all:on-device"},
    {"name": "NVIDIA Research", "ticker": "NVDA", "query": "all:nvidia+AND+all:inference+OR+all:training+efficiency"},
    {"name": "Tesla AI", "ticker": "TSLA", "query": "all:tesla+AND+all:autonomous+OR+all:robot+OR+all:self-driving"},
    {"name": "AMD Research", "ticker": "AMD", "query": "all:amd+AND+all:gpu+AND+all:machine+learning"},
    {"name": "Salesforce Research", "ticker": "CRM", "query": "all:salesforce+AND+all:language+model+OR+all:agent"},
]


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 20: GraphQL Schema Introspection
# Many companies expose GraphQL endpoints. Introspection reveals new
# types, fields, and mutations before they're documented or UI-visible.
# ═══════════════════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
      }
    }
    mutationType {
      fields {
        name
      }
    }
  }
}
"""

def monitor_graphql(conn, targets):
    """Monitor GraphQL endpoints for schema changes revealing new features."""
    logger.info("=== GraphQL Schema Monitor ===")

    for target in targets:
        name = target["name"]
        url = target["url"]
        ticker = target.get("ticker", "")

        try:
            resp = requests.post(
                url,
                json={"query": INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
                timeout=15,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception:
            continue

        # Extract type and field names
        schema_items = set()
        types = data.get("data", {}).get("__schema", {}).get("types", [])
        for t in types:
            type_name = t.get("name", "")
            if type_name.startswith("__"):  # skip introspection types
                continue
            schema_items.add(f"type:{type_name}")
            for field in (t.get("fields") or []):
                schema_items.add(f"field:{type_name}.{field['name']}")

        mutations = data.get("data", {}).get("__schema", {}).get("mutationType", {})
        if mutations:
            for field in (mutations.get("fields") or []):
                schema_items.add(f"mutation:{field['name']}")

        if not schema_items:
            continue

        schema_hash = hashlib.sha256(json.dumps(sorted(schema_items)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "graphql", name)

        if old_hash and schema_hash != old_hash:
            old_items = set(json.loads(old_content)) if old_content else set()
            new_items = schema_items - old_items

            if new_items:
                new_types = [i.split(":", 1)[1] for i in new_items if i.startswith("type:")]
                new_fields = [i.split(":", 1)[1] for i in new_items if i.startswith("field:")]
                new_mutations = [i.split(":", 1)[1] for i in new_items if i.startswith("mutation:")]

                details_parts = []
                if new_types:
                    details_parts.append(f"**New Types:** {', '.join(sorted(new_types)[:10])}")
                if new_mutations:
                    details_parts.append(f"**New Mutations:** {', '.join(sorted(new_mutations)[:10])}")
                if new_fields:
                    details_parts.append(f"**New Fields:** {', '.join(sorted(new_fields)[:15])}")

                details = "\n".join(details_parts)
                send_discord_alert(
                    f"GraphQL Schema Change: {name} ({ticker})",
                    f"**{len(new_items)} new schema items**\n\n{details}",
                    color=0xE535AB,
                    url=url,
                )
                log_detection(conn, "graphql", name, "schema_change", f"{len(new_items)} items", details[:1000])
                logger.info(f"  -> {len(new_items)} new GraphQL schema items: {name}")

        store_hash(conn, "graphql", name, schema_hash, json.dumps(list(schema_items)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 21: CDN Asset Discovery
# New images, videos, and files uploaded to company CDNs before pages
# reference them. Product images, logos for new features, etc.
# ═══════════════════════════════════════════════════════════════════════════

def monitor_cdn_assets(conn, targets):
    """Monitor known CDN/asset URLs for new files hinting at upcoming products."""
    logger.info("=== CDN Asset Monitor ===")

    for target in targets:
        name = target["name"]
        url = target["url"]  # page to scan for asset URLs
        ticker = target.get("ticker", "")
        cdn_domains = target.get("cdn_domains", [])

        resp = fetch_url(url)
        if not resp:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        assets = set()

        # Collect all image, video, script, link references
        for tag in soup.find_all(["img", "video", "source"]):
            src = tag.get("src") or tag.get("data-src") or ""
            if src:
                full_url = urljoin(url, src)
                if cdn_domains:
                    if any(cdn in full_url for cdn in cdn_domains):
                        assets.add(full_url)
                else:
                    assets.add(full_url)

        for tag in soup.find_all("link", rel=["preload", "prefetch"]):
            href = tag.get("href", "")
            if href:
                assets.add(urljoin(url, href))

        if not assets:
            continue

        # Hash just the asset paths (not query strings which may change)
        clean_assets = set()
        for a in assets:
            parsed = urlparse(a)
            clean_assets.add(f"{parsed.netloc}{parsed.path}")

        assets_hash = hashlib.sha256(json.dumps(sorted(clean_assets)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "cdn_assets", name)

        if old_hash and assets_hash != old_hash:
            old_assets = set(json.loads(old_content)) if old_content else set()
            new_assets = clean_assets - old_assets

            if new_assets and len(new_assets) < 50:  # filter noise from full redesigns
                # Filter out noise: hash-based URLs, tracking pixels, etc.
                interesting = []
                for a in new_assets:
                    path = a.split("/", 1)[-1] if "/" in a else a

                    # Skip content-addressed / hash URLs (googleusercontent, etc.)
                    # Match long random strings anywhere in path
                    if re.search(r"[A-Za-z0-9_-]{40,}", path):
                        continue

                    # Skip paths that are mostly a single hash segment
                    segments = [s for s in path.split("/") if s]
                    if segments and re.match(r"^[A-Za-z0-9_-]{20,}$", segments[-1]):
                        continue

                    # Skip common assets with hash filenames
                    if re.search(r"/[a-f0-9]{8,}\.(png|jpg|jpeg|gif|webp|svg|woff|woff2|ttf|css|js)$", path, re.I):
                        continue

                    # Skip tracking pixels and analytics (but not product names like "pixel-10")
                    if any(x in a for x in ["/pixel/", "/pixel?", "beacon", "analytics",
                                             "gtag", "/collect", "tracker", "1x1", "spacer"]):
                        continue

                    # Skip data URIs and inline
                    if "data:" in a or "blob:" in a:
                        continue

                    interesting.append(a)

                if interesting:
                    asset_list = "\n".join(f"* `{a[:120]}`" for a in sorted(interesting)[:12])
                    send_discord_alert(
                        f"New CDN Assets: {name} ({ticker})",
                        f"**{len(interesting)} new assets** detected\n\n{asset_list}",
                        color=0x009688,
                        url=url,
                    )
                    log_detection(conn, "cdn_assets", name, "new_assets", f"{len(interesting)} assets", asset_list[:1000])
                    logger.info(f"  -> {len(interesting)} new CDN assets: {name}")

        store_hash(conn, "cdn_assets", name, assets_hash, json.dumps(list(clean_assets)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 22: GitHub Organization Repo Watcher
# Watches for NEW public repos being created under target orgs.
# Companies push repos before announcing products (e.g. anthropics/claude-code).
# ═══════════════════════════════════════════════════════════════════════════

GITHUB_ORGS = [
    # AI / LLM
    {"name": "Anthropic", "org": "anthropics"},
    {"name": "Anthropic MCP", "org": "modelcontextprotocol"},
    {"name": "OpenAI", "org": "openai"},
    {"name": "Google DeepMind", "org": "google-deepmind"},
    {"name": "Google Research", "org": "google-research"},
    {"name": "Google", "org": "google"},
    {"name": "Meta FAIR", "org": "facebookresearch"},
    {"name": "Meta", "org": "facebook"},
    {"name": "Microsoft", "org": "microsoft"},
    {"name": "xAI", "org": "xai-org"},
    {"name": "Mistral", "org": "mistralai"},
    {"name": "Stability AI", "org": "Stability-AI"},
    {"name": "Hugging Face", "org": "huggingface"},
    {"name": "DeepSeek", "org": "deepseek-ai"},
    {"name": "Cohere", "org": "cohere-ai"},
    {"name": "Runway", "org": "runwayml"},
    {"name": "ElevenLabs", "org": "elevenlabs"},
    {"name": "Cognition (Devin)", "org": "cognition-labs"},
    {"name": "Character.ai", "org": "character-ai"},
    # Dev tools
    {"name": "Cursor", "org": "getcursor"},
    {"name": "Vercel", "org": "vercel"},
    {"name": "Supabase", "org": "supabase"},
    {"name": "Stripe", "org": "stripe"},
    {"name": "Linear", "org": "linearapp"},
    {"name": "Railway", "org": "railwayapp"},
    {"name": "Cloudflare", "org": "cloudflare"},
    {"name": "Docker", "org": "docker"},
    {"name": "Sourcegraph", "org": "sourcegraph"},
    {"name": "Replit", "org": "replit"},
    # Consumer tech
    {"name": "Roblox", "org": "Roblox"},
    {"name": "Discord", "org": "discord"},
    {"name": "Bluesky", "org": "bluesky-social"},
    {"name": "Signal", "org": "signalapp"},
    {"name": "Telegram", "org": "nicegram"},
    # Enterprise
    {"name": "Databricks", "org": "databricks"},
    {"name": "Snowflake", "org": "snowflakedb"},
    {"name": "Elastic", "org": "elastic"},
    {"name": "CrowdStrike", "org": "CrowdStrike"},
    {"name": "HashiCorp", "org": "hashicorp"},
    # Hardware
    {"name": "Apple", "org": "apple"},
    {"name": "Tesla", "org": "teslamotors"},
]


def monitor_github_orgs(conn):
    """Watch GitHub organizations for new public repositories."""
    logger.info(f"=== GitHub Org Watcher ({len(GITHUB_ORGS)} orgs) ===")

    github_token = os.getenv("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    for target in GITHUB_ORGS:
        name = target["name"]
        org = target["org"]

        try:
            resp = session.get(
                f"https://api.github.com/orgs/{org}/repos",
                params={"sort": "created", "direction": "desc", "per_page": 30, "type": "public"},
                headers=headers,
                timeout=15,
            )
            if resp.status_code != 200:
                continue
            repos = resp.json()
        except Exception:
            continue

        if not repos or not isinstance(repos, list):
            continue

        repo_names = set()
        repo_details = {}
        for r in repos:
            rname = r.get("full_name", "")
            if rname:
                repo_names.add(rname)
                repo_details[rname] = {
                    "desc": (r.get("description") or "")[:150],
                    "url": r.get("html_url", ""),
                    "stars": r.get("stargazers_count", 0),
                    "created": (r.get("created_at") or "")[:10],
                }

        repos_hash = hashlib.sha256(json.dumps(sorted(repo_names)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "github_org", name)

        if old_hash and repos_hash != old_hash:
            old_repos = set(json.loads(old_content)) if old_content else set()
            new_repos = repo_names - old_repos

            if new_repos:
                lines = []
                for rname in sorted(new_repos)[:10]:
                    info = repo_details.get(rname, {})
                    desc = f" — {info['desc']}" if info.get("desc") else ""
                    lines.append(f"* **[{rname}]({info.get('url', '')})**{desc}")

                repo_list = "\n".join(lines)
                send_discord_alert(
                    f"New GitHub Repos: {name}",
                    f"**{len(new_repos)} new public repo(s)** created\n\n{repo_list}",
                    color=0x6E5494,
                    url=f"https://github.com/{org}?tab=repositories&sort=created",
                )
                log_detection(conn, "github_org", name, "new_repo", f"{len(new_repos)} repos", repo_list[:1000])
                logger.info(f"  -> {len(new_repos)} new repos for {name}")

        store_hash(conn, "github_org", name, repos_hash, json.dumps(list(repo_names)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 23: Hugging Face Model Watcher
# Companies publish models on HuggingFace before announcing them.
# Catches new model uploads from specific organizations.
# ═══════════════════════════════════════════════════════════════════════════

HF_ORGS = [
    {"name": "Anthropic (HF)", "org": "Anthropic"},
    {"name": "OpenAI (HF)", "org": "openai"},
    {"name": "Google (HF)", "org": "google"},
    {"name": "Meta (HF)", "org": "meta-llama"},
    {"name": "Meta FAIR (HF)", "org": "facebook"},
    {"name": "Microsoft (HF)", "org": "microsoft"},
    {"name": "Mistral (HF)", "org": "mistralai"},
    {"name": "xAI (HF)", "org": "xai-org"},
    {"name": "Stability AI (HF)", "org": "stabilityai"},
    {"name": "NVIDIA (HF)", "org": "nvidia"},
    {"name": "Apple (HF)", "org": "apple"},
    {"name": "Salesforce (HF)", "org": "Salesforce"},
    {"name": "Databricks (HF)", "org": "databricks"},
    {"name": "Cohere (HF)", "org": "CohereForAI"},
    {"name": "DeepSeek (HF)", "org": "deepseek-ai"},
    {"name": "Qwen (HF)", "org": "Qwen"},
    {"name": "ElevenLabs (HF)", "org": "elevenlabs"},
    {"name": "Runway (HF)", "org": "runwayml"},
    {"name": "Adobe (HF)", "org": "Adobe"},
    {"name": "Samsung (HF)", "org": "Samsung"},
    {"name": "Intel (HF)", "org": "Intel"},
    {"name": "AMD (HF)", "org": "amd"},
    {"name": "Snowflake (HF)", "org": "Snowflake"},
    {"name": "Reka (HF)", "org": "RekaAI"},
    {"name": "AI21 (HF)", "org": "AI21Labs"},
    {"name": "Together (HF)", "org": "togethercomputer"},
    {"name": "Nous Research (HF)", "org": "NousResearch"},
    {"name": "01.AI (HF)", "org": "01-ai"},
    {"name": "Black Forest Labs (HF)", "org": "black-forest-labs"},
]


def monitor_huggingface(conn):
    """Watch HuggingFace organizations for new model uploads."""
    logger.info(f"=== HuggingFace Model Watcher ({len(HF_ORGS)} orgs) ===")

    for target in HF_ORGS:
        name = target["name"]
        org = target["org"]

        try:
            resp = session.get(
                f"https://huggingface.co/api/models",
                params={"author": org, "sort": "lastModified", "direction": -1, "limit": 20},
                timeout=15,
            )
            if resp.status_code != 200:
                continue
            models = resp.json()
        except Exception:
            continue

        if not models or not isinstance(models, list):
            continue

        model_ids = set()
        model_details = {}
        for m in models:
            mid = m.get("modelId", "")
            if mid:
                model_ids.add(mid)
                model_details[mid] = {
                    "downloads": m.get("downloads", 0),
                    "likes": m.get("likes", 0),
                    "pipeline": m.get("pipeline_tag", ""),
                    "created": (m.get("createdAt") or "")[:10],
                }

        models_hash = hashlib.sha256(json.dumps(sorted(model_ids)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "huggingface", name)

        if old_hash and models_hash != old_hash:
            old_models = set(json.loads(old_content)) if old_content else set()
            new_models = model_ids - old_models

            if new_models:
                lines = []
                for mid in sorted(new_models)[:10]:
                    info = model_details.get(mid, {})
                    pipeline = f" ({info['pipeline']})" if info.get("pipeline") else ""
                    lines.append(f"* **[{mid}](https://huggingface.co/{mid})**{pipeline}")

                model_list = "\n".join(lines)
                send_discord_alert(
                    f"New HF Models: {name}",
                    f"**{len(new_models)} new model(s)** published\n\n{model_list}",
                    color=0xFFD21E,
                    url=f"https://huggingface.co/{org}",
                )
                log_detection(conn, "huggingface", name, "new_model", f"{len(new_models)} models", model_list[:1000])
                logger.info(f"  -> {len(new_models)} new HF models for {name}")

        store_hash(conn, "huggingface", name, models_hash, json.dumps(list(model_ids)))


# ═══════════════════════════════════════════════════════════════════════════
# MONITOR 24: AI Model Registry Monitor
# Checks cloud AI provider APIs for newly listed models.
# New models appear in registries hours/days before official announcements.
# (How TestingCatalog found Gemini 3.1 Flash Lite Preview on Vertex AI)
# ═══════════════════════════════════════════════════════════════════════════

def monitor_model_registries(conn):
    """
    Poll AI provider model APIs for new model IDs.
    Uses API keys from environment variables when available.
    """
    logger.info("=== AI Model Registry Monitor ===")

    registries = []

    # ── OpenAI ──
    openai_key = os.getenv("OPENAI_API_KEY", "")
    if openai_key:
        registries.append({
            "name": "OpenAI",
            "ticker": "OpenAI",
            "url": "https://api.openai.com/v1/models",
            "headers": {"Authorization": f"Bearer {openai_key}"},
            "parse": lambda data: {m["id"] for m in data.get("data", [])},
        })

    # ── Anthropic ──
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        registries.append({
            "name": "Anthropic",
            "ticker": "Anthropic",
            "url": "https://api.anthropic.com/v1/models",
            "headers": {
                "x-api-key": anthropic_key,
                "anthropic-version": "2023-06-01",
            },
            "parse": lambda data: {m["id"] for m in data.get("data", [])},
        })

    # ── Google AI (Gemini) ──
    google_key = os.getenv("GOOGLE_AI_API_KEY", "")
    if google_key:
        registries.append({
            "name": "Google AI (Gemini)",
            "ticker": "GOOGL",
            "url": f"https://generativelanguage.googleapis.com/v1beta/models?key={google_key}",
            "headers": {},
            "parse": lambda data: {m["name"] for m in data.get("models", [])},
        })

    # ── Groq ──
    groq_key = os.getenv("GROQ_API_KEY", "")
    if groq_key:
        registries.append({
            "name": "Groq",
            "ticker": "Groq",
            "url": "https://api.groq.com/openai/v1/models",
            "headers": {"Authorization": f"Bearer {groq_key}"},
            "parse": lambda data: {m["id"] for m in data.get("data", [])},
        })

    # ── Together AI ──
    together_key = os.getenv("TOGETHER_API_KEY", "")
    if together_key:
        registries.append({
            "name": "Together AI",
            "ticker": "Together",
            "url": "https://api.together.xyz/v1/models",
            "headers": {"Authorization": f"Bearer {together_key}"},
            "parse": lambda data: {m["id"] for m in data.get("data", []) if isinstance(m, dict)},
        })

    if not registries:
        logger.info("  No API keys configured - set OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_AI_API_KEY")
        return

    for reg in registries:
        name = reg["name"]

        try:
            resp = session.get(reg["url"], headers=reg.get("headers", {}), timeout=15)
            if resp.status_code != 200:
                logger.debug(f"  {name}: HTTP {resp.status_code}")
                continue
            data = resp.json()
            model_ids = reg["parse"](data)
        except Exception as e:
            logger.debug(f"  {name} error: {e}")
            continue

        if not model_ids:
            continue

        models_hash = hashlib.sha256(json.dumps(sorted(model_ids)).encode()).hexdigest()
        old_hash, old_content = get_stored_hash(conn, "model_registry", name)

        if old_hash and models_hash != old_hash:
            old_models = set(json.loads(old_content)) if old_content else set()
            new_models = model_ids - old_models
            removed_models = old_models - model_ids

            if new_models:
                model_list = "\n".join(f"* `{m}`" for m in sorted(new_models)[:20])
                send_discord_alert(
                    f"🆕 New Models: {name} ({reg.get('ticker', '')})",
                    f"**{len(new_models)} new model(s)** appeared in API\n\n{model_list}",
                    color=0x9C27B0,
                    url=reg["url"].split("?")[0],
                )
                log_detection(conn, "model_registry", name, "new_model",
                              f"{len(new_models)} models", model_list[:1000])
                logger.info(f"  -> {len(new_models)} new models on {name}!")

            if removed_models:
                removed_list = "\n".join(f"* ~~`{m}`~~" for m in sorted(removed_models)[:10])
                send_discord_alert(
                    f"❌ Models Removed: {name} ({reg.get('ticker', '')})",
                    f"**{len(removed_models)} model(s) delisted**\n\n{removed_list}",
                    color=0xFF5722,
                    url=reg["url"].split("?")[0],
                )

        elif not old_hash:
            logger.info(f"  Baseline: {len(model_ids)} models for {name}")

        store_hash(conn, "model_registry", name, models_hash, json.dumps(list(model_ids)))


DEFAULT_CONFIG = {
    "js_bundles": [
        {
            "name": "ChatGPT",
            "url": "https://chatgpt.com",
            "keywords": ["gpt-5", "o3", "reasoning", "agent", "canvas", "operator", "codex"]
        },
        {
            "name": "Claude",
            "url": "https://claude.ai",
            "keywords": ["opus", "haiku", "sonnet", "artifact", "project", "memory", "computer_use"]
        },
        {
            "name": "Gemini",
            "url": "https://gemini.google.com",
            "keywords": ["ultra", "flash", "nano", "gems", "deep-research"]
        },
        {
            "name": "Perplexity",
            "url": "https://www.perplexity.ai",
            "keywords": ["sonar", "pro", "enterprise", "finance", "agent"]
        },
        {
            "name": "Grok",
            "url": "https://grok.com",
            "keywords": ["grok-3", "colossus", "aurora", "build"]
        },
    ],

    "docs": [
        {
            "name": "OpenAI API Docs",
            "urls": [
                "https://platform.openai.com/docs/models",
                "https://platform.openai.com/docs/changelog",
            ],
            "keywords": ["gpt", "model", "new", "beta", "deprecated", "preview"]
        },
        {
            "name": "Anthropic API Docs",
            "urls": [
                "https://docs.anthropic.com/en/docs/about-claude/models",
            ],
            "keywords": ["claude", "model", "new", "opus", "sonnet", "haiku"]
        },
        {
            "name": "Google AI Docs",
            "urls": [
                "https://ai.google.dev/gemini-api/docs/models",
            ],
            "keywords": ["gemini", "model", "new", "flash", "pro", "ultra"]
        },
    ],

    "sitemaps": [
        {
            "name": "OpenAI",
            "sitemap_url": "https://openai.com/sitemap.xml",
            "interesting_patterns": [r"/blog/", r"/product/", r"/research/", r"/index/"]
        },
        {
            "name": "Anthropic",
            "sitemap_url": "https://www.anthropic.com/sitemap.xml",
            "interesting_patterns": [r"/news/", r"/research/", r"/claude"]
        },
        {
            "name": "Google DeepMind",
            "sitemap_url": "https://deepmind.google/sitemap.xml",
            "interesting_patterns": [r"/discover/", r"/research/", r"/technologies/"]
        },
    ],

    "github": [
        {
            "name": "LLaMA (Meta)",
            "repo": "meta-llama/llama",
            "watch": ["releases"],
            "keywords": ["llama"]
        },
        {
            "name": "Ollama",
            "repo": "ollama/ollama",
            "watch": ["releases"],
            "keywords": []
        },
        {
            "name": "LangChain",
            "repo": "langchain-ai/langchain",
            "watch": ["releases"],
            "keywords": ["agent", "tool"]
        },
    ],

    "app_store": [
        {"name": "ChatGPT iOS", "app_id": "6448311069"},
        {"name": "Claude iOS", "app_id": "6473753684"},
        {"name": "Gemini iOS", "app_id": "6477489129"},
        {"name": "Perplexity iOS", "app_id": "1668000334"},
        {"name": "Grok iOS", "app_id": "6670324846"},
        {"name": "Copilot iOS", "app_id": "6738605245"},
    ],

    "play_store": [
        {"name": "ChatGPT Android", "package": "com.openai.chatgpt"},
        {"name": "Claude Android", "package": "com.anthropic.claude"},
        {"name": "Gemini Android", "package": "com.google.android.apps.bard"},
        {"name": "Perplexity Android", "package": "ai.perplexity.app.android"},
    ],

    "subdomains": [
        {
            "name": "OpenAI",
            "domain": "openai.com",
            "extra_subdomains": ["codex", "sora", "operator", "agent", "swarm", "o3"]
        },
        {
            "name": "Anthropic",
            "domain": "anthropic.com",
            "extra_subdomains": ["claude", "opus", "workbench", "tools"]
        },
        {
            "name": "Google AI",
            "domain": "google.com",
            "extra_subdomains": ["gemini", "notebooklm", "aistudio", "stitch"]
        },
    ],

    "pages": [
        {
            "name": "OpenAI Changelog",
            "url": "https://help.openai.com/en/articles/6825453-chatgpt-release-notes",
            "selector": None
        },
        {
            "name": "Anthropic News",
            "url": "https://www.anthropic.com/news",
            "selector": None
        },
        {
            "name": "Google AI Blog",
            "url": "https://blog.google/technology/ai/",
            "selector": None
        },
        {
            "name": "Chrome Status Features",
            "url": "https://chromestatus.com/features",
            "selector": None
        },
    ],
}


def load_config(config_path="config.json"):
    """Load or create configuration file."""
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return json.load(f)

    # Save default config
    with open(config_path, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    logger.info(f"Created default config at {config_path}")
    return DEFAULT_CONFIG


# ═══════════════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_all_monitors(config, conn):
    """Run all configured monitors."""
    start = time.time()
    logger.info("=" * 60)
    logger.info(f"Feature Intel scan started at {datetime.now(timezone.utc).isoformat()}")
    logger.info("=" * 60)

    try:
        if config.get("js_bundles"):
            monitor_js_bundles(conn, config["js_bundles"])
    except Exception as e:
        logger.error(f"JS Bundle monitor error: {e}")

    try:
        if config.get("docs"):
            monitor_docs(conn, config["docs"])
    except Exception as e:
        logger.error(f"Docs monitor error: {e}")

    try:
        if config.get("sitemaps"):
            monitor_sitemaps(conn, config["sitemaps"])
    except Exception as e:
        logger.error(f"Sitemap monitor error: {e}")

    try:
        if config.get("github"):
            monitor_github(conn, config["github"])
    except Exception as e:
        logger.error(f"GitHub monitor error: {e}")


    try:
        if config.get("play_store"):
            monitor_play_store(conn, config["play_store"])
    except Exception as e:
        logger.error(f"Play Store monitor error: {e}")

    try:
        monitor_chrome_flags(conn)
    except Exception as e:
        logger.error(f"Chrome flags monitor error: {e}")

    try:
        if config.get("subdomains"):
            monitor_subdomains(conn, config["subdomains"])
    except Exception as e:
        logger.error(f"Subdomain monitor error: {e}")

    try:
        if config.get("pages"):
            monitor_pages(conn, config["pages"])
    except Exception as e:
        logger.error(f"Page change monitor error: {e}")

    try:
        monitor_fcc(conn, config.get("fcc_grantees", None))
    except Exception as e:
        logger.error(f"FCC monitor error: {e}")

    try:
        monitor_trademarks(conn, config.get("trademark_owners", None))
    except Exception as e:
        logger.error(f"Trademark monitor error: {e}")

    try:
        if config.get("ct_logs"):
            monitor_ct_logs(conn, config["ct_logs"])
    except Exception as e:
        logger.error(f"CT logs monitor error: {e}")

    try:
        if config.get("robots_txt"):
            monitor_robots_txt(conn, config["robots_txt"])
    except Exception as e:
        logger.error(f"robots.txt monitor error: {e}")

    try:
        monitor_sec_filings(conn, config.get("sec_ciks", None))
    except Exception as e:
        logger.error(f"SEC EDGAR monitor error: {e}")

    try:
        monitor_npm_packages(conn, config.get("npm_packages", None))
    except Exception as e:
        logger.error(f"npm monitor error: {e}")

    try:
        monitor_pypi_packages(conn, config.get("pypi_packages", None))
    except Exception as e:
        logger.error(f"PyPI monitor error: {e}")

    try:
        targets = config.get("job_postings", JOB_TARGETS)
        if targets:
            monitor_job_postings(conn, targets)
    except Exception as e:
        logger.error(f"Job posting monitor error: {e}")


    try:
        targets = config.get("arxiv", ARXIV_TARGETS)
        if targets:
            monitor_arxiv(conn, targets)
    except Exception as e:
        logger.error(f"arXiv monitor error: {e}")

    try:
        if config.get("graphql"):
            monitor_graphql(conn, config["graphql"])
    except Exception as e:
        logger.error(f"GraphQL monitor error: {e}")

    try:
        if config.get("cdn_assets"):
            monitor_cdn_assets(conn, config["cdn_assets"])
    except Exception as e:
        logger.error(f"CDN asset monitor error: {e}")

    elapsed = time.time() - start
    logger.info(f"Scan complete in {elapsed:.1f}s")


def run_monitor_timed(name, fn):
    """Run a monitor with timing, error isolation, and memory cleanup."""
    """Run a single monitor with timing and error handling."""
    t0 = time.time()
    try:
        fn()
        elapsed = time.time() - t0
        logger.info(f"  [{name}] done in {elapsed:.1f}s")
    except Exception as e:
        elapsed = time.time() - t0
        logger.error(f"  [{name}] FAILED after {elapsed:.1f}s: {e}")
    gc.collect()  # Free memory between monitors


def run_all_monitors(config, conn):
    """Run all configured monitors with timing and progress."""
    start = time.time()
    logger.info("=" * 60)
    logger.info(f"Feature Intel scan started at {datetime.now(timezone.utc).isoformat()}")
    logger.info("=" * 60)

    # Build list of (name, callable) for all monitors
    monitors = []

    if config.get("js_bundles"):
        monitors.append(("JS Bundles", lambda: monitor_js_bundles(conn, config["js_bundles"])))
    if config.get("docs"):
        monitors.append(("Docs", lambda: monitor_docs(conn, config["docs"])))
    if config.get("sitemaps"):
        monitors.append(("Sitemaps", lambda: monitor_sitemaps(conn, config["sitemaps"])))
    if config.get("github"):
        monitors.append(("GitHub", lambda: monitor_github(conn, config["github"])))
    if config.get("play_store"):
        monitors.append(("Play Store", lambda: monitor_play_store(conn, config["play_store"])))
    monitors.append(("Chrome Flags", lambda: monitor_chrome_flags(conn)))
    if config.get("subdomains"):
        monitors.append(("Subdomains", lambda: monitor_subdomains(conn, config["subdomains"])))
    if config.get("pages"):
        monitors.append(("Pages", lambda: monitor_pages(conn, config["pages"])))
    monitors.append(("FCC", lambda: monitor_fcc(conn, config.get("fcc_grantees", None))))
    monitors.append(("Trademarks", lambda: monitor_trademarks(conn, config.get("trademark_owners", None))))
    if config.get("ct_logs"):
        monitors.append(("CT Logs", lambda: monitor_ct_logs(conn, config["ct_logs"])))
    if config.get("robots_txt"):
        monitors.append(("robots.txt", lambda: monitor_robots_txt(conn, config["robots_txt"])))
    monitors.append(("PyPI", lambda: monitor_pypi_packages(conn, config.get("pypi_packages", None))))
    monitors.append(("Jobs", lambda: monitor_job_postings(conn, config.get("job_postings", JOB_TARGETS))))
    monitors.append(("arXiv", lambda: monitor_arxiv(conn, config.get("arxiv", ARXIV_TARGETS))))
    if config.get("graphql"):
        monitors.append(("GraphQL", lambda: monitor_graphql(conn, config["graphql"])))
    if config.get("cdn_assets"):
        monitors.append(("CDN Assets", lambda: monitor_cdn_assets(conn, config["cdn_assets"])))
    monitors.append(("GitHub Orgs", lambda: monitor_github_orgs(conn)))
    monitors.append(("HuggingFace", lambda: monitor_huggingface(conn)))
    monitors.append(("Model Registries", lambda: monitor_model_registries(conn)))

    logger.info(f"Running {len(monitors)} monitors...")

    for i, (name, fn) in enumerate(monitors, 1):
        logger.info(f"[{i}/{len(monitors)}] Running: {name}")
        run_monitor_timed(name, fn)

    elapsed = time.time() - start
    logger.info(f"Full scan complete in {elapsed:.1f}s ({len(monitors)} monitors)")


def get_sleep_seconds():
    """
    Smart scheduling (Eastern Time):
    - Weekdays 9:30 AM - 4 PM ET (market hours): every 15 min
    - Weekdays 6 AM - 9:30 AM / 4 PM - 8 PM ET: every 60 min
    - Weekends (Sat-Sun): once per day at 6 AM ET
    - 8 PM - 6 AM every day: sleep until 6 AM ET next morning
    
    Returns (seconds_to_sleep, reason_string)
    """
    try:
        from zoneinfo import ZoneInfo
        et_now = datetime.now(ZoneInfo("America/New_York"))
    except ImportError:
        et_now = datetime.now(timezone(timedelta(hours=-5)))

    hour = et_now.hour
    minute = et_now.minute
    weekday = et_now.weekday()  # 0=Mon, 6=Sun
    is_weekend = weekday >= 5

    # Outside active hours (8 PM - 6 AM) → sleep until 6 AM ET
    if hour >= 20 or hour < 6:
        if hour >= 20:
            next_6am = et_now.replace(hour=6, minute=0, second=0, microsecond=0) + timedelta(days=1)
        else:
            next_6am = et_now.replace(hour=6, minute=0, second=0, microsecond=0)
        sleep_secs = max(60, int((next_6am - et_now).total_seconds()))
        wake_str = next_6am.strftime("%a %I:%M %p ET")
        return sleep_secs, f"overnight - next scan at {wake_str}"

    # Weekend active hours → sleep until 6 AM tomorrow (one scan per day)
    if is_weekend:
        tomorrow_6am = et_now.replace(hour=6, minute=0, second=0, microsecond=0) + timedelta(days=1)
        sleep_secs = max(60, int((tomorrow_6am - et_now).total_seconds()))
        wake_str = tomorrow_6am.strftime("%a %I:%M %p ET")
        return sleep_secs, f"weekend - next scan at {wake_str}"

    # Weekday trading hours (9:30 AM - 4:00 PM ET) → every 15 min
    time_decimal = hour + minute / 60.0
    if 9.5 <= time_decimal < 16.0:
        return 900, "market hours - next scan in 15 min"

    # Weekday pre-market / after-hours (6 AM - 9:30 AM, 4 PM - 8 PM) → every 60 min
    return 3600, "weekday off-hours - next scan in 60 min"


def main():
    parser = argparse.ArgumentParser(description="Feature Intel - Competitive Intelligence Monitor")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--interval", type=int, default=None, help="Override interval in minutes (ignores smart schedule)")
    parser.add_argument("--monitor", type=str, help="Run specific monitor only")
    args = parser.parse_args()

    config = load_config(args.config)
    conn = init_db()

    if args.once:
        run_all_monitors(config, conn)
    else:
        logger.info("Starting Feature Intel (market hours every 15min | weekdays hourly 6AM-8PM ET | weekends once daily | off overnight)")
        while True:
            # Check if we're in active hours before running
            try:
                from zoneinfo import ZoneInfo
                et_now = datetime.now(ZoneInfo("America/New_York"))
            except ImportError:
                et_now = datetime.now(timezone(timedelta(hours=-5)))

            hour = et_now.hour
            if hour >= 6 and hour < 20:
                try:
                    run_all_monitors(config, conn)
                except Exception as e:
                    logger.error(f"Monitor cycle error: {e}")
                finally:
                    gc.collect()  # Free memory after each scan cycle
            else:
                logger.info(f"Outside active hours ({et_now.strftime('%I:%M %p ET')}) - skipping scan")

            if args.interval:
                sleep_secs = args.interval * 60
                logger.info(f"Sleeping {args.interval} min (manual override)...")
            else:
                sleep_secs, reason = get_sleep_seconds()
                hours = sleep_secs / 3600
                if hours >= 1:
                    logger.info(f"Sleeping {hours:.1f}h ({reason})")
                else:
                    logger.info(f"Sleeping {sleep_secs // 60}m ({reason})")

            time.sleep(sleep_secs)


if __name__ == "__main__":
    main()