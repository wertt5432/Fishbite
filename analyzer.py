# analyzer.py
# Checks messages and links for common scam tricks

import re
from urllib.parse import urlparse

# Real websites and phone numbers for companies scammers like to copy
BRANDS = {
    "usps": {"domain": "usps.com", "category": "Delivery", "phone": "1-800-275-8777"},
    "ups": {"domain": "ups.com", "category": "Delivery", "phone": "1-800-742-5877"},
    "fedex": {"domain": "fedex.com", "category": "Delivery", "phone": "1-800-463-3339"},
    "irs": {"domain": "irs.gov", "category": "Government", "phone": "1-800-829-1040"},
    "fbi": {"domain": "fbi.gov", "category": "Government", "phone": "1-800-225-5324"},
    "social security": {"domain": "ssa.gov", "category": "Government", "phone": "1-800-772-1213"},
    "e-zpass": {"domain": "e-zpassiag.com", "category": "Toll", "phone": "1-800-333-8655"},
    "ezpass": {"domain": "e-zpassiag.com", "category": "Toll", "phone": "1-800-333-8655"},
    "paypal": {"domain": "paypal.com", "category": "Payment", "phone": "1-888-221-1161"},
    "amazon": {"domain": "amazon.com", "category": "Shopping", "phone": "1-888-280-4331"},
    "netflix": {"domain": "netflix.com", "category": "Streaming", "phone": "1-844-505-2993"},
    "apple": {"domain": "apple.com", "category": "Tech", "phone": "1-800-275-2273"},
    "geek squad": {"domain": "bestbuy.com", "category": "Tech Support", "phone": "1-800-433-5778"},
    "chase": {"domain": "chase.com", "category": "Bank", "phone": "1-800-935-9935"},
    "wells fargo": {"domain": "wellsfargo.com", "category": "Bank", "phone": "1-800-869-3557"},
    "bank of america": {"domain": "bankofamerica.com", "category": "Bank", "phone": "1-800-432-1000"},
}

URGENT_WORDS = [
    "within 24 hours", "within 12 hours", "account suspended", "account locked",
    "immediately", "urgent notice", "final warning", "unauthorized transaction",
    "unusual sign-in", "package cannot be delivered", "incomplete address",
    "redelivery fee", "unpaid toll", "overdue toll", "warrant", "arrest",
    "frozen", "suspended", "avoid late fees"
]

PAYMENT_WORDS = [
    "gift card", "gift cards", "apple gift", "steam card", "wire transfer",
    "bitcoin", "crypto", "western union", "social security number",
    "verify your pin", "one-time passcode", "verification code"
]

JOB_SCAM_WORDS = [
    "remote part-time job", "part-time remote opportunity", "part-time remote",
    "remote opportunity", "earn $500 a day", "daily salary", "base salary",
    "whatsapp to apply", "telegram to apply", "paid per task",
    "product information for merchants", "product optimization"
]

JOB_SCAM_PATTERNS = [
    r"\bearn\s+\$\d[\d,]*(?:\s*-\s*\$\d[\d,]*)?\s*(?:daily|(?:per|a)\s+(?:day|hour))\b",
    r"\bwork\s+(?:only\s+)?\d+\s*-\s*\d+\s*(?:minutes|mins|hours|hrs)\s+(?:per|a)\s+day\b",
    r"\bat\s+least\s+\d{2}\s+years\s+old\b",
    r"\b(?:please\s+)?text\s*\+?\d[\d\s().-]{7,}\s+to\s+(?:learn\s+more|apply)\b",
    r"\bon\s+behalf\s+of\s+[a-z0-9\s]{1,30}\brecruiting\b",
]

PRIZE_SCAM_WORDS = [
    "you have won", "claim your prize", "selected as a winner",
    "free iphone", "unclaimed reward", "cash prize"
]

TECH_SCAM_WORDS = [
    "auto-renewal", "charged $399", "charged $499", "virus detected",
    "call to cancel subscription"
]

GREETINGS = ["dear customer", "dear user", "dear member", "valued customer", "kindly"]

BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "ru", "cn", "icu", "vip", "click", "link", "buzz", "shop"]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy"]

LOOKALIKES = {
    "\u0430": "a (Cyrillic 'a')",
    "\u0435": "e (Cyrillic 'e')",
    "\u0456": "i (Cyrillic 'i')",
    "\u0458": "j (Cyrillic 'j')",
    "\u043e": "o (Cyrillic 'o')",
    "\u0440": "p (Cyrillic 'p')",
    "\u0441": "c (Cyrillic 'c')",
    "\u0455": "s (Cyrillic 's')",
    "\u0443": "y (Cyrillic 'y')",
    "\u0445": "x (Cyrillic 'x')",
    "\u04bb": "h (Cyrillic 'h')",
    "\u0410": "A (Cyrillic 'A')",
    "\u0412": "B (Cyrillic 'B')",
    "\u0421": "C (Cyrillic 'C')",
    "\u0415": "E (Cyrillic 'E')",
    "\u041d": "H (Cyrillic 'H')",
    "\u0406": "I (Cyrillic 'I')",
    "\u0408": "J (Cyrillic 'J')",
    "\u041a": "K (Cyrillic 'K')",
    "\u041c": "M (Cyrillic 'M')",
    "\u041e": "O (Cyrillic 'O')",
    "\u0420": "P (Cyrillic 'P')",
    "\u0405": "S (Cyrillic 'S')",
    "\u0422": "T (Cyrillic 'T')",
    "\u0423": "Y (Cyrillic 'Y')",
    "\u0425": "X (Cyrillic 'X')",
    "\u0391": "A (Greek 'Alpha')",
    "\u0392": "B (Greek 'Beta')",
    "\u0395": "E (Greek 'Epsilon')",
    "\u0396": "Z (Greek 'Zeta')",
    "\u0397": "H (Greek 'Eta')",
    "\u0399": "I (Greek 'Iota')",
    "\u039a": "K (Greek 'Kappa')",
    "\u039c": "M (Greek 'Mu')",
    "\u039d": "N (Greek 'Nu')",
    "\u039f": "O (Greek 'Omicron')",
    "\u03a1": "P (Greek 'Rho')",
    "\u03a4": "T (Greek 'Tau')",
    "\u03a5": "Y (Greek 'Upsilon')",
    "\u03a7": "X (Greek 'Chi')",
    "\u03b1": "a (Greek 'alpha')",
    "\u03b5": "e (Greek 'epsilon')",
    "\u03b9": "i (Greek 'iota')",
    "\u03ba": "k (Greek 'kappa')",
    "\u03bd": "v (Greek 'nu')",
    "\u03bf": "o (Greek 'omicron')",
    "\u03c1": "p (Greek 'rho')",
    "\u03c4": "t (Greek 'tau')",
    "\u03c5": "u (Greek 'upsilon')",
    "\u03c7": "x (Greek 'chi')",
}

HOMOGLYPH_CHAR_MAP = str.maketrans({
    **{k: v[0] for k, v in LOOKALIKES.items()},
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2212": "-",
    "\u2018": "'",
    "\u2019": "'",
})


def normalize_text(text):
    """Normalizes 1-to-1 Cyrillic/Greek homoglyphs and Unicode dashes to ASCII while preserving character indices."""
    return text.translate(HOMOGLYPH_CHAR_MAP)


def find_word_span(text, phrase):
    """Finds a phrase as a whole word (case-insensitive) and returns the match object."""
    return re.search(r"\b" + re.escape(phrase) + r"\b", text, re.IGNORECASE)


def has_word(text, phrase):
    """Checks if a word is in the text as a whole word (so 'warranty' doesn't match 'warrant')."""
    return bool(find_word_span(normalize_text(text), phrase))


def is_brand_mentioned(text, brand_name):
    """
    Checks if a brand is mentioned as an impersonated organization,
    filtering out non-impersonation contexts like requested payment methods
    ('Apple gift cards', 'Amazon gift card') or requested credentials
    ('Social Security Number').
    """
    norm = normalize_text(text)
    if brand_name == "social security":
        # Ignore when used only as a requested credential / ID number or card
        text_no_ssn = re.sub(
            r"\bsocial security\s*(?:numbers?|no\.?|#|cards?|digits?)\b",
            "",
            norm,
            flags=re.IGNORECASE,
        )
        return (
            has_word(text_no_ssn, "social security")
            or has_word(norm, "ssa")
            or has_word(norm, "social security administration")
        )

    # For commercial brands, ignore when mentioned solely as a gift card payment method
    text_no_gift = re.sub(
        r"\b" + re.escape(brand_name) + r"\s*(?:gift\s*cards?|giftcards?|gifts?|itunes\s*(?:gift\s*cards?|cards?)?)\b",
        "",
        norm,
        flags=re.IGNORECASE,
    )
    return has_word(text_no_gift, brand_name)


def check_url(url):
    reasons = []
    points = 0

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"

    # 0. Check for '@' credential spoofing in URL (e.g. https://paypal.com@evil.xyz)
    if "@" in parsed.netloc:
        points += 45
        reasons.append("Deceptive '@' symbol in link hides the real destination website (+45 pts)")

    # 1. Check if link is just an IP address (like 192.168.1.50)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        points += 45
        reasons.append("Link uses a raw IP address (" + host + ") instead of a website name (+45 pts)")
        return {
            "raw_url": url, "scheme": scheme, "subdomain": "(none)",
            "domain": host, "tld": "(IP)", "real_domain": host,
            "path": path, "points": points, "reasons": reasons
        }

    # Split the website address by dots
    parts = host.split(".")
    if len(parts) >= 2:
        tld = parts[-1].lower()
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
    else:
        tld = ""
        domain = host
        subdomain = ""

    real_domain = (domain + "." + tld).lower()

    # 2. Check for fake Cyrillic lookalike letters
    for letter in host.lower():
        if letter in LOOKALIKES:
            points += 50
            reasons.append("Domain uses a fake lookalike letter: " + LOOKALIKES[letter] + " (+50 pts)")
            break

    # 3. Check for letter swaps like 'rn' instead of 'm'
    if "rn" in domain.lower() or "paypa1" in domain.lower():
        points += 45
        reasons.append("Typosquatting: swaps letters like 'rn' for 'm' or '1' for 'l' (+45 pts)")

    # 4. Check if a company name is used in a fake subdomain or fake domain
    for name, info in BRANDS.items():
        word = name.replace(" ", "")
        if word in subdomain.lower() and real_domain != info["domain"]:
            points += 45
            reasons.append("Subdomain trap: puts " + name.upper() + " in front of " + real_domain + " (+45 pts)")
        if word in domain.lower() and real_domain != info["domain"]:
            points += 40
            reasons.append("Fake brand domain: includes " + name.upper() + ", but real site is " + info["domain"] + " (+40 pts)")

    # 5. Check for risky domain endings (.xyz, .top, etc.)
    if tld in BAD_TLDS:
        points += 30
        reasons.append("Suspicious domain ending (." + tld + ") often used by scam sites (+30 pts)")

    # 6. Check for link shorteners
    if real_domain in SHORTENERS:
        points += 25
        reasons.append("Uses a link shortener (" + real_domain + ") to hide the real website (+25 pts)")

    # 7. Check for too many hyphens in the domain (like fbi-gov-case-verify)
    if domain.count("-") >= 2:
        points += 15
        reasons.append("Domain name uses multiple hyphens (" + domain + "), common in fake sites (+15 pts)")

    # 8. Check for insecure http
    if scheme == "http":
        points += 10
        reasons.append("Uses insecure http:// instead of https:// (+10 pts)")

    return {
        "raw_url": url,
        "scheme": scheme,
        "subdomain": subdomain if subdomain else "(none)",
        "domain": domain,
        "tld": "." + tld if tld else "",
        "real_domain": real_domain,
        "path": path,
        "points": points,
        "reasons": reasons
    }


def analyze_message(text):
    if not text:
        text = ""
    else:
        text = str(text)[:5000]

    norm_text = normalize_text(text)

    score = 0
    reasons = []
    matched_words = []
    scam_type = "General Message"
    brand_help = None

    def add_matched(word):
        if not word:
            return
        for existing in matched_words:
            if word in existing or existing in word:
                return
        matched_words.append(word)

    # 1. Check urgent words
    for w in URGENT_WORDS:
        m = find_word_span(norm_text, w)
        if m:
            orig_w = text[m.start():m.end()]
            score += 25
            reasons.append("Urgent or threatening language: '" + orig_w + "' (+25 pts)")
            add_matched(orig_w)
            break

    # 2. Check payment / gift card words
    for w in PAYMENT_WORDS:
        m = find_word_span(norm_text, w)
        if m:
            orig_w = text[m.start():m.end()]
            score += 40
            reasons.append("Asks for untraceable payment or private info: '" + orig_w + "' (+40 pts)")
            add_matched(orig_w)
            scam_type = "Payment / Gift Card Scam"
            break

    # 3. Check job scams, prize scams, and tech support scams
    job_matches = []
    for w in JOB_SCAM_WORDS:
        m = find_word_span(norm_text, w)
        if m:
            if not any(not (m.end() <= s or m.start() >= e) for s, e in job_matches):
                job_matches.append((m.start(), m.end()))

    for pat in JOB_SCAM_PATTERNS:
        m = re.search(pat, norm_text, re.IGNORECASE)
        if m:
            if not any(not (m.end() <= s or m.start() >= e) for s, e in job_matches):
                job_matches.append((m.start(), m.end()))

    job_matches.sort(key=lambda span: span[0])
    for idx, (s, e) in enumerate(job_matches):
        orig_w = text[s:e]
        add_matched(orig_w)
        scam_type = "Job / Task Scam"
        if idx < 4:
            pts = 35 if idx == 0 else 20
            score += pts
            reasons.append("Matches Job / Task Scam phrase: '" + orig_w + "' (+" + str(pts) + " pts)")

    for w in PRIZE_SCAM_WORDS:
        m = find_word_span(norm_text, w)
        if m:
            orig_w = text[m.start():m.end()]
            score += 35
            reasons.append("Matches Prize / Giveaway Scam phrase: '" + orig_w + "' (+35 pts)")
            add_matched(orig_w)
            scam_type = "Prize / Lottery Scam"
            break

    for w in TECH_SCAM_WORDS:
        m = find_word_span(norm_text, w)
        if m:
            orig_w = text[m.start():m.end()]
            score += 35
            reasons.append("Matches Fake Tech Support / Invoice phrase: '" + orig_w + "' (+35 pts)")
            add_matched(orig_w)
            scam_type = "Fake Tech Support Scam"
            break

    # 4. Check generic greetings
    for w in GREETINGS:
        m = find_word_span(norm_text, w)
        if m:
            orig_w = text[m.start():m.end()]
            score += 15
            reasons.append("Generic greeting or scam phrasing: '" + orig_w + "' (+15 pts)")
            add_matched(orig_w)
            break

    # 5. Find and check all links (supports http://, https://, www., and bare domains like usps-scam.xyz/login)
    raw_urls = re.findall(
        r"(?:https?://|www\.)[^\s<>\"'`]+|\b[a-zA-Z0-9\u0370-\u03FF\u0400-\u04FF-]+\.(?:com|gov|org|net|xyz|top|tk|ru|cn|icu|vip|click|link|buzz|shop)(?:/[^\s<>\"'`]*)?",
        text
    )
    urls = []
    seen_urls = []
    for u in raw_urls:
        clean_u = u.rstrip(".,!?)\"'")
        if "@" + clean_u in text:
            continue
        if clean_u not in seen_urls:
            seen_urls.append(clean_u)
            info = check_url(clean_u)
            urls.append(info)
            score += info["points"]
            for r in info["reasons"]:
                reasons.append(r)

    # 5b. Check for homoglyph / lookalike character obfuscation in message text (outside URLs)
    text_without_urls = text
    for u in seen_urls:
        text_without_urls = text_without_urls.replace(u, " ")
    lookalike_found = None
    for ch in text_without_urls:
        if ch in LOOKALIKES:
            lookalike_found = LOOKALIKES[ch]
            break
    if lookalike_found:
        score += 40
        reasons.append(
            "Text uses disguised lookalike characters (e.g. " + lookalike_found + ") to bypass spam filters (+40 pts)"
        )
        # Highlight up to 3 obfuscated words not already inside matched_words
        obf_words = re.findall(r"\b\w+\b", text_without_urls)
        added_obf = 0
        for ow in obf_words:
            if any(c in LOOKALIKES for c in ow) and len(ow) >= 3:
                if not any(ow in mw or mw in ow for mw in matched_words):
                    add_matched(ow)
                    added_obf += 1
                    if added_obf >= 3:
                        break

    # 6. Check if message mentions a brand in our dictionary
    detected_brands = []
    for name, info in BRANDS.items():
        if is_brand_mentioned(text, name):
            detected_brands.append((name, info))

    if detected_brands:
        # Determine the primary impersonated brand:
        # 1. Highest priority: a brand whose name or domain appears in any link's path, subdomain, or domain
        # 2. Next priority: the brand that appears earliest in the message text
        def brand_priority(item):
            b_name, b_info = item
            score_prio = 0
            clean_name = b_name.replace(" ", "")
            for u in urls:
                url_str = normalize_text(u.get("raw_url") or "").lower()
                if clean_name in url_str or b_info["domain"] in url_str:
                    score_prio += 1000
            pos = norm_text.lower().find(b_name)
            if pos != -1:
                score_prio += max(0, 500 - pos)
            return score_prio

        detected_brands.sort(key=brand_priority, reverse=True)
        primary_name, primary_info = detected_brands[0]

        if scam_type == "Job / Task Scam":
            scam_type = "Job / Task Scam (" + primary_name.upper() + " Impersonation)"
        else:
            scam_type = primary_info["category"] + " Impersonation (" + primary_name.upper() + ")"
        brand_help = {
            "brand": primary_name.upper(),
            "official_domain": primary_info["domain"],
            "official_phone": primary_info["phone"]
        }

        seen_brand_domains = set()
        for name, info in detected_brands:
            if info["domain"] not in seen_brand_domains:
                seen_brand_domains.add(info["domain"])
                if len(urls) > 0 and urls[0]["real_domain"] != info["domain"]:
                    score += 30
                    reasons.append("Mentions " + name.upper() + " (" + info["domain"] + "), but link goes to " + urls[0]["real_domain"] + " (+30 pts)")

            # 7. Check if message includes a fake callback / contact phone number
            phones_in_text = re.findall(
                r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b|\+\d{10,15}\b",
                norm_text
            )
            official_digits = re.sub(r"\D", "", info["phone"])
            for p in phones_in_text:
                p_clean = p.strip()
                p_digits = re.sub(r"\D", "", p_clean)
                if p_digits and p_digits != official_digits and official_digits not in p_digits:
                    score += 35
                    reasons.append("Includes an unverified phone number (" + p_clean + "). Official " + name.upper() + " number is " + info["phone"] + " (+35 pts)")
                    add_matched(p_clean)

            # 8. Check if message includes an email address that doesn't match the official brand domain
            emails_in_text = re.findall(
                r"(?<![\w.-])[\w.-]{1,64}@([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b",
                norm_text
            )
            for email_domain in emails_in_text:
                if email_domain.lower() != info["domain"]:
                    score += 35
                    reasons.append("Email sender domain (@" + email_domain + ") does not match official " + name.upper() + " domain (" + info["domain"] + ") (+35 pts)")
                    add_matched(email_domain)

    if score > 100:
        score = 100

    if score >= 50:
        verdict = "HIGH RISK"
        color = "red"
        advice = "High likelihood of a phishing or scam attempt. Do not click any links, reply, or share personal information. Verify independently through an official website or phone number."
    elif score >= 20:
        verdict = "MODERATE RISK"
        color = "yellow"
        advice = "Caution advised: this message contains warning signs commonly found in scams. Verify the sender independently using an official app or phone number before taking action."
    else:
        verdict = "LOW RISK"
        color = "green"
        scam_type = "No Known Indicators Detected"
        advice = "No known scam patterns were detected by our automated checks. However, no tool is 100% certain—always remain vigilant and verify unexpected requests."

    return {
        "input_text": text,
        "overall_score": score,
        "verdict": verdict,
        "verdict_color": color,
        "scam_type": scam_type,
        "advice": advice,
        "reasons": reasons,
        "matched_words": matched_words,
        "urls": urls,
        "verified_brand_help": brand_help
    }
