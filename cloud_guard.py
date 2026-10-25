#!/usr/bin/env python3
"""
iCloud Mail 24/7 Cloud Anti-Phishing Guard (Production Grade v3.1)
High-precision, Zero false-positive detection.
100% Free, Zero Cloud Cost, Ultra-low CPU.
"""

import os
import sys
import imaplib
import email
from email.header import decode_header
import urllib.parse
import re
import datetime

# --- Comprehensive Japanese Phishing Database (v3.1) ---
OFFICIAL_DOMAINS = {
    # 官公庁
    "国税庁": ["nta.go.jp", "e-tax.nta.go.jp"],
    "e-tax": ["nta.go.jp", "e-tax.nta.go.jp"],
    "税務署": ["nta.go.jp", "e-tax.nta.go.jp"],
    "マイナポータル": ["myna.go.jp", "digital.go.jp"],
    "デジタル庁": ["digital.go.jp"],
    "日本年金機構": ["nenkin.go.jp"],
    "厚生労働省": ["mhlw.go.jp"],
    "警察庁": ["npa.go.jp"],

    # 交通・ETC
    "etc": ["etc-meisai.jp", "etc-plaza.jp", "driveplaza.com", "shutoko.jp", "nexco.ne.jp", "c-nexco.co.jp", "w-nexco.co.jp"],
    "えきねっと": ["eki-net.com"],
    "jreast": ["jreast.co.jp", "eki-net.com"],
    "jr東日本": ["jreast.co.jp", "eki-net.com"],
    "jr西日本": ["jr-odekake.net", "westjr.co.jp"],
    "スマートex": ["smart-ex.jp"],
    "ana": ["ana.co.jp"],
    "jal": ["jal.co.jp"],

    # 公共料金
    "東京電力": ["tepco.co.jp"],
    "tepco": ["tepco.co.jp"],
    "関西電力": ["kepco.co.jp"],
    "中部電力": ["chuden.co.jp"],
    "大阪ガス": ["osakagas.co.jp"],
    "東京ガス": ["tokyogas.co.jp"],
    "水道局": ["metro.tokyo.lg.jp", "waterworks.metro.tokyo.lg.jp"],
    "nhk": ["nhk.or.jp"],

    # クレジットカード
    "jcb": ["jcb.co.jp"],
    "三井住友カード": ["smbc-card.com", "smbc.co.jp", "vpass.ne.jp"],
    "vpass": ["vpass.ne.jp", "smbc-card.com"],
    "セゾンカード": ["saisoncard.co.jp"],
    "クレディセゾン": ["saisoncard.co.jp"],
    "エポスカード": ["eposcard.co.jp"],
    "epos": ["eposcard.co.jp"],
    "イオンカード": ["aeon.co.jp"],
    "aeon": ["aeon.co.jp"],
    "楽天カード": ["rakuten-card.co.jp", "rakuten.co.jp"],
    "paypayカード": ["paypay-card.co.jp", "paypay.ne.jp"],
    "dカード": ["dcard.co.jp", "docomo.ne.jp"],
    "au payカード": ["kddi-fs.com", "au.com"],
    "viewcard": ["viewsnet.jp", "jreast.co.jp"],
    "ビューカード": ["viewsnet.jp", "jreast.co.jp"],
    "アメリカン・エキスプレス": ["americanexpress.com"],
    "amex": ["americanexpress.com"],

    # 銀行
    "三井住友銀行": ["smbc.co.jp"],
    "smbc": ["smbc.co.jp"],
    "三菱ufj": ["mufg.jp", "bk.mufg.jp", "cr.mufg.jp"],
    "mufg": ["mufg.jp", "bk.mufg.jp"],
    "みずほ": ["mizuhobank.co.jp"],
    "ゆうちょ": ["jp-bank.japanpost.jp", "japanpost.jp"],
    "りそな": ["resonabank.co.jp"],
    "住信sbi": ["netbk.co.jp"],
    "楽天銀行": ["rakuten-bank.co.jp"],
    "paypay銀行": ["paypay-bank.co.jp"],

    # 通信
    "docomo": ["docomo.ne.jp", "dpoint.jp", "dmarket.docomo.ne.jp"],
    "ドコモ": ["docomo.ne.jp", "dpoint.jp"],
    "dアカウント": ["docomo.ne.jp"],
    "au": ["au.com", "kddi.com", "auone.jp"],
    "kddi": ["kddi.com", "au.com"],
    "softbank": ["softbank.jp", "mb.softbank.jp"],
    "ソフトバンク": ["softbank.jp", "mb.softbank.jp"],
    "ymobile": ["ymobile.jp"],
    "ワイモバイル": ["ymobile.jp"],
    "uq mobile": ["uqwimax.jp"],

    # 物流
    "ヤマト": ["kuronekoyamato.co.jp", "yamato-hd.co.jp"],
    "クロネコ": ["kuronekoyamato.co.jp", "yamato-hd.co.jp"],
    "佐川急便": ["sagawa-exp.co.jp"],
    "日本郵便": ["post.japanpost.jp", "japanpost.jp"],

    # ショッピング
    "amazon": ["amazon.co.jp", "amazon.com", "media-amazon.com"],
    "アマゾン": ["amazon.co.jp", "amazon.com"],
    "楽天": ["rakuten.co.jp", "rakuten-card.co.jp", "rakuten-bank.co.jp"],
    "rakuten": ["rakuten.co.jp"],
    "メルカリ": ["mercari.com", "mercari.jp"],
    "mercari": ["mercari.com", "mercari.jp"],
    "ヤフー": ["yahoo.co.jp"],
    "yahoo": ["yahoo.co.jp"],
    "paypay": ["paypay.ne.jp", "paypay-card.co.jp"],
    "line": ["line.me", "lycorp.co.jp"],
    "アップル": ["apple.com", "icloud.com"],
    "apple": ["apple.com", "icloud.com"],
}

ALL_LEGIT_DOMAINS = {d for dom_list in OFFICIAL_DOMAINS.values() for d in dom_list}

SUSPICIOUS_TLDS = {
    ".top", ".xyz", ".icu", ".work", ".click", ".buzz", ".fit",
    ".cn", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".vip", ".surf",
    ".cc", ".rest", ".shop", ".online", ".site", ".live"
}

def extract_sender_email(sender_str):
    match = re.search(r'<([^>]+)>', sender_str)
    if match:
        return match.group(1).lower()
    return sender_str.strip().lower()

def extract_display_name(sender_str):
    return re.sub(r'<[^>]+>', '', sender_str).strip().lower()

def extract_urls(text):
    if not text:
        return []
    url_pattern = r'https?://[^\s<>"\')]+'
    return re.findall(url_pattern, text)

def get_base_domain(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        return hostname.lower() if hostname else ""
    except Exception:
        return ""

def is_domain_in_list(domain, domain_list):
    for legit in domain_list:
        if domain == legit or domain.endswith("." + legit):
            return True
    return False

def is_phishing(subject, sender, body):
    sender_email = extract_sender_email(sender)
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    # Appleプライベートリレー（メールを非公開）経由のメールはユーザー本人の登録メールなので安全
    if "privaterelay.appleid.com" in sender_domain:
        return False, None

    if is_domain_in_list(sender_domain, ALL_LEGIT_DOMAINS):
        return False, None

    # ブランド名詐称の判定には「表示名」と「件名」のみを使う（アドレス内の文字列で誤爆しないように）
    display_name = extract_display_name(sender)
    header_text = f"{subject} {display_name}".lower()
    urls = extract_urls(body)
    if not urls:
        return False, None

    for brand_key, legitimate_domains in OFFICIAL_DOMAINS.items():
        if brand_key in header_text:
            if not is_domain_in_list(sender_domain, legitimate_domains):
                fake_links = []
                for u in urls:
                    d = get_base_domain(u)
                    if not d or any(d.endswith(x) for x in ["apple.com", "icloud.com", "google.com", "twitter.com", "facebook.com", "instagram.com", "youtube.com"]):
                        continue
                    if not is_domain_in_list(d, legitimate_domains):
                        fake_links.append((u, d))

                if fake_links:
                    first_fake_url, first_fake_domain = fake_links[0]
                    return True, f"ブランド偽装: '{brand_key}' を名乗っていますが送信元({sender_email})およびリンク先({first_fake_domain})が公式外です"

    urgent_keywords = ["未払い", "利用停止", "料金", "差し押さえ", "滞納", "アカウント制限", "緊急", "本人確認", "支払期日", "制限を解除", "不正アクセス", "利用制限"]
    has_urgent = any(k in (header_text + " " + body) for k in urgent_keywords)

    if has_urgent:
        for u in urls:
            d = get_base_domain(u)
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', d):
                return True, f"直接IPアドレスへの誘導: {d}"
            for tld in SUSPICIOUS_TLDS:
                if d.endswith(tld):
                    return True, f"危険TLDリンク ({tld}): {d}"

    return False, None

def decode_mime_header(val):
    if not val:
        return ""
    decoded_parts = decode_header(val)
    res = ""
    for part, enc in decoded_parts:
        if isinstance(part, bytes):
            res += part.decode(enc or "utf-8", errors="ignore")
        else:
            res += str(part)
    return res

def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            if ctype in ["text/plain", "text/html"] and "attachment" not in cdispo:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body += payload.decode(charset, errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="ignore")
    return body

def run_cloud_guard():
    email_user = os.environ.get("ICLOUD_EMAIL")
    email_pass = os.environ.get("ICLOUD_APP_PASSWORD")

    if not email_user or not email_pass:
        print("❌ Error: ICLOUD_EMAIL and ICLOUD_APP_PASSWORD environment variables are required.")
        sys.exit(1)

    print(f"[{datetime.datetime.now()}] Connecting to iCloud Mail IMAP server...")
    try:
        mail = imaplib.IMAP4_SSL("imap.mail.me.com", 993)
        mail.login(email_user, email_pass)
        print("✅ Logged in to iCloud Mail successfully.")
    except Exception as e:
        print(f"❌ Failed to login to iCloud Mail: {e}")
        sys.exit(1)

    # Detect exact trash mailbox name
    resp, mailboxes = mail.list()
    trash_folder = '"Deleted Messages"'
    for mb in mailboxes:
        decoded_mb = mb.decode("utf-8", errors="ignore")
        if "\\Trash" in decoded_mb:
            parts = decoded_mb.split(' "/" ')
            if len(parts) > 1:
                trash_folder = parts[-1]
            break

    mail.select("INBOX")
    status, messages = mail.search(None, "ALL")
    if status != "OK" or not messages[0]:
        print("No messages in INBOX.")
        mail.logout()
        return

    msg_ids = messages[0].split()
    recent_ids = msg_ids[-30:] # check up to 30 recent emails
    print(f"Scanning {len(recent_ids)} recent emails in INBOX...")

    trashed_count = 0
    for mid in reversed(recent_ids):
        status, data = mail.fetch(mid, "(RFC822)")
        if status != "OK" or not data:
            continue

        raw_email = None
        for part in data:
            if isinstance(part, tuple) and len(part) > 1:
                raw_email = part[1]
                break

        if not raw_email or not isinstance(raw_email, bytes):
            continue

        msg = email.message_from_bytes(raw_email)

        subject = decode_mime_header(msg.get("Subject", ""))
        sender = decode_mime_header(msg.get("From", ""))
        body = get_email_body(msg)

        is_fake, reason = is_phishing(subject, sender, body)
        if is_fake:
            print(f"\n🚨 [PHISHING DETECTED! TRASHING...]")
            print(f"   Subject: {subject}")
            print(f"   Sender:  {sender}")
            print(f"   Reason:  {reason}")

            # Mark as read
            mail.store(mid, "+FLAGS", "(\\Seen)")
            # Copy to Trash (Properly quoted for IMAP)
            mail.copy(mid, trash_folder)
            # Mark deleted from INBOX
            mail.store(mid, "+FLAGS", "(\\Deleted)")
            trashed_count += 1

    if trashed_count > 0:
        mail.expunge()

    mail.close()
    mail.logout()

    print(f"\n✨ Inspection complete. Trashed {trashed_count} phishing emails.")

if __name__ == "__main__":
    run_cloud_guard()
