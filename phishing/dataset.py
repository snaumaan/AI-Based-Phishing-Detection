"""Deterministically create the bundled educational synthetic sample dataset.

Includes diverse multi-vector templates covering URLs, emails, and HTML markup.
Author: PhishGuard Project. Fixed seed ensures 100% reproducibility.
"""
from __future__ import annotations
import random
import pandas as pd
from .features import extract_features, FEATURE_NAMES

SEED = 2026

URL_BAD = [
    "http://192.0.2.10/verify-account",
    "http://secure-login.example.xyz/account/update",
    "http://account-verify.bank-security.top/urgent-login",
    "http://payment-alert.wallet-auth.work/confirm",
    "http://wallet-secure.crypto-login.buzz/password-reset",
    "http://login.paypal-update.example.test/verify-now",
    "http://bank-support.secure-session.click/credential-check",
    "http://prize-claim.bonus-rewards.xyz/limited-offer",
    "http://user.billing-notification.support/account-suspended",
    "http://signin.identity-recovery.club/one-time-code",
    "http://0x7f000001/bank/login",
    "http://xn--pypal-4ve.com/account-verification",
    "http://apple-id-verify.support-device.xyz/login.php?user=alert",
    "http://microsoft365-secure.tenant-auth.top/auth/session",
]

URL_GOOD = [
    "https://www.example.com/about",
    "https://docs.example.org/getting-started",
    "https://university.example.edu/course/catalog",
    "https://shop.example.com/products/books",
    "https://news.example.org/technology",
    "https://library.example.edu/search?q=python",
    "https://www.example.net/contact",
    "https://status.example.com/uptime",
    "https://developer.example.org/reference/api",
    "https://museum.example.edu/visit",
    "https://github.com/torvalds/linux/releases",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://portal.reva.edu.in/student/dashboard",
    "https://scholar.google.com/citations?user=sample",
]

EMAIL_BAD = [
    "URGENT: verify your account password immediately using http://login.example.xyz or your service will be terminated.",
    "Final warning: payment suspended. Confirm your credentials now at http://pay.wallet-update.top to unlock access.",
    "Your wallet account will expire today. Sign in to update your password and private key immediately.",
    "Security alert: unauthorized login detected from Russia. One-time code and password required to secure your account: http://auth.session-verify.xyz",
    "Limited prize: you have won $5,000. Verify your bank details immediately at http://prize.claim-funds.buzz",
    "Account suspended: multiple failed login attempts. Log in now to confirm billing credentials: <a href='http://evil-server.xyz'>https://paypal.com/signin</a>",
    "Support notice: mandatory IT account update required within 24 hours. Enter your password at http://staff-portal.auth-login.work",
    "Invoice #94827 is past due. Confirm your sign in immediately at http://billing-check.xyz or your account access will expire.",
]

EMAIL_GOOD = [
    "Hello team, the lecture notes are attached for your review before Friday's class.",
    "Your library book is due next week. You can view opening hours and renewals on our official website.",
    "Thanks for attending the research seminar. Attached are the meeting notes and action items.",
    "The academic course catalog has been updated for the upcoming semester. Please check your schedule.",
    "Your order summary #40291 is available in your account order history on https://shop.example.com.",
    "Reminder: the departmental colloquium begins at 2:00 PM today in the main auditorium.",
    "Please review the project rubric and submit your Phase-1 draft by the stated university deadline.",
    "Your monthly newsletter includes new publications, event photos, and community announcements.",
]

HTML_BAD = [
    '<html><body><h1>Urgent verify account</h1><form action="http://192.0.2.10/login"><input type="password" name="pwd"><button>Sign in now</button></form></body></html>',
    '<html><body>Payment suspended immediately<form action="http://external-catcher.xyz/steal"><input type="password"><input type="hidden" name="session_token"></form><iframe src="http://phish.xyz"></iframe></body></html>',
    '<html><body>Secure wallet update today<form><input type="password" name="seed_phrase"><input name="otp"><button>Confirm</button></form></body></html>',
    '<html><body>Final warning: account expire.<form action="http://harvester.top/log"><input type="password"></form><a href="http://login.example.xyz">https://mybank.com</a></body></html>',
    '<html><body><h1>Sign In to Office 365</h1><form action="http://steal-credentials.xyz"><input type="text" placeholder="Work Email"><input type="password" placeholder="Password"><button>Verify</button></form></body></html>',
]

HTML_GOOD = [
    '<html><body><h1>Course catalog</h1><p>Browse the semester schedule and syllabi.</p><a href="https://university.example.edu/courses">Courses</a></body></html>',
    '<html><body><h1>Library hours</h1><p>Open Monday through Friday from 8:00 AM to 8:00 PM.</p></body></html>',
    '<html><body><h1>Community news</h1><p>Read our latest research announcements and publications.</p><a href="https://news.example.org">News</a></body></html>',
    '<html><body><h1>Product details</h1><p>Read technical specifications and customer support documentation.</p></body></html>',
    '<html><body><h1>Conference Agenda</h1><p>Keynote at 9 AM, paper sessions at 11 AM.</p><a href="https://acm.org">Event Info</a></body></html>',
]


def build_dataset(n_per_class_per_type: int = 80) -> pd.DataFrame:
    rng = random.Random(SEED)
    rows = []
    pools = {
        "URL": (URL_BAD, URL_GOOD),
        "Email": (EMAIL_BAD, EMAIL_GOOD),
        "HTML": (HTML_BAD, HTML_GOOD)
    }
    benign_suffixes = ["", "?ref=academic", "/overview", " - please review", " # public notice", "/resources"]
    suspicious_prefixes = ["", "! ACTION REQUIRED: ", " [Security Alert] ", " Billing Update: ", " Account Restriction Notice: "]

    for input_type, (bad_pool, good_pool) in pools.items():
        for label, pool in [(1, bad_pool), (0, good_pool)]:
            for i in range(n_per_class_per_type):
                base = pool[i % len(pool)]
                if input_type == "URL":
                    text = base + (f"/page{i}" if i % 3 == 0 else (f"?ref=auth{i}" if i % 3 == 1 else ""))
                elif input_type == "Email":
                    text = (suspicious_prefixes[i % len(suspicious_prefixes)] + base if label
                            else base + benign_suffixes[i % len(benign_suffixes)])
                else:
                    text = base.replace(
                        "</body>",
                        f"<p>{'Verify security settings immediately' if label and i % 2 else 'Read the student information handbook below' if not label and i % 2 else 'Details and documentation'}</p></body>"
                    )
                features = extract_features(input_type, text)
                rows.append({
                    "input_type": input_type,
                    "text": text,
                    "label": label,
                    "group_id": f"{input_type}_{label}_{i % len(pool)}",
                    **features
                })
    rng.shuffle(rows)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    from pathlib import Path
    out = Path(__file__).resolve().parents[1] / "data" / "sample_dataset.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    df = build_dataset()
    df.to_csv(out, index=False)
    print(f"Generated {out} with {len(df)} examples across {df['group_id'].nunique()} template groups.")
