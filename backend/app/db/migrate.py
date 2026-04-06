"""Run on container start — creates tables if not exist, seeds rules."""
import asyncio
from app.db.base import engine, Base
from app.db import models  # noqa: F401 — registers all models


async def run():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[migrate] Tables created / verified.")
    await seed_rules()
    await seed_domains()


async def seed_rules():
    from app.db.base import SessionLocal
    from app.db.models import Rule
    from sqlalchemy import select

    default_rules = [
        # --- Urgency ---
        ("urgent_action", r"\b(urgent|immediately|act now|right now|asap)\b", "regex", 0.25, "Urgency pressure tactic", "urgency"),
        ("account_suspended", r"\b(account|access).{0,15}(suspended|locked|disabled|blocked)\b", "regex", 0.30, "Account threat language", "urgency"),
        ("limited_time", r"\b(limited time|offer expires|hours? left|minutes? left)\b", "regex", 0.20, "Artificial deadline", "urgency"),

        # --- Phishing ---
        ("verify_credentials", r"\b(verify|confirm|update).{0,20}(account|password|detail|info|login)\b", "regex", 0.30, "Credential harvesting pattern", "phishing"),
        ("click_link", r"\b(click here|click the link|tap here|follow this link)\b", "regex", 0.25, "Phishing CTA", "phishing"),
        ("prize_winner", r"\b(you('ve| have) won|congratulations|selected as winner|lucky winner)\b", "regex", 0.35, "Fake prize / lottery scam", "phishing"),
        ("impersonation_bank", r"\b(maybank|cimb|rhb|hong leong|public bank|ambank|bsn|bank islam).{0,30}(click|verify|login|account)\b", "regex", 0.40, "Bank impersonation", "phishing"),

        # --- OTP / Financial ---
        ("otp_share", r"\b(otp|one.time.password|pin|passcode).{0,20}(share|send|give|provide|enter)\b", "regex", 0.45, "OTP sharing request — very high risk", "otp"),
        ("money_transfer", r"\b(transfer|send).{0,15}(rm|myr|ringgit|\$|usd|money|fund)\b", "regex", 0.35, "Money transfer request", "financial"),
        ("gift_card", r"\b(gift card|voucher|reload|prepaid).{0,20}(send|buy|purchase|pay)\b", "regex", 0.40, "Gift card scam pattern", "financial"),
        ("investment_return", r"\b(return|profit|invest).{0,20}(\d{2,3}%|guaranteed|sure)\b", "regex", 0.35, "Fake investment returns", "financial"),

        # --- URL patterns ---
        ("url_shortener", r"\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.io|rb\.gy)\b", "regex", 0.30, "URL shortener used", "url"),
        ("free_tld", r"\.(xyz|top|click|loan|online|tk|ml|ga|cf)\b", "regex", 0.25, "Suspicious TLD", "url"),
        ("ip_url", r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "regex", 0.35, "IP address used as URL", "url"),
    ]

    async with SessionLocal() as db:
        result = await db.execute(select(Rule))
        existing = {r.name for r in result.scalars().all()}
        new_rules = [
            Rule(name=n, pattern=p, pattern_type=pt, weight=w, description=d, category=c)
            for n, p, pt, w, d, c in default_rules
            if n not in existing
        ]
        if new_rules:
            db.add_all(new_rules)
            await db.commit()
            print(f"[migrate] Seeded {len(new_rules)} rules.")
        else:
            print("[migrate] Rules already seeded.")


async def seed_domains():
    from app.db.base import SessionLocal
    from app.db.models import SuspiciousDomain
    from sqlalchemy import select

    shorteners = [
        ("bit.ly", "shortener", 0.30), ("tinyurl.com", "shortener", 0.30),
        ("t.co", "shortener", 0.20), ("goo.gl", "shortener", 0.25),
        ("ow.ly", "shortener", 0.25), ("rb.gy", "shortener", 0.30),
    ]
    free_tlds = [
        ("*.tk", "free_tld", 0.25), ("*.ml", "free_tld", 0.25),
        ("*.ga", "free_tld", 0.25), ("*.cf", "free_tld", 0.25),
        ("*.xyz", "free_tld", 0.20), ("*.top", "free_tld", 0.20),
    ]

    async with SessionLocal() as db:
        result = await db.execute(select(SuspiciousDomain))
        existing = {r.domain for r in result.scalars().all()}
        entries = [
            SuspiciousDomain(domain=d, reason=r, risk_weight=w)
            for d, r, w in (shorteners + free_tlds)
            if d not in existing
        ]
        if entries:
            db.add_all(entries)
            await db.commit()
            print(f"[migrate] Seeded {len(entries)} suspicious domains.")


if __name__ == "__main__":
    asyncio.run(run())
