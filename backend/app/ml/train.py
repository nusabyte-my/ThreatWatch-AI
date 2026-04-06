"""
Train or retrain the scam detection model.
Run: python -m app.ml.train [--seed]

Uses bundled seed data if no external dataset is present.
Saves model.pkl to MODEL_PATH.
"""
import argparse
import os
import joblib
import nltk
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from app.config import settings
from app.ml.preprocessor import preprocess

# ---------------------------------------------------------------------------
# Seed dataset — enough to bootstrap a working demo
# ---------------------------------------------------------------------------
SEED_SCAM = [
    "URGENT: Your Maybank account has been suspended. Verify now at http://bit.ly/mayb4nk",
    "Congratulations! You've won RM5000. Click here to claim your prize immediately",
    "Your OTP is 348291. NEVER share your OTP with anyone including bank staff.",
    "Dear customer, your account will be locked in 24 hours. Update your info: http://login-bank.xyz",
    "FREE: You have been selected for RM1000 government aid. Tap here to register",
    "ALERT: Suspicious login detected. Verify your identity now or account will be disabled",
    "Investment opportunity! Guaranteed 30% monthly return. WhatsApp us now",
    "Your parcel is on hold. Pay RM3.50 customs fee: http://pos-laju.top/pay",
    "Maybank2u: Please verify your account to avoid suspension. Click http://tinyurl.com/mb2u",
    "You have pending credit card rewards. Claim before they expire: http://rewards.click",
    "FINAL WARNING: Legal action will be taken if you don't pay outstanding tax now",
    "Your Netflix subscription failed. Update payment: http://netflix-update.xyz",
    "Win an iPhone 15! You're our 1000th visitor. Click to claim now!",
    "CIMB: Account temporarily restricted. Verify via this link to restore access",
    "Send RM200 gift card code to receive your RM2000 prize. Limited time offer!",
    "Your DHL shipment requires customs clearance fee. Pay here: http://dhl-clearance.tk",
    "URGENT reply needed — transfer RM5000 to this account immediately, boss needs it",
    "You have unclaimed Shopee vouchers worth RM500. Tap here before midnight",
    "Bank Islam: Your token has expired. Click here to renew: http://bankislam.ml",
    "Earn RM300/day from home! No experience needed. WhatsApp to join our team",
]

SEED_SAFE = [
    "Hi, are we still meeting at 3pm today for the project discussion?",
    "Your order #12345 has been shipped. Estimated delivery: 3-5 business days.",
    "Please find attached the invoice for last month's services.",
    "The team lunch is confirmed for Friday at 1pm. See you there!",
    "Your password was changed successfully. If you did not make this change, contact support.",
    "Monthly statement for March 2026 is now available in your online banking portal.",
    "Hi, just following up on the proposal I sent last week. Any updates?",
    "Your appointment is confirmed for Tuesday 10am at KL Sentral.",
    "Thank you for your payment of RM450. Receipt number: INV-2026-0392.",
    "Reminder: Team meeting tomorrow at 9am. Agenda attached.",
    "Your subscription renews on April 15. Log in to manage your plan.",
    "The report you requested is ready. You can download it from the portal.",
    "Security tip: Never share your password or OTP with anyone.",
    "Your flight booking is confirmed. Check-in opens 48 hours before departure.",
    "New message from your doctor: Your test results are ready. Please log in to view.",
    "Payment received. Thank you for settling invoice #INV-9834.",
    "Your package has been delivered to the parcel locker. Pickup code: 4821.",
    "Please review and sign the NDA before our call on Thursday.",
    "Happy birthday! Hope you have a wonderful day.",
    "Your tax return has been processed. Refund of RM320 will be credited in 5-7 days.",
]


def build_dataset():
    texts = SEED_SCAM + SEED_SAFE
    labels = [1] * len(SEED_SCAM) + [0] * len(SEED_SAFE)
    return texts, labels


def train(save_path: str):
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)

    texts, labels = build_dataset()
    processed = [preprocess(t) for t in texts]

    X_train, X_test, y_train, y_test = train_test_split(
        processed, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # Two models — LR is primary, NB is secondary
    lr_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=500, C=1.0, class_weight="balanced")),
    ])

    nb_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
        ("clf", MultinomialNB(alpha=0.5)),
    ])

    # Soft voting ensemble
    lr_pipeline.fit(X_train, y_train)
    nb_pipeline.fit(X_train, y_train)

    bundle = {
        "lr": lr_pipeline,
        "nb": nb_pipeline,
        "version": "1.0",
    }

    joblib.dump(bundle, save_path)
    print(f"[train] Model saved → {save_path}")

    # Quick eval
    lr_preds = lr_pipeline.predict(X_test)
    print("[train] LR evaluation:")
    print(classification_report(y_test, lr_preds, target_names=["safe", "scam"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", action="store_true", help="Force retrain from seed data")
    args = parser.parse_args()
    train(settings.model_path)
