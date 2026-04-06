import re
import string
import nltk
from nltk.corpus import stopwords

try:
    _STOPWORDS = set(stopwords.words("english"))
except LookupError:
    nltk.download("stopwords")
    _STOPWORDS = set(stopwords.words("english"))

# Keep scam-signal words even if they're "stopwords"
_KEEP = {"not", "no", "never", "urgent", "free", "win", "won", "click", "now", "limited"}
_STOPWORDS -= _KEEP

URL_RE = re.compile(r"https?://\S+|www\.\S+")
EMAIL_RE = re.compile(r"\S+@\S+")


def preprocess(text: str) -> str:
    text = text.lower()
    text = URL_RE.sub(" url_token ", text)
    text = EMAIL_RE.sub(" email_token ", text)
    text = text.translate(str.maketrans("", "", string.punctuation))
    tokens = text.split()
    tokens = [t for t in tokens if t not in _STOPWORDS and len(t) > 1]
    return " ".join(tokens)
