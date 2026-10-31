"""PhishShield X - Machine Learning Service

Implements lightweight TF-IDF + Logistic Regression for scam/phishing message classification.
Trained once and saved to disk. If model loading fails, rules-based engine continues operating.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from app.schemas.findings import FindingCategory, FindingSeverity, ScanFindingResponse

logger = logging.getLogger("phishshield.ml")

# Paths for models and datasets
BASE_DIR = Path(__file__).resolve().parent.parent.parent
MODEL_PATH = BASE_DIR / "models" / "phish_classifier.joblib"
DATASET_PATH = BASE_DIR / "data" / "training_samples.json"


class MLClassificationService:
    """Manages training, loading, and inference for message phishing classification."""

    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        self.pipeline: Optional[Pipeline] = None
        self.is_available: bool = False
        self._initialize_model()

    def _initialize_model(self) -> None:
        """Load trained model if present; otherwise train from seed dataset."""
        try:
            if self.model_path.exists():
                import warnings
                with warnings.catch_warnings(record=True) as caught_warnings:
                    warnings.simplefilter("always")
                    self.pipeline = joblib.load(self.model_path)
                    # Check if there is an InconsistentVersionWarning
                    has_version_warning = any(
                        "InconsistentVersionWarning" in str(w.category.__name__)
                        or "version" in str(w.message).lower()
                        for w in caught_warnings
                    )
                    if has_version_warning:
                        logger.info("Detected scikit-learn version mismatch in saved model. Re-fitting locally...")
                        self.train_and_save()
                        return

                self.is_available = True
                logger.info("Loaded pre-trained ML phishing classification model.")
            else:
                logger.info("No saved ML model found. Training initial model from training dataset...")
                self.train_and_save()
        except Exception as exc:
            logger.warning(f"ML model failed to load ({exc}). Attempting fresh train...")
            try:
                self.train_and_save()
            except Exception as train_exc:
                logger.warning(f"Retrain also failed: {train_exc}. Operating in rule-only mode.")
                self.pipeline = None
                self.is_available = False

    def train_and_save(self) -> bool:
        """Train pipeline using Scikit-learn TF-IDF + Logistic Regression and persist artifact."""
        if not DATASET_PATH.exists():
            logger.warning(f"Training dataset not found at {DATASET_PATH}")
            return False

        try:
            with open(DATASET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)

            texts = [item["text"] for item in data]
            labels = [item["label"] for item in data]

            # TF-IDF + Logistic Regression Pipeline
            pipeline = Pipeline(
                [
                    (
                        "tfidf",
                        TfidfVectorizer(
                            ngram_range=(1, 2),
                            max_features=1000,
                            lowercase=True,
                            stop_words="english",
                        ),
                    ),
                    (
                        "clf",
                        LogisticRegression(
                            C=1.0,
                            max_iter=500,
                            class_weight="balanced",
                            random_state=42,
                        ),
                    ),
                ]
            )

            # Train model
            pipeline.fit(texts, labels)

            # Ensure models directory exists
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(pipeline, self.model_path)

            self.pipeline = pipeline
            self.is_available = True
            logger.info(f"Trained and persisted ML classifier to {self.model_path}")
            return True
        except Exception as exc:
            logger.error(f"Error training ML classifier: {exc}")
            self.is_available = False
            return False

    def predict(self, text: str) -> Optional[Tuple[bool, float]]:
        """Predict phishing probability for a message.
        
        Returns:
            (is_phishing, confidence_probability) or None if model unavailable.
        """
        if not self.is_available or self.pipeline is None:
            return None

        try:
            clean_text = text.strip()
            if not clean_text:
                return (False, 0.0)

            # Probability of class 1 (phishing/scam)
            probs = self.pipeline.predict_proba([clean_text])[0]
            phish_prob = float(probs[1])
            is_phishing = phish_prob >= 0.50
            return (is_phishing, round(phish_prob, 3))
        except Exception as exc:
            logger.warning(f"ML inference error: {exc}")
            return None

    def analyze_message_ml(self, text: str) -> List[ScanFindingResponse]:
        """Produce structured scan findings based on ML confidence score."""
        findings: List[ScanFindingResponse] = []
        result = self.predict(text)
        if not result:
            return findings

        is_phishing, prob = result
        if is_phishing and prob >= 0.50:
            severity = FindingSeverity.HIGH.value if prob >= 0.70 else FindingSeverity.MEDIUM.value
            pts = 10 if prob >= 0.70 else 8
            findings.append(
                ScanFindingResponse(
                    id="ml_001",
                    category=FindingCategory.REPUTATION.value,
                    severity=severity,
                    points=pts,
                    title="Machine learning flagged statistical phishing patterns",
                    evidence=f"TF-IDF Logistic Classifier confidence: {int(prob * 100)}%",
                    explanation=(
                        "Statistical language patterns strongly correlate with known scam communications, "
                        "exhibiting deceptive lexical patterns and coercive social engineering traits."
                    ),
                )
            )

        return findings


# Singleton ML Service
ml_service = MLClassificationService()
