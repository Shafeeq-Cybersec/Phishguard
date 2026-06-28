import os
import random

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import train_test_split

from model.features import FEATURE_NAMES, featurize

RANDOM_SEED = 42
DATA_PATH = os.path.join("data", "phishbenign.csv")
MODEL_PATH = os.path.join("model", "phishguard_model.pkl")
MAX_PER_CLASS = 75_000

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


def load_urls(path: str):
    phishing, benign = [], []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        next(fh, None)
        for line in fh:
            line = line.strip()
            if not line:
                continue
            url, _, label = line.rpartition(",")
            if label == "1":
                phishing.append(url)
            elif label == "0":
                benign.append(url)
    return phishing, benign


def build_balanced_dataset(phishing, benign):
    random.shuffle(phishing)
    random.shuffle(benign)
    n = min(len(phishing), len(benign), MAX_PER_CLASS)
    urls = phishing[:n] + benign[:n]
    labels = [1] * n + [0] * n
    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)


def main():
    print("=" * 60)
    print("PhishGuard - Model Training")
    print("=" * 60)

    print(f"\n[1/5] Loading data from {DATA_PATH} ...")
    phishing, benign = load_urls(DATA_PATH)
    print(f"      phishing: {len(phishing):,}  benign: {len(benign):,}")

    print("\n[2/5] Balancing classes ...")
    urls, labels = build_balanced_dataset(phishing, benign)
    print(f"      total: {len(urls):,}")

    print("\n[3/5] Extracting features ...")
    X = np.array([featurize(u) for u in urls], dtype=float)
    y = np.array(labels)
    print(f"      {X.shape[0]:,} rows x {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    print("\n[4/5] Training RandomForestClassifier ...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        min_samples_leaf=20,
        n_jobs=-1,
        random_state=RANDOM_SEED,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    print("\n[5/5] Evaluating ...")
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    auc = roc_auc_score(y_test, y_proba)

    print(f"      Accuracy:  {acc:.4f}")
    print(f"      Precision: {prec:.4f}")
    print(f"      Recall:    {rec:.4f}")
    print(f"      F1:        {f1:.4f}")
    print(f"      ROC-AUC:   {auc:.4f}")

    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_),
        key=lambda t: t[1], reverse=True,
    )

    print(f"\nSaving model -> {MODEL_PATH}")
    joblib.dump({
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "roc_auc": auc},
        "feature_importances": dict(importances),
        "trained_on": len(X_train),
    }, MODEL_PATH)
    print("Done.")


if __name__ == "__main__":
    main()
