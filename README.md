# PhishGuard

A machine learning web application that detects phishing URLs in real time. Paste any link and get an instant risk score, a verdict (SAFE / SUSPICIOUS / PHISHING), and a full explanation of why.

## Features

- Random Forest classifier trained on 120K labeled URLs
- 22 lexical features extracted from the URL structure (no network calls, links are never visited)
- Trusted domain allowlist with spoof-safe matching
- Brand impersonation detection
- Risk breakdown, detected keywords, and URL feature table
- Model Details page explaining the full technical pipeline

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```bash
python app/app.py
```

Open http://127.0.0.1:5000

### Retrain the model (optional)

The trained model is included. To retrain from scratch, download the dataset from HuggingFace (`Mitake/PhishingURLsANDBenignURLs`) as `data/phishbenign.csv`, then run:

```bash
python train.py
```

## Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 86.5% |
| Precision | 87.2% |
| Recall | 85.5% |
| ROC-AUC | 0.94 |

## Tech Stack

Python, scikit-learn, Flask, vanilla JS
