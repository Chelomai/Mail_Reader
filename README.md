# Email Analysis & Security Scanner ????

A Python utility that parses `.eml` files, performs NLP-based sentiment analysis, detects potential phishing risk indicators, and generates structured CSV/JSON reports.

## Features
- **Parsing**: Extracts metadata (sender, recipient, subject, date) and body content.
- **Sentiment Analysis**: Uses NLTK VADER to classify sentiment (Positive, Neutral, Negative).
- **Phishing Detection**: Scans for high-risk urgency indicators and suspicious URL counts.
- **Reporting**: Exports findings to `CSV` and `JSON` format.

## Setup & Run

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/email-analyzer.git](https://github.com/YOUR_USERNAME/email-analyzer.git)
   cd email-analyzer