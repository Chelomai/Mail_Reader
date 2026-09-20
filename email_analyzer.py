import os
import re
import json
import email
from email import policy
from email.parser import BytesParser
import pandas as pd
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer

# Download required NLTK lexicon silently
nltk.download('vader_lexicon', quiet=True)

class EmailAnalyzer:
    """A tool to parse, analyze, and detect security indicators in email files."""

    # Keywords commonly associated with phishing or urgency
    SUSPICIOUS_KEYWORDS = [
        "urgent", "verify your account", "action required", "password reset",
        "wire transfer", "suspended", "security alert", "click here", "login immediately"
    ]

    def __init__(self):
        self.sia = SentimentIntensityAnalyzer()

    def parse_email(self, file_path: str) -> dict:
        """Parses an .eml file and extracts headers and body content."""
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        subject = msg.get('subject', '')
        sender = msg.get('from', '')
        recipient = msg.get('to', '')
        date = msg.get('date', '')

        # Extract body text
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))

                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    body = part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True).decode(msg.get_content_charset('utf-8'), errors='ignore')

        # Extract URLs from body
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)

        return {
            "filename": os.path.basename(file_path),
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "date": date,
            "body": body,
            "url_count": len(urls),
            "urls": urls
        }

    def analyze_sentiment(self, text: str) -> dict:
        """Calculates sentiment scores using NLTK VADER."""
        scores = self.sia.polarity_scores(text)
        compound = scores['compound']
        
        if compound >= 0.05:
            label = 'Positive'
        elif compound <= -0.05:
            label = 'Negative'
        else:
            label = 'Neutral'

        return {"compound": compound, "label": label}

    def detect_phishing_risks(self, email_data: dict) -> dict:
        """Analyzes email contents for basic security and spam indicators."""
        content = f"{email_data['subject']} {email_data['body']}".lower()
        matched_flags = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in content]

        # Basic SPF/DKIM presence check in headers (if passed raw headers)
        risk_score = len(matched_flags) * 2
        if email_data['url_count'] > 3:
            risk_score += 2

        risk_level = "High" if risk_score >= 4 else "Medium" if risk_score >= 2 else "Low"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "suspicious_flags": matched_flags
        }

    def process_folder(self, folder_path: str) -> list:
        """Processes all .eml files in a directory."""
        results = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.eml'):
                    full_path = os.path.join(root, file)
                    parsed = self.parse_email(full_path)
                    sentiment = self.analyze_sentiment(parsed['body'])
                    security = self.detect_phishing_risks(parsed)

                    combined = {
                        **parsed,
                        "sentiment": sentiment['label'],
                        "sentiment_score": sentiment['compound'],
                        "risk_level": security['risk_level'],
                        "flags_detected": ", ".join(security['suspicious_flags'])
                    }
                    # Remove raw body from table export for clean output
                    del combined['body']
                    results.append(combined)

        return results

if __name__ == "__main__":
    analyzer = EmailAnalyzer()
    sample_dir = "./sample_emails"

    if not os.path.exists(sample_dir):
        os.makedirs(sample_dir)
        print(f"Created '{sample_dir}' directory. Place your .eml files there to test.")
    else:
        print(f"Analyzing emails in '{sample_dir}'...")
        report_data = analyzer.process_folder(sample_dir)

        if report_data:
            df = pd.DataFrame(report_data)
            print("\n--- Analysis Summary ---")
            print(df[['filename', 'sender', 'sentiment', 'risk_level']].to_string(index=False))

            # Export reports
            df.to_csv("email_analysis_report.csv", index=False)
            with open("email_analysis_report.json", "w") as f:
                json.dump(report_data, f, indent=4)
            print("\nReports generated: email_analysis_report.csv and email_analysis_report.json")
        else:
            print("No .eml files found in the folder.")