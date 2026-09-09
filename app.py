import json
import logging
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

from config import Config
from log_parser import parse_syslog, parse_json_log
from gemini_analyzer import analyze_log
from mitre_mapper import enrich_with_mitre

# Setup logging
logging.basicConfig(level=Config.LOG_LEVEL)
logger = logging.getLogger(__name__)

# Init Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = Config.DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CORS(app)

# Init DB
db = SQLAlchemy(app)

# ---------- Database Model ----------
class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45))
    user = db.Column(db.String(100))
    event_type = db.Column(db.String(100))
    raw_log = db.Column(db.Text)
    suspicious = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Integer, default=0)
    explanation = db.Column(db.Text)
    mitre_ids = db.Column(db.String(200))  # Stored as comma-separated
    response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "user": self.user,
            "event_type": self.event_type,
            "raw_log": self.raw_log,
            "suspicious": self.suspicious,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "mitre_ids": self.mitre_ids.split(',') if self.mitre_ids else [],
            "response": self.response,
            "created_at": self.created_at.isoformat()
        }

# Create tables (if using SQLite/Postgres)
with app.app_context():
    db.create_all()

# ---------- API Routes ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "Aegis Sentinel"})

@app.route("/analyze", methods=["POST"])
def analyze():
    """Accept log, run AI analysis, enrich with MITRE, store in DB, return result."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    # Parse based on input type
    if "raw" in data and isinstance(data["raw"], str):
        log_entry = parse_syslog(data["raw"])
    else:
        log_entry = parse_json_log(data)

    logger.info(f"Analyzing log: {log_entry}")

    # Run Gemini analysis
    analysis = analyze_log(log_entry)

    # Enrich with MITRE details
    enriched_analysis = enrich_with_mitre(analysis)

    # Store in database
    alert = Alert(
        timestamp=log_entry.get("timestamp"),
        source_ip=log_entry.get("source_ip"),
        user=log_entry.get("user"),
        event_type=log_entry.get("event_type"),
        raw_log=log_entry.get("raw"),
        suspicious=enriched_analysis.get("suspicious", False),
        confidence=enriched_analysis.get("confidence", 0),
        explanation=enriched_analysis.get("explanation", ""),
        mitre_ids=','.join(enriched_analysis.get("mitre_ids", [])),
        response=enriched_analysis.get("response", "")
    )
    db.session.add(alert)
    db.session.commit()

    # Build final result
    result = {
        "log": log_entry,
        "analysis": enriched_analysis,
        "alert_id": alert.id
    }

    if enriched_analysis.get("suspicious"):
        logger.warning(f"🚨 Suspicious activity detected (ID: {alert.id}): {enriched_analysis['explanation']}")

    return jsonify(result)

@app.route("/alerts", methods=["GET"])
def get_alerts():
    """Retrieve all stored alerts (for the dashboard)."""
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(100).all()
    return jsonify([a.to_dict() for a in alerts])

@app.route("/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    """Retrieve a single alert by ID."""
    alert = Alert.query.get(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert.to_dict())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
