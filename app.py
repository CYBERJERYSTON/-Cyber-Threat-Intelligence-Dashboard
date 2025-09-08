#!/usr/bin/env python3
"""
CTI Dashboard - Starter Flask app

Environment variables (recommended to set, or use a .env file):
- MONGO_URI       -> MongoDB connection string (default: mongodb://localhost:27017)
- MONGO_DBNAME    -> Database name (default: cti_db)
- VIRUSTOTAL_KEY  -> VirusTotal API key (optional)
- ABUSEIPDB_KEY   -> AbuseIPDB API key (optional)
"""

import os
import csv
import io
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from pymongo import MongoClient, ASCENDING
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DBNAME = os.environ.get("MONGO_DBNAME", "cti_db")
VT_KEY = os.environ.get("VIRUSTOTAL_KEY")       # put your VirusTotal API key here
ABUSE_KEY = os.environ.get("ABUSEIPDB_KEY")     # put your AbuseIPDB API key here

# --- Initialize Flask and MongoDB ---
app = Flask(__name__)
client = MongoClient(MONGO_URI)
db = client[MONGO_DBNAME]
threats = db.threats    # collection for IOC records
# create a basic index
threats.create_index([("ioc", ASCENDING)], unique=False)

# --- Utility / API wrappers ---

def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB check endpoint for an IP reputation.
    Returns parsed JSON dict or empty dict if unavailable.
    """
    if not ABUSE_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(entity: str) -> Dict[str, Any]:
    """
    Query VirusTotal for an IP or domain using the v3 API.
    Returns parsed JSON or error dict.
    Note: VT rate limits on free tiers; use sparingly.
    """
    if not VT_KEY:
        return {"error": "VirusTotal API key not configured"}
    headers = {"x-apikey": VT_KEY}
    # Decide endpoint: domains or ip_addresses
    if all(ch.isdigit() or ch=='.' for ch in entity):  # crude IP check
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{entity}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{entity}"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# --- Storage model helpers ---

def upsert_threat_record(ioc: str, source_data: Dict[str, Any], source: str):
    """
    Store or update an IOC record in MongoDB.
    Structure:
    {
        "ioc": "1.2.3.4" or "example.com",
        "first_seen": datetime,
        "last_seen": datetime,
        "sources": { "abuseipdb": {...}, "virustotal": {...} },
        "tags": ["phishing"],
    }
    """
    now = datetime.utcnow()
    rec = threats.find_one({"ioc": ioc})
    if not rec:
        rec = {
            "ioc": ioc,
            "first_seen": now,
            "created_at": now,
            "last_seen": now,
            "sources": {source: source_data},
            "tags": [],
        }
        threats.insert_one(rec)
    else:
        updates = {"last_seen": now, f"sources.{source}": source_data}
        threats.update_one({"_id": rec["_id"]}, {"$set": updates})

# --- Background job to refresh existing IOCs ---
def refresh_stored_iocs():
    """
    Refreshes the 'sources' data for IOCs stored in DB.
    This helps keep the dashboard 'near real-time' without hammering APIs.
    """
    print("[scheduler] refresh_stored_iocs running:", datetime.utcnow().isoformat())
    cutoff = datetime.utcnow() - timedelta(hours=1)   # refresh IOCs older than 1 hour
    cursor = threats.find({"last_seen": {"$lt": cutoff}}).limit(50)
    for rec in cursor:
        ioc = rec["ioc"]
        # Check both providers if keys present
        if ABUSE_KEY:
            a = check_abuseipdb(ioc)
            upsert_threat_record(ioc, a, "abuseipdb")
        if VT_KEY:
            v = check_virustotal(ioc)
            upsert_threat_record(ioc, v, "virustotal")
        # modest sleep to avoid bursting quotas
        time.sleep(1)

# start scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(refresh_stored_iocs, "interval", minutes=10, id="refresh_iocs", max_instances=1)
scheduler.start()

# --- Flask routes ---

@app.route("/")
def index():
    """
    Render main dashboard:
    - top malicious iocs (by recent reports)
    - trend: number of new IOCs per day (7 days)
    """
    # Top IOCs: we will consider presence in abnormal sources as severity — simple heuristic
    pipeline = [
        {"$project": {
            "ioc": 1,
            "tags": 1,
            "has_abuse": {"$cond": [{"$ifNull": ["$sources.abuseipdb", False]}, 1, 0]},
            "has_vt": {"$cond": [{"$ifNull": ["$sources.virustotal", False]}, 1, 0]},
            "last_seen": 1
        }},
        {"$sort": {"has_abuse": -1, "has_vt": -1, "last_seen": -1}},
        {"$limit": 20}
    ]
    top = list(threats.aggregate(pipeline))
    # trend (last 14 days)
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    days = []
    counts = []
    for i in range(13, -1, -1):
        d = today - timedelta(days=i)
        start = d
        end = d + timedelta(days=1)
        cnt = threats.count_documents({"created_at": {"$gte": start, "$lt": end}})
        days.append(d.strftime("%Y-%m-%d"))
        counts.append(cnt)
    return render_template("index.html", top=top, days=days, counts=counts)

@app.route("/lookup", methods=["POST"])
def lookup():
    """
    Lookup an IP or domain. Query local DB first; if not present or if 'force' requested,
    query external APIs and store the results.
    """
    data = request.form or request.json or {}
    ioc = (data.get("ioc") or "").strip()
    force = data.get("force", "false") in ("true", "1", True)
    if not ioc:
        return jsonify({"error": "no ioc provided"}), 400

    rec = threats.find_one({"ioc": ioc})
    if rec and not force:
        # return stored data
        result = rec
    else:
        result = {"ioc": ioc, "sources": {}, "fetched_at": datetime.utcnow().isoformat()}
        # AbuseIPDB
        if ABUSE_KEY:
            result["sources"]["abuseipdb"] = check_abuseipdb(ioc)
        # VirusTotal
        if VT_KEY:
            result["sources"]["virustotal"] = check_virustotal(ioc)
        # store/update
        upsert_threat_record(ioc, result["sources"].get("abuseipdb") or result["sources"].get("virustotal") or {}, "lookup")
        # read back stored doc
        rec = threats.find_one({"ioc": ioc})
        result = rec
    # convert datetimes to strings for JSON
    if result and isinstance(result, dict):
        result_out = dict(result)
        for k in ("first_seen", "last_seen", "created_at"):
            if k in result_out and isinstance(result_out[k], datetime):
                result_out[k] = result_out[k].isoformat()
        return jsonify({"result": result_out})
    return jsonify({"error": "unexpected error"}), 500

@app.route("/tag", methods=["POST"])
def tag():
    """
    Add or remove a tag for an IOC.
    payload: { "ioc": "1.2.3.4", "tag": "phishing", "action": "add"|"remove" }
    """
    d = request.json or request.form
    ioc = d.get("ioc")
    tag = d.get("tag")
    action = d.get("action", "add")
    if not ioc or not tag:
        return jsonify({"error": "ioc and tag required"}), 400
    if action == "add":
        threats.update_one({"ioc": ioc}, {"$addToSet": {"tags": tag}, "$set": {"last_seen": datetime.utcnow()}}, upsert=True)
    else:
        threats.update_one({"ioc": ioc}, {"$pull": {"tags": tag}})
    return jsonify({"ok": True})

@app.route("/export", methods=["GET"])
def export_csv():
    """
    Export current IOC records to CSV. Optional query param 'tag' to filter by tag.
    """
    tag = request.args.get("tag")
    query = {}
    if tag:
        query["tags"] = tag
    cursor = threats.find(query).sort("last_seen", -1)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ioc", "first_seen", "last_seen", "tags", "has_abuseipdb", "has_virustotal"])
    for rec in cursor:
        writer.writerow([
            rec.get("ioc"),
            rec.get("first_seen").isoformat() if rec.get("first_seen") else "",
            rec.get("last_seen").isoformat() if rec.get("last_seen") else "",
            ",".join(rec.get("tags") or []),
            "abuseipdb" in (rec.get("sources") or {}),
            "virustotal" in (rec.get("sources") or {})
        ])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv",
                     as_attachment=True, download_name="cti_export.csv")

# --- Simple convenience route for testing ---
@app.route("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# --- Shutdown scheduler when app stops (only works for non-production dev server) ---
import atexit
atexit.register(lambda: scheduler.shutdown(wait=False))

if __name__ == "__main__":
    # For development only; use gunicorn/uwsgi in production
    app.run(host="0.0.0.0", port=5000, debug=True)
