A real-time cyber threat intelligence dashboard that integrates with AbuseIPDB and VirusTotal APIs to analyze and monitor IP addresses/domains.
The dashboard stores results in MongoDB and provides an interactive web interface for threat lookup and monitoring.

**Features
 IOC Lookup – Search IPs/domains and fetch intelligence.
 Threat Scoring – AbuseIPDB confidence score + VirusTotal analysis.
 Detailed Insights – View per-engine VirusTotal detections.
 Database Support – All lookups stored in MongoDB.
 Dashboard View – Latest 20 lookups with timestamp.
 Timestamped Results – Accurate UTC timestamps.
 Tagging Support – Tags for organizing IOCs (future).
 Export Support – Export threat data (future).

🛠️ Tech Stack
Backend: Flask (Python)
Database: MongoDB
APIs: AbuseIPDB, VirusTotal
Frontend: HTML, Bootstrap, Jinja2
Visualization: Chart.js (future extension)
