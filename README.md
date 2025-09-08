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

Installation
1️⃣ Clone the Repository
git clone https://github.com/CYBERJERYSTON/Steganography-Tool-for-Image-File-Hiding.git
cd Steganography-Tool-for-Image-File-Hiding

2️⃣ Create a Virtual Environment
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # Linux/macOS

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Configure API Keys

Get free API keys:
VirusTotal API
AbuseIPDB API
Open app.py and replace:
VT_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"

5️⃣ Run MongoDB
Make sure MongoDB is running:
mongod

6️⃣ Run the App
python app.py


Now visit 👉 http://127.0.0.1:5000
