# 🔐 QR Code Threat Intelligence Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-teal.svg)](https://fastapi.tiangolo.com)
[![HTML5](https://img.shields.io/badge/Frontend-HTML5-orange.svg)](index.html)

A **cybersecurity web platform** that scans QR codes using your device camera, decodes the embedded URL, and runs a full threat intelligence analysis — detecting phishing, malware, typosquatting, redirect chains, SSL issues, and more — before you ever open the link.

---

## 🚀 Live Demo

> Open `index.html` directly in any browser — no server needed for the frontend demo.
> For full backend analysis, run the FastAPI server (see [Backend Setup](#backend-setup)).

---

## ✨ Features

| Feature | Description |
|---|---|
| 📷 **QR Scanner** | Real-time camera scanning using `html5-qrcode` |
| 🔗 **Redirect Chain Detection** | Traces up to 5 redirect hops |
| 🔒 **SSL Certificate Validation** | Checks HTTPS, cert expiry, mismatches |
| 📅 **Domain Age Analysis** | WHOIS-based new-domain risk detection |
| 🌍 **GeoIP Lookup** | Server location and ASN analysis |
| 🎭 **Typosquatting Detection** | Brand impersonation pattern matching |
| 🛡️ **Threat Intelligence** | Checks phishing and malware databases |
| 📊 **Risk Score (0–100)** | Weighted multi-factor scoring engine |
| 📄 **Export Reports** | JSON report export for SIEM integration |
| 📋 **Scan History Dashboard** | Persistent history with statistics |

---

## 📁 Project Structure

```
qr-threat-analyzer/
├── index.html          # Frontend (single-page app, no build needed)
├── backend.py          # FastAPI backend server
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🖥️ Frontend Setup

The frontend is a **zero-dependency single HTML file**. Just open it:

```bash
# Option 1: Open directly
open index.html

# Option 2: Serve with Python
python -m http.server 3000
# Then visit http://localhost:3000
```

**Dependencies (loaded via CDN):**
- [`html5-qrcode`](https://github.com/mebjas/html5-qrcode) — camera QR scanning
- [Google Fonts](https://fonts.google.com) — Syne + Space Mono

---

## ⚙️ Backend Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the server

```bash
uvicorn backend:app --reload --host 0.0.0.0 --port 8000
```

### 3. API Docs

Visit **http://localhost:8000/docs** for interactive Swagger UI.

---

## 🔌 API Reference

### `POST /analyze`

Analyze a URL for security threats.

**Request:**
```json
{
  "url": "https://example.com",
  "deep_scan": false
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "score": 15,
  "risk_level": "safe",
  "checks": [
    {
      "name": "SSL Certificate",
      "value": "Valid",
      "detail": "Expires in 287 days",
      "status": "pass",
      "icon": "🔒"
    }
  ],
  "redirect_chain": ["https://example.com"],
  "tags": [],
  "timestamp": "2025-01-01T12:00:00",
  "summary": "SAFE: This URL appears legitimate. Risk score 15/100."
}
```

### `GET /health`
```json
{ "status": "ok", "timestamp": "..." }
```

---

## 🧪 Risk Score Logic

| Score Range | Risk Level | Meaning |
|---|---|---|
| 0 – 34 | ✅ Safe | No major threats |
| 35 – 69 | ⚠️ Suspicious | Proceed with caution |
| 70 – 100 | 🚨 Malicious | Do not open |

**Score is computed from:**
- No HTTPS: +25
- SSL issues: +10–25
- URL shortener / long redirect chain: +15
- New/suspicious domain: +15–30
- Typosquatting pattern: +35
- Raw IP address: +20
- Suspicious URL parameters: +20
- Known threat intelligence match: +25

---

## 🛣️ Development Roadmap

- [x] QR camera scanner
- [x] URL decoding
- [x] SSL certificate check
- [x] Redirect chain tracing
- [x] Typosquatting detection
- [x] Risk score engine
- [x] Scan history dashboard
- [x] JSON report export
- [ ] Real WHOIS API integration
- [ ] Real GeoIP database (MaxMind)
- [ ] VirusTotal API integration
- [ ] Google Safe Browsing API
- [ ] Database (PostgreSQL) for scan history
- [ ] User authentication
- [ ] Docker deployment
- [ ] CI/CD pipeline

---

## 🔧 Connect Real APIs

To upgrade from simulation to real threat intelligence, add these to `backend.py`:

| Service | What It Does | Free Tier |
|---|---|---|
| [VirusTotal](https://virustotal.com/gui/home/upload) | Malware/phishing scan | 4 req/min |
| [Google Safe Browsing](https://developers.google.com/safe-browsing) | Known bad URLs | 10k req/day |
| [WhoisXML API](https://whois.whoisxmlapi.com/) | Domain age | 500 req/month |
| [MaxMind GeoIP2](https://dev.maxmind.com/geoip/) | Server location | Free DB download |
| [URLScan.io](https://urlscan.io/docs/api/) | Full URL analysis | 100 req/hour |

---

## 🐳 Docker Deployment

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY backend.py .
EXPOSE 8000
CMD ["uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t qr-threat-analyzer .
docker run -p 8000:8000 qr-threat-analyzer
```

---

## 📖 How It Works

```
User scans QR code
       ↓
URL extracted from QR
       ↓
Frontend sends URL to /analyze
       ↓
Backend runs parallel checks:
  ├── SSL certificate validation
  ├── Redirect chain tracing
  ├── Domain pattern analysis
  ├── Typosquatting detection
  └── Threat intelligence lookup
       ↓
Risk score computed (0–100)
       ↓
Result displayed in dashboard
```

---

## 🛡️ Use Cases

- **Enterprise Security** — Check QR codes on physical materials before scanning
- **Banking & Finance** — Protect customers from QR phishing attacks
- **Education** — Teach safe QR code practices
- **Event Security** — Validate QR codes at registration/access points
- **Personal Safety** — Verify QR codes before entering credentials

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/real-whois-api`
3. Commit: `git commit -m 'Add real WHOIS integration'`
4. Push: `git push origin feature/real-whois-api`
5. Open a Pull Request

---

## ⚠️ Disclaimer

This tool is for **educational and defensive security purposes only**. The frontend demo uses simulated analysis. For production use, integrate real threat intelligence APIs. Never use this tool to access or test systems without authorization.

---

Made with ❤️ for cybersecurity awareness
