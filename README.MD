# VulnBot - CVE Explainer

<div align="center">

![VulnBot Logo](https://img.shields.io/badge/VulnBot-CVE_Explainer-7a9f79?style=flat-square&logo=security)
![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-Latest-000000?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**VulnBot is an intelligent CVE (Common Vulnerabilities and Exposures) analysis tool that transforms complex security vulnerability data into simple, understandable explanations for non-technical users.**

[Features](#features) • [Getting Started](#getting-started) • [Configuration](#configuration) • [Usage](#usage) • [API](#api) • [Architecture](#architecture)

</div>

---

## Overview

VulnBot combines data from the **National Vulnerability Database (NVD)** with AI-powered analysis to provide:
- **Simplified explanations** of complex security vulnerabilities
- **Detailed CVE metadata** including CVSS scores, severity ratings, and impact assessments
- **Real-world analogies** to help non-technical users understand risks
- **PDF exports** for reports and documentation
- **Multi-AI fallback system** for reliability (Groq → Hugging Face → Fallback)

Whether you're a security professional, IT administrator, or curious learner, VulnBot makes cybersecurity vulnerabilities accessible to everyone.

---

## Features

### 🔍 Core Features

- **CVE Search & Analysis**: Query any CVE using the CVE ID format (e.g., `CVE-2024-3400`)
- **NVD Integration**: Real-time data from NIST's National Vulnerability Database
- **AI-Powered Explanations**: Uses Groq and Hugging Face APIs to generate human-readable summaries
- **Comprehensive Metadata**:
  - CVSS Scores and Severity Ratings
  - Attack Vectors and Privilege Requirements
  - Impact Assessment (Confidentiality, Integrity, Availability)
  - Affected Products
  - Publication and Modification Dates
  - CISA Exploitation Status

### 🎨 User Experience

- **Modern Web Interface**: Clean, responsive dark-themed UI built with Tailwind CSS
- **Real-time Chat Interface**: Intuitive conversation-like experience
- **PDF Export**: Generate professional reports of vulnerability analyses
- **Code Highlighting**: Syntax-highlighted technical information
- **Copy Functionality**: Easy copying of vulnerability details
- **Responsive Design**: Works seamlessly on desktop and mobile devices

### 🤖 AI Backends

VulnBot implements an intelligent fallback system:

1. **Groq API** (Primary): Fast, free, uses `llama-3.3-70b-versatile` model
2. **Hugging Face API** (Secondary): Alternative using `mistralai/Mistral-7B-Instruct-v0.3`
3. **Enhanced Fallback**: Smart rule-based explanations when APIs are unavailable

---

## Getting Started

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- **API Keys** (see [Configuration](#configuration)):
  - GROQ_API_KEY (free at https://console.groq.com/)
  - HF_API_KEY (free at https://huggingface.co/settings/tokens)
  - NVD_API_KEY (optional, free at https://nvd.nist.gov/developers/request-an-api-key)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/VulnBot.git
cd VulnBot
```

2. **Create a virtual environment** (recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install flask requests python-dotenv
```

4. **Configure environment variables** (see [Configuration](#configuration))
```bash
# Create .env file in project root
echo NVD_API_KEY=your_key_here >> .env
echo GROQ_API_KEY=your_key_here >> .env
echo HF_API_KEY=your_key_here >> .env
```

5. **Run the application**
```bash
python app.py
```

6. **Open in browser**
```
http://127.0.0.1:8000
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root directory:

```env
# NIST NVD API Key (Optional - needed for higher rate limits)
NVD_API_KEY=your_nvd_api_key_here

# Groq API Key (Get free at https://console.groq.com/)
GROQ_API_KEY=your_groq_api_key_here

# Hugging Face API Key (Get free at https://huggingface.co/settings/tokens)
HF_API_KEY=your_huggingface_api_key_here
```

### Getting API Keys

#### Groq API (Free)
1. Visit https://console.groq.com/
2. Sign up for a free account
3. Go to API Keys section
4. Create a new API key
5. Copy the key to your `.env` file

#### Hugging Face API (Free)
1. Visit https://huggingface.co/
2. Create an account or log in
3. Go to Settings → Access Tokens
4. Create a new token with `read` access
5. Copy the token to your `.env` file

#### NVD API Key (Optional)
1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the request form
3. Check your email for the API key
4. Add to `.env` for higher rate limits

---

## Usage

### Web Interface

1. **Navigate to the application**: Open `http://127.0.0.1:8000` in your browser
2. **Enter a CVE ID**: Type a CVE ID like `CVE-2024-3400` in the input field
3. **View Results**: Get a detailed analysis including:
   - Simple explanation with real-world analogy
   - CVSS metrics and severity
   - Attack vector information
   - Impact assessment
   - Affected products
   - Publication details

### Example CVE IDs

- `CVE-2024-3400` - Palo Alto Networks GlobalProtect vulnerability
- `CVE-2023-44487` - HTTP/2 Rapid Reset vulnerability
- `CVE-2023-38545` - curl vulnerability
- `CVE-2024-1234` - Any recent CVE

### Features in Action

#### 📋 Analyze Vulnerability
```
User: CVE-2024-3400
VulnBot: [Shows detailed analysis with AI-generated explanation]
```

#### 📥 Export 
Click the "Download" button to save the analysis as a professional report.

#### 📋 Copy Details
Click the copy button on any section to copy details to your clipboard.

---

## API

### Endpoints

#### POST `/api/analyze`

Analyzes a CVE and returns comprehensive vulnerability data.

**Request:**
```json
{
  "cve_id": "CVE-2024-3400"
}
```

**Response:**
```json
{
  "metadata": {
    "id": "CVE-2024-3400",
    "cvssScore": 9.8,
    "severity": "CRITICAL",
    "attackVector": "NETWORK",
    "exploitability": "High",
    "affectedProducts": ["PAN-OS"],
    "description": "A command injection vulnerability...",
    "privilegesRequired": "NONE",
    "userInteraction": "NONE",
    "confidentialityImpact": "HIGH",
    "integrityImpact": "HIGH",
    "availabilityImpact": "HIGH",
    "sourceIdentifier": "psirt@paloaltonetworks.com",
    "published": "2024-04-12",
    "lastModified": "2025-11-04",
    "vulnStatus": "Analyzed",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cisaExploitAdd": "2024-04-12",
    "cisaActionDue": "2024-04-19",
    "cisaRequiredAction": "Apply updates",
    "cisaVulnerabilityName": "PAN-OS GlobalProtect RCE"
  },
  "analysis": {
    "simple": "This vulnerability is like leaving a bank vault door wide open. Remote attackers can inject commands to execute arbitrary code with root privileges without any authentication..."
  }
}
```

**Error Response:**
```json
{
  "error": "CVE not found in NVD"
}
```

---

## Architecture

### Technology Stack

```
Frontend
├── HTML5
├── Tailwind CSS (UI Framework)
├── JavaScript (ES6+)
├── jsPDF + html2canvas (PDF Export)
└── Responsive Design

Backend
├── Python 3.8+
├── Flask (Web Framework)
├── Requests (HTTP Client)
├── python-dotenv (Config Management)
└── functools.lru_cache (Response Caching)

External APIs
├── NIST NVD API (CVE Data)
├── Groq API (AI Explanations - Primary)
└── Hugging Face API (AI Explanations - Fallback)
```

### Request Flow

```
User Input (CVE ID)
        ↓
Frontend (JavaScript)
        ↓
Flask Backend
        ↓
NVD API Request → Parse & Extract Data
        ↓
Generate Explanation
├── Try Groq API (Primary)
├── Try Hugging Face (Fallback)
└── Use Rule-Based Fallback
        ↓
Frontend Display + Cache
```

### Data Processing Pipeline

```
NVD JSON Response
        ↓
extract_cve_fields()
├── Extract CVE Metadata
├── Parse CVSS Metrics (V3.1, V3.0, V2)
├── Extract Affected Products
├── Parse Attack Vector Info
└── Handle CISA Metadata
        ↓
AI Explanation Generation
├── Format prompt for AI model
├── Call Groq/Hugging Face/Fallback
└── Return explanation
        ↓
JSON Response to Frontend
```

---

## Features in Detail

### CVSS Metrics

VulnBot extracts and displays CVSS v3.1 metrics including:
- **Base Score**: Overall severity rating (0-10)
- **Attack Vector**: Network, Adjacent Network, Local, Physical
- **Attack Complexity**: Low, High
- **Privileges Required**: None, Low, High
- **User Interaction**: None, Required
- **Impact Metrics**: Confidentiality, Integrity, Availability (None, Low, High)

### Severity Classification

```
CVSS Score Range → Severity
9.0 - 10.0     → CRITICAL
7.0 - 8.9      → HIGH
4.0 - 6.9      → MEDIUM
0.1 - 3.9      → LOW
0.0            → NONE
```

### CISA KEV Tracking

VulnBot displays CISA Known Exploited Vulnerabilities data when available:
- **Exploit Add Date**: When CISA was notified of active exploitation
- **Action Due Date**: Deadline for patching
- **Required Action**: Steps organizations should take
- **Vulnerability Name**: CISA's assigned name

### Caching

The application implements LRU caching for NVD requests to:
- Reduce API calls
- Improve response time
- Respect API rate limits

Cache size: 100 CVEs, ~1 hour duration

---

## Troubleshooting

### Common Issues

#### 🔴 "API Key not set" Error

**Problem**: Getting warnings that API keys aren't configured

**Solution**:
```bash
# Verify .env file exists
ls .env  # or dir .env on Windows

# Check that keys are properly formatted
cat .env

# Make sure .env is in the project root directory
# Not in a subdirectory
```

#### 🔴 "CVE not found in NVD"

**Problem**: Valid CVE IDs returning not found

**Solution**:
- Check CVE ID format: `CVE-YYYY-XXXXX`
- Ensure you're using hyphens, not underscores
- Verify the CVE ID exists on https://nvd.nist.gov/
- Try a different CVE ID to verify API connectivity

#### 🔴 API Timeouts

**Problem**: Requests timing out

**Solution**:
- Check internet connection
- Verify API endpoints are accessible (ping them)
- Try with different CVE ID
- Check API service status pages

#### 🔴 Port Already in Use

**Problem**: `Address already in use` error

**Solution**:
```bash
# Find process using port 8000
lsof -i :8000  # macOS/Linux

# Kill the process
kill -9 <PID>

# Or use a different port
python app.py --port 8001
```

### Debugging

Enable verbose logging:
```python
# In app.py, the application already logs:
# - NVD API requests
# - API key status
# - CVE data extraction details
# - AI API responses and errors
```

Check the console output for detailed error messages.

---

## Performance

### Response Times

- **NVD API Call**: ~1-2 seconds
- **Groq AI Generation**: ~2-3 seconds
- **Hugging Face AI Generation**: ~3-4 seconds
- **Total Response**: ~3-6 seconds (cached: <100ms)


## Development

### Project Structure

```
VulnBot/
├── app.py                 # Flask backend
├── index.html            # Web interface
├── script.js             # Frontend JavaScript
├── static/
│   └── style.css         # Additional styles
├── requirements.txt      # Python dependencies (empty - install manually)
├── .env                  # Configuration (not in repo)
├── .gitignore           # Git ignore file
└── README.md            # This file
```

### Running in Development Mode

```bash
# Enable debug mode
export FLASK_ENV=development  # or set FLASK_ENV=development on Windows
python app.py
```

## Contributing

Contributions are welcome! 

## Limitations

- **Rate Limiting**: NVD API has rate limits (higher with API key)
- **Historical Data**: Only recent CVEs have complete CVSS v3 data
- **AI Latency**: First response may take 2-3 seconds while AI generates explanation
- **Offline Mode**: Requires internet connection for NVD and AI APIs
- **CVE Coverage**: Limited to CVEs in NIST NVD database


<div align="center">

**Made with ❤️ for cybersecurity education and awareness**

[⬆ Back to Top](#vulnbot---cve-explainer)

</div>
