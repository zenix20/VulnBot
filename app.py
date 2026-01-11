from flask import Flask, request, jsonify, send_file, send_from_directory
import requests
import os
from dotenv import load_dotenv
from functools import lru_cache
from datetime import datetime
import json

# Initialize
load_dotenv()

app = Flask(__name__, template_folder='.')

# Route for index.html
@app.route('/')
def home():
    return send_file('index.html')

# Route for root files (like script.js in root)
@app.route('/<filename>')
def serve_root_files(filename):
    return send_from_directory('.', filename)

# Route for static files (style.css in static folder)
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# Config
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Cache NVD responses for 1 hour
@lru_cache(maxsize=100)
def fetch_nvd_data(cve_id: str):
    """Fetch raw CVE data from NVD API"""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        print(f"🌐 Making NVD API request for {cve_id}")
        response = requests.get(
            f"{NVD_API_URL}?cveId={cve_id}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"⚠️ NVD API Error for {cve_id}: {str(e)}")
        return None

def extract_cve_fields(nvd_data: dict):
    """Extract key fields from NVD response with proper error handling"""
    if not nvd_data or "vulnerabilities" not in nvd_data:
        return None

    vuln = nvd_data["vulnerabilities"][0]["cve"]
    # Add this to your extract_cve_fields function after the vuln = ... line
    print(f"🔍 Available keys in CVE data: {list(vuln.keys())}")
    if "cisaExploitAdd" in vuln:
        print(f"📋 CISA Exploit Added: {vuln['cisaExploitAdd']}")
    if "cisaActionDue" in vuln:
        print(f"📋 CISA Action Due: {vuln['cisaActionDue']}")
    
    # Initialize with default values that match frontend expectations
    result = {
        "id": vuln["id"],
        "cvssScore": 0.0,
        "severity": "UNKNOWN",
        "attackVector": "N/A",
        "exploitability": "Unknown",
        "affectedProducts": ["Unknown"],
        "description": "No description available",
        "privilegesRequired": "N/A",
        "userInteraction": "N/A",
        "confidentialityImpact": "N/A",
        "integrityImpact": "N/A",
        "availabilityImpact": "N/A",
        "sourceIdentifier": "Unknown",
        "published": "Unknown",
        "lastModified": "Unknown",
        "vulnStatus": "Unknown",
        "vector": "N/A",
    }
    
    # Get description
    result["description"] = next((desc["value"] for desc in vuln.get("descriptions", []) 
                              if desc["lang"] == "en"), "No description available")

    # Get CVSS metrics (prioritize V3)
    metrics = vuln.get("metrics", {})
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            cvss = metrics[version][0]["cvssData"]
            result.update({
                "cvssScore": cvss["baseScore"],
                "severity": cvss.get("baseSeverity", "HIGH" if cvss["baseScore"] >= 7.0 else "MEDIUM"),
                "vector": cvss["vectorString"],
                "attackVector": cvss.get("attackVector", "N/A"),
                "privilegesRequired": cvss.get("privilegesRequired", "N/A"),
                "userInteraction": cvss.get("userInteraction", "N/A"),
                "confidentialityImpact": cvss.get("confidentialityImpact", "N/A"),
                "integrityImpact": cvss.get("integrityImpact", "N/A"),
                "availabilityImpact": cvss.get("availabilityImpact", "N/A")
            })
            break

    # Set exploitability based on score
    result["exploitability"] = "High" if result["cvssScore"] >= 7.0 else "Medium"

    # Extract affected products
    products = set()
    for node in vuln.get("configurations", []):
        for match in node.get("nodes", []):
            for cpe_match in match.get("cpeMatch", []):
                if isinstance(cpe_match, dict) and cpe_match.get("vulnerable"):
                    criteria = cpe_match.get("criteria", "")
                    if isinstance(criteria, str) and criteria.startswith("cpe:2.3:o:"):
                        try:
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                products.add(parts[4])
                        except (IndexError, AttributeError):
                            continue
    if products:
        result["affectedProducts"] = list(products)

    # Handle dates
    for date_field in ["published", "lastModified"]:
        if date_field in vuln:
            try:
                dt = datetime.strptime(vuln[date_field], "%Y-%m-%dT%H:%M:%S.%f")
                result[date_field] = dt.strftime("%Y-%m-%d")
            except ValueError:
                result[date_field] = vuln[date_field].split("T")[0]

    # Handle other metadata
    for field in ["vulnStatus", "sourceIdentifier"]:
        if field in vuln:
            result[field] = vuln[field]

    # Handle CISA metadata - this is the key fix!
    # CISA data is typically in the 'cisaExploitAdd' and related fields at the root level
    cisa_fields = ["cisaExploitAdd", "cisaActionDue", "cisaRequiredAction", "cisaVulnerabilityName"]
    for field in cisa_fields:
        if field in vuln:
            result[field] = vuln[field]
        else:
            # Only set to N/A if the field doesn't exist
            result[field] = "N/A"
    return result
    
def generate_simple_explanation(cve_data: dict):
    """
    Generate simple explanation using Groq API (free and reliable)
    """
    try:
        # First try Groq API (more reliable)
        groq_result = try_groq_api(cve_data)
        if groq_result:
            return groq_result
        
        # If Groq fails, try Hugging Face
        hf_result = try_hugging_face(cve_data)
        if hf_result:
            return hf_result
        
        # Final fallback
        return generate_enhanced_fallback(cve_data)
        
    except Exception as e:
        print(f"⚠️ Error in explanation generation: {str(e)}")
        return generate_enhanced_fallback(cve_data)

def try_groq_api(cve_data):
    """Try Groq API which is free and reliable"""
    try:
        GROQ_API_KEY = os.getenv('GROQ_API_KEY', '').strip()
        
        if not GROQ_API_KEY:
            print("⚠️ GROQ_API_KEY not set, skipping Groq API")
            return None
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}"
        }
        
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {
                        "role": "system", 
                        "content": "You are a cybersecurity expert who explains technical vulnerabilities in simple, easy-to-understand language for non-technical people. Use relatable analogies."
                    },
                    {
                        "role": "user",
                        "content": f"""
                            Explain this cybersecurity vulnerability in simple, non-technical terms with a relatable analogy:

                            CVE ID: {cve_data['id']}
                            Description: {cve_data['description'][:400]}
                            Severity: {cve_data.get('severity', 'Unknown')}
                            CVSS Score: {cve_data.get('cvssScore', 'Unknown')}
                            Attack Vector: {cve_data['attackVector']}

                            Please provide:
                            1. A simple explanation that a non-technical person can understand
                            2. A relatable analogy (like "it's like leaving your front door unlocked")
                            3. Basic implications of the vulnerability
                            4. Keep it under 200 words and very concise
                            5. Keep it in the form of one single paragraph. Don't add any individual headings.
                            """
                    }
                ],
                "max_tokens": 500,
                "temperature": 0.7
            },
            timeout=8
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Groq API succeeded")
            return result['choices'][0]['message']['content']
        else:
            print(f"Groq API returned status {response.status_code}: {response.text[:200]}")
            return None
            
    except Exception as e:
        print(f"Groq API error: {str(e)}")
    
    return None

def try_hugging_face(cve_data):
    """Try Hugging Face API as backup"""
    try:
        HF_API_KEY = os.getenv('HF_API_KEY', '').strip()
        
        if not HF_API_KEY:
            print("HF_API_KEY not set, skipping Hugging Face API")
            return None
        
        # Try Hugging Face Inference API with router endpoint
        API_URL = "https://router.huggingface.co/v1/text-generation"
        headers = {"Authorization": f"Bearer {HF_API_KEY}", "Content-Type": "application/json"}
        
        prompt = f"""Explain this cybersecurity vulnerability in simple, non-technical terms with a relatable analogy:

CVE ID: {cve_data['id']}
Description: {cve_data['description'][:400]}
Severity: {cve_data.get('severity', 'Unknown')}
CVSS Score: {cve_data.get('cvssScore', 'Unknown')}
Attack Vector: {cve_data['attackVector']}

Please provide:
1. A simple explanation that a non-technical person can understand
2. A relatable analogy (like "it's like leaving your front door unlocked")
3. Basic implications of the vulnerability
4. Keep it under 200 words and very concise
5. Keep it in the form of one single paragraph. Don't add any individual headings."""
        
        response = requests.post(
            API_URL,
            headers=headers,
            json={
                "model": "mistralai/Mistral-7B-Instruct-v0.3",
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": 300,
                    "temperature": 0.7
                }
            },
            timeout=8
        )
        
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list) and len(result) > 0:
                print(f"✅ Hugging Face API succeeded")
                generated_text = result[0].get('generated_text', '')
                # Extract only the generated part (remove the prompt)
                if generated_text.startswith(prompt):
                    generated_text = generated_text[len(prompt):].strip()
                return generated_text
        else:
            print(f"⚠️ Hugging Face API returned status {response.status_code}: {response.text[:200]}")
                
    except Exception as e:
        print(f"Hugging Face error: {str(e)}")
    
    return None

def generate_enhanced_fallback(cve_data: dict):
    """Enhanced fallback explanation when AI is not available"""
    description = cve_data['description']
    severity = cve_data.get('severity', 'UNKNOWN').lower()
    cvss_score = cve_data.get('cvssScore', 0)
    
    # Simple analogies based on severity and CVSS score
    if cvss_score >= 9.0:
        analogy = "This is critically dangerous - like leaving a bank vault wide open with security asleep. Attackers can easily cause massive damage."
    elif cvss_score >= 7.0:
        analogy = "This is highly dangerous - like forgetting to lock your front door. Remote attackers could exploit this easily."
    elif cvss_score >= 4.0:
        analogy = "This is moderately dangerous - like having a weak lock that could be picked with the right tools."
    else:
        analogy = "This is a low-risk issue that would require very specific conditions to be exploited."
    
    # Get the main description
    sentences = description.split('.')
    main_description = sentences[0] + '.' if len(sentences) > 0 else description
    if len(main_description) < 30 and len(sentences) > 1:
        main_description = sentences[0] + '.' + sentences[1] + '.'
    
    return f"{main_description} {analogy} Rated as {severity} severity ({cvss_score}/10 CVSS score)."
    
@app.route('/api/analyze', methods=['POST'])
def analyze_cve():
    data = request.get_json()
    cve_id = data.get("cve_id", "").strip().upper()
    
    # Validate CVE format
    if not cve_id.startswith("CVE-") or len(cve_id.split("-")) != 3:
        return jsonify({"error": "Invalid CVE ID format (use CVE-YYYY-XXXXX)"}), 400
    
    print(f"\n🔍 Fetching data for {cve_id}...")
    
    # Step 1: Fetch from NVD
    nvd_response = fetch_nvd_data(cve_id)

    print("📄 Full NVD response structure:")
    print(json.dumps(nvd_response, indent=2)[:1000])  # First 1000 chars

    if not nvd_response or not nvd_response.get("vulnerabilities"):
        print(f"❌ No data found for {cve_id}")
        return jsonify({"error": "CVE not found in NVD"}), 404
    
    print("✅ NVD Data Received")
    
    # Step 2: Extract fields
    cve_data = extract_cve_fields(nvd_response)
    if not cve_data:
        return jsonify({"error": "Failed to extract CVE data"}), 500
    print("📊 Extracted Fields")
    
    # Step 3: Generate simple explanation
    print("🧠 Generating simple explanation...")
    simple_explanation = generate_simple_explanation(cve_data)
    
    print("🚀 Sending response")
    return jsonify({
        "metadata": cve_data,  # Send all extracted fields directly
        "analysis": {
            "simple": simple_explanation
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)