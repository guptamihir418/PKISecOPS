#!/usr/bin/env python3
"""
================================================================================
inference.py

Loads your fine-tuned QLoRA adapter on top of Mistral-7B,
and runs an interactive Q&A loop on X.509 certificate flaws.

The script can analyze certificates and identify security flaws based on your
fine-tuned model. It supports loading certificates from the command line or
from JSON files in the project structure.

Usage:
  - Enter a question followed by 'context' and then the certificate
  - Example: "List all security flaws found in this certificate." context-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
  - Or use built-in certificate analysis with: "analyze"

Author: Mihir Gupta, 2025
For AI Certificate Service POC (PKISecOPS project)
================================================================================
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
import torch
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime

# =================================================================================
# Config
# =================================================================================
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"
ADAPTER_DIR = "../model_weights/"
MAX_NEW_TOKENS = 512

# Certificate flaws for the POC
CERT_FLAWS = {
    "expired": "The certificate has expired or is not yet valid",
    "sha1_signature": "The certificate uses the SHA-1 signature algorithm which is considered weak",
    "low_entropy_serial": "The certificate has low entropy in its serial number (weak randomness)",
    "short_key": "The certificate uses a key shorter than recommended (less than 2048 bits for RSA)",
    "missing_SAN": "The certificate is missing Subject Alternative Names (SAN) extension"
}

# =================================================================================
# Load tokenizer & model
# =================================================================================
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4"
)

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
tokenizer.pad_token = tokenizer.eos_token

# Load base model with quantization
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto"
)

# Load your fine-tuned QLoRA adapter
model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
model.eval()

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"✅ Model loaded on {device.upper()}")

# =================================================================================
# Helper functions
# =================================================================================
def extract_certificate(text):
    """Extract a PEM certificate from text"""
    cert_pattern = r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'
    match = re.search(cert_pattern, text)
    if match:
        return match.group(0)
    return None

def load_cert_from_json(cert_id=None):
    """Load a certificate from the JSON files in the project"""
    # Navigate up to project root
    project_root = Path(__file__).parent.parent.parent
    
    # Look in synthetic directory for certificate files
    cert_dirs = list(project_root.glob('synthetic/*_flaws'))
    
    if not cert_id:
        # If no specific cert requested, just get the first one
        for cert_dir in cert_dirs:
            json_files = list(cert_dir.glob('*.json'))
            if json_files:
                with open(json_files[0], 'r') as f:
                    try:
                        cert_data = json.load(f)
                        if 'pem' in cert_data:
                            return cert_data['pem'], cert_data.get('flaws', [])
                    except json.JSONDecodeError:
                        continue
    else:
        # Look for a specific certificate by ID/hash
        for cert_dir in cert_dirs:
            cert_file = cert_dir / f"{cert_id}.json"
            if cert_file.exists():
                with open(cert_file, 'r') as f:
                    try:
                        cert_data = json.load(f)
                        return cert_data['pem'], cert_data.get('flaws', [])
                    except (json.JSONDecodeError, KeyError):
                        pass
    
    return None, []

# =================================================================================
# Certificate analysis functions
# =================================================================================
def analyze_certificate(cert_pem):
    """Perform rule-based analysis on the certificate focusing on the 5 POC flaws"""
    import re
    from datetime import datetime
    import subprocess
    import tempfile
    import binascii
    import random
    
    results = {
        "critical_issues": [],
        "security_concerns": [],
        "best_practice_violations": [],
        "informational": []
    }
    
    # 1. Check for SHA-1 signature
    if "SHA1" in cert_pem or "SHA-1" in cert_pem or "sha1With" in cert_pem:
        results["security_concerns"].append(CERT_FLAWS["sha1_signature"])
    
    # 2. Check for short key (basic pattern matching)
    if "1024" in cert_pem:
        results["security_concerns"].append(CERT_FLAWS["short_key"])
    
    # 3. Check expiration (pattern matching for dates)
    # Look for validity dates in the certificate
    not_before_pattern = r'NotBefore:\s*(\w+\s+\d+\s+\d+:\d+:\d+\s+\d{4})'
    not_after_pattern = r'NotAfter\s*:\s*(\w+\s+\d+\s+\d+:\d+:\d+\s+\d{4})'
    
    # Alternative pattern for binary format dates
    expiry_pattern = r'Fw0[\w]{6}(\d{4})\d{4}Z'
    
    # Check for expired certificate
    current_date = datetime.now()
    expired = False
    
    # Try to find expiration date in text format
    expiry_match = re.search(expiry_pattern, cert_pem)
    if expiry_match:
        expiry_year = int(expiry_match.group(1))
        if expiry_year < current_date.year:
            results["critical_issues"].append(CERT_FLAWS["expired"] + f" (expired in {expiry_year})")
            expired = True
    
    # 4. Check for serial number patterns (for low entropy)
    serial_pattern = r'SerialNumber:\s*([0-9a-fA-F:]+)'
    serial_match = re.search(serial_pattern, cert_pem)
    
    if serial_match:
        serial = serial_match.group(1).replace(':', '')
        # Check for low entropy patterns like sequential numbers, repeating digits
        if len(set(serial)) < 5 or serial.count(serial[0]) > len(serial) * 0.5:
            results["security_concerns"].append(CERT_FLAWS["low_entropy_serial"])
    else:
        # If we can't find the serial, look for other patterns that might indicate low entropy
        if "00:00:00" in cert_pem or "11:11:11" in cert_pem or "aa:aa:aa" in cert_pem:
            results["security_concerns"].append(CERT_FLAWS["low_entropy_serial"] + " (detected repeating patterns)")
    
    # Try using OpenSSL for more detailed analysis if available
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
            temp.write(cert_pem)
            temp_path = temp.name
        
        # Run OpenSSL to get certificate details
        openssl_output = subprocess.check_output(
            ["openssl", "x509", "-in", temp_path, "-text", "-noout"],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Check for SAN extension
        if "subject alternative name" not in openssl_output.lower() and "x509v3 subject alternative name" not in openssl_output.lower():
            results["best_practice_violations"].append(CERT_FLAWS["missing_SAN"])
        
        # Check for short key more precisely
        key_size_match = re.search(r'(RSA|DSA|EC)\s+Public(-|\s)Key:\s*\((\d+)\s*bit\)', openssl_output)
        if key_size_match:
            key_type = key_size_match.group(1)
            key_size = int(key_size_match.group(3))
            
            if (key_type == "RSA" and key_size < 2048) or (key_type == "EC" and key_size < 256):
                results["security_concerns"].append(CERT_FLAWS["short_key"] + f" ({key_size} bits)")
        
        # Check for signature algorithm
        if "sha1With" in openssl_output or "sha1with" in openssl_output or "SHA1" in openssl_output:
            results["security_concerns"].append(CERT_FLAWS["sha1_signature"])
        
        # Check for expiration if we didn't detect it earlier
        if not expired:
            not_after_match = re.search(r'Not After\s*:\s*(.*?)\n', openssl_output)
            if not_after_match:
                try:
                    import dateutil.parser
                    expiry_date = dateutil.parser.parse(not_after_match.group(1))
                    if expiry_date < current_date:
                        results["critical_issues"].append(CERT_FLAWS["expired"] + f" (expired on {expiry_date.strftime('%Y-%m-%d')})")
                except (ImportError, ValueError):
                    # If dateutil is not available or date parsing fails, use basic check
                    if "Jan 2020" in openssl_output or "Feb 2020" in openssl_output:
                        results["critical_issues"].append(CERT_FLAWS["expired"] + " (detected 2020 or earlier expiry date)")
        
        # Clean up temp file
        import os
        os.unlink(temp_path)
        
    except (subprocess.SubprocessError, FileNotFoundError):
        # OpenSSL not available or error occurred
        results["informational"].append("Limited analysis - OpenSSL not available or error occurred")
        
        # Fallback checks if OpenSSL failed
        if not any(CERT_FLAWS["missing_SAN"] in issue for issues in results.values() for issue in issues):
            # Check for SAN with basic pattern matching
            if "subjectAltName" not in cert_pem and "Subject Alternative Name" not in cert_pem:
                results["best_practice_violations"].append(CERT_FLAWS["missing_SAN"] + " (basic check)")
    
    # If no issues found in any category
    all_empty = all(len(issues) == 0 for issues in results.values())
    if all_empty:
        results["informational"].append("No obvious security issues detected with basic analysis")
        results["informational"].append("Consider using specialized tools for thorough certificate validation")
    
    return results

# =================================================================================
# Interactive loop
# =================================================================================
def main():
    print("\n✅ QLoRA Cert Inspector Ready! Type 'exit' to quit.")
    print("Commands:")
    print("  - 'exit' or 'quit': Exit the program")
    print("  - 'load <cert_id>': Load a certificate from JSON files")
    print("  - 'analyze': Run built-in certificate analysis")
    print("  - Or enter a question about certificate flaws")
    print("\nTo analyze a certificate, use the format:")
    print('"Your question" context-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----')

    # Default certificate
    cert_context = """
    -----BEGIN CERTIFICATE-----
    MIIDWjCCAsOgAwIBAgIUL1M/vYxrrfKIeeVyePEBEThvDsUwDQYJKoZIhvcNAQEF
    ...
    -----END CERTIFICATE-----
    """

    known_flaws = []

    while True:
        try:
            user_input = input("\nEnter your question (about cert flaws): ").strip()
            
            # Handle exit commands
            if user_input.lower() in ["exit", "quit"]:
                break
            
            # Handle load command
            if user_input.lower().startswith("load "):
                cert_id = user_input[5:].strip()
                loaded_cert, loaded_flaws = load_cert_from_json(cert_id)
                if loaded_cert:
                    cert_context = loaded_cert
                    known_flaws = loaded_flaws
                    print(f"✅ Loaded certificate {cert_id}")
                    if known_flaws:
                        print(f"Known flaws: {', '.join(known_flaws)}")
                    continue
                else:
                    print(f"❌ Certificate {cert_id} not found")
                    continue
            
            # Process the input to extract question and certificate
            if "context" in user_input and "-----BEGIN CERTIFICATE-----" in user_input:
                try:
                    # Split only on the first occurrence of 'context'
                    question_part, cert_part = user_input.split("context", 1)
                    
                    # Clean up the question
                    question = question_part.strip()
                    if question.startswith('"') and question.endswith('"'):
                        question = question[1:-1].strip()
                        
                    # Extract the certificate
                    cert_pattern = r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'
                    cert_match = re.search(cert_pattern, cert_part)
                    
                    if cert_match:
                        cert_context = cert_match.group(0)
                except Exception as e:
                    print(f"\n⚠️ Error processing input: {e}")
                    continue
            else:
                # Just a question without a new certificate
                question = user_input.strip()
                if question.startswith('"') and question.endswith('"'):
                    question = question[1:-1].strip()
            
            # Handle special commands
            if question.lower() == "analyze":
                print("\n🔍 Running comprehensive certificate analysis...")
                analysis_results = analyze_certificate(cert_context)
                for category, issues in analysis_results.items():
                    if issues:
                        print(f"\n{category.upper()}:")
                        for issue in issues:
                            print(f" - {issue}")
                continue
            
            # Format the prompt for the model - ensure the certificate is properly formatted
            # Clean up any extra whitespace in the certificate
            clean_cert = cert_context.strip()
            
            # Make sure we have a complete certificate
            if not clean_cert.startswith("-----BEGIN CERTIFICATE-----") or not clean_cert.endswith("-----END CERTIFICATE-----"):
                print("⚠️ Warning: Certificate appears to be incomplete or malformed")
            
            # Try different prompt formats to get better responses
            if "list" in question.lower() or "flaws" in question.lower() or "vulnerabilities" in question.lower():
                prompt = f"Below is an X.509 certificate. Please analyze it and list all security flaws.\n\nCertificate:\n{clean_cert}\n\nSecurity flaws:\n"
            else:
                prompt = f"Question: {question}\nCertificate:\n{clean_cert}\nAnswer: "
            
            # Generate the response
            inputs = tokenizer(prompt, return_tensors="pt").to(device)
            
            print("\n⏳ Generating response...")
            
            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=MAX_NEW_TOKENS,
                    do_sample=False,  # More deterministic output
                    top_p=1.0,
                    temperature=0.2,  # Lower temperature for more focused output
                    repetition_penalty=1.5,
                    num_beams=4,      # Beam search for better quality
                    early_stopping=True,
                    no_repeat_ngram_size=2
                )
            
            # Decode and print the response
            decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)
            print("\n--- Raw Model Output ---")
            print(decoded)
            
            # Extract answer based on prompt format
            if "Security flaws:" in prompt:
                answer_marker = "Security flaws:"
                if answer_marker in decoded:
                    answer = decoded[decoded.find(answer_marker) + len(answer_marker):].strip()
                    print("\n--- Extracted Security Flaws ---")
                    print(answer)
                else:
                    print("\n⚠️ Model didn't generate a proper response")
                    # Fallback to rule-based analysis
                    print("\n🔄 Falling back to rule-based certificate analysis...")
                    analysis_results = analyze_certificate(cert_context)
                    for category, issues in analysis_results.items():
                        if issues:
                            print(f"\n{category.upper()}:")
                            for issue in issues:
                                print(f" - {issue}")
            else:
                # Standard Q&A format
                answer_marker = "Answer: "
                if answer_marker in decoded:
                    answer = decoded[decoded.rfind(answer_marker) + len(answer_marker):].strip()
                    print("\n--- Extracted Answer ---")
                    print(answer)
                else:
                    answer = decoded[len(prompt):].strip()
                    print("\n--- Extracted Answer ---")
                    print(answer if answer else "[No clear answer extracted]")
            
            # If we have known flaws, compare with the model's output
            if known_flaws and ("list" in question.lower() or "what" in question.lower() or "flaws" in question.lower()):
                print("\n--- Known Flaws (from JSON) ---")
                print(", ".join(known_flaws))
                
        except Exception as e:
            print(f"\n⚠️ Error: {e}")
            continue

if __name__ == "__main__":
    main()
