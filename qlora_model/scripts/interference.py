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

# =================================================================================
# Config
# =================================================================================
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"
ADAPTER_DIR = "../model_weights/"
MAX_NEW_TOKENS = 512

# Common certificate security flaws for fallback analysis
COMMON_CERT_FLAWS = {
    "expired": "The certificate has expired or is not yet valid",
    "self_signed": "The certificate is self-signed",
    "weak_key": "The certificate uses a weak key size (less than 2048 bits for RSA)",
    "weak_signature": "The certificate uses a weak signature algorithm (e.g., SHA-1, MD5)",
    "wildcard": "The certificate uses wildcards which may be overly permissive",
    "subject_mismatch": "The certificate subject doesn't match the intended domain",
    "missing_san": "The certificate is missing Subject Alternative Names",
    "revoked": "The certificate may be revoked",
    "path_validation": "Certificate path validation issues",
    "short_validity": "The certificate has an unusually short validity period"
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
# Interactive loop
# =================================================================================
print("\n✅ QLoRA Cert Inspector Ready! Type 'exit' to quit.")
print("Commands:")
print("  - 'exit' or 'quit': Exit the program")
print("  - 'load <cert_id>': Load a certificate from JSON files")
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

# Function to process the input and extract question and certificate
def process_input(input_text):
    # Check if this is a full input with certificate
    if "context" in input_text and "-----BEGIN CERTIFICATE-----" in input_text:
        try:
            # Split only on the first occurrence of 'context'
            question_part, cert_part = input_text.split("context", 1)
            
            # Clean up the question
            question = question_part.strip()
            if question.startswith('"') and question.endswith('"'):
                question = question[1:-1].strip()
                
            # Extract the certificate
            cert_pattern = r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----'
            cert_match = re.search(cert_pattern, cert_part)
            
            if cert_match:
                certificate = cert_match.group(0)
                return question, certificate
        except Exception as e:
            print(f"\n⚠️ Error processing input: {e}")
    
    # If we get here, either there's no certificate or we couldn't parse it properly
    # Just return the input as the question and use the existing certificate
    question = input_text.strip()
    if question.startswith('"') and question.endswith('"'):
        question = question[1:-1].strip()
    return question, None

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
        question, new_cert = process_input(user_input)
        
        # If a new certificate was provided, use it
        if new_cert:
            cert_context = new_cert
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
    except Exception as e:
        print(f"⚠️ Error: {e}")
        continue
    
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
