#!/usr/bin/env python3

"""
harvest_clean_certs.py - Downloads clean certificates without flaws from crt.sh

This script:
1. Downloads certificates from Certificate Transparency logs via crt.sh
2. Evaluates each certificate against flaw criteria
3. Only saves certificates that have no flaws
4. Continues until reaching the target number of clean certificates
"""

import requests
import os
import json
import hashlib
import time
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

# Configuration
OUTPUT_DIR = "../clean"
INDEX_FILE = "../clean/index.json"
TARGET_CLEAN_CERTS = 1800

# Expanded domain list with domains more likely to have clean certificates
# Including financial, government, and major tech companies known for good security practices
DOMAINS = [
    # Major tech companies with good security practices
    "%25.google.com",
    "%25.microsoft.com",
    "%25.cloudflare.com",
    "%25.apple.com",
    "%25.amazon.com",
    "%25.aws.amazon.com",
    "%25.digicert.com",
    "%25.entrust.net",
    "%25.globalsign.com",
    "%25.godaddy.com",
    "%25.sectigo.com",
    "%25.letsencrypt.org",
    "%25.github.com",
    "%25.salesforce.com",
    "%25.ibm.com",
    "%25.cisco.com",
    
    # Financial services (typically have strong certificate practices)
    "%25.visa.com",
    "%25.mastercard.com",
    "%25.amex.com",
    "%25.chase.com",
    "%25.bankofamerica.com",
    "%25.wellsfargo.com",
    "%25.citibank.com",
    "%25.jpmorgan.com",
    "%25.fidelity.com",
    "%25.schwab.com",
    "%25.paypal.com",
    "%25.stripe.com",
    
    # Government domains (often have strict requirements)
    "%25.gov",
    "%25.mil",
    "%25.nasa.gov",
    "%25.nih.gov",
    "%25.cdc.gov",
    "%25.nist.gov",
    "%25.treasury.gov",
    "%25.whitehouse.gov",
    "%25.gsa.gov",
    "%25.irs.gov",
    
    # Cloud providers
    "%25.azure.com",
    "%25.gcp.com",
    "%25.digitalocean.com",
    "%25.heroku.com",
    
    # Certificate Authorities
    "%25.comodo.com",
    "%25.verisign.com",
    "%25.identrust.com",
    "%25.trustwave.com",
    "%25.rapidssl.com",
    
    # Healthcare (often have compliance requirements)
    "%25.mayo.edu",
    "%25.clevelandclinic.org",
    "%25.hopkinsmedicine.org",
    "%25.mountsinai.org",
    "%25.ucsfhealth.org",
    
    # Education
    "%25.edu",
    "%25.harvard.edu",
    "%25.mit.edu",
    "%25.stanford.edu",
    "%25.berkeley.edu",
    
    # Newer TLDs (often have newer, cleaner certs)
    "%25.dev",
    "%25.app",
    "%25.cloud",
    "%25.security"
]

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load index if exists
if os.path.exists(INDEX_FILE):
    with open(INDEX_FILE, "r") as f:
        cert_index = json.load(f)
else:
    cert_index = {}

def get_cert_hash(cert):
    """Generate SHA256 hash of certificate DER bytes"""
    der_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der_bytes).hexdigest()

def has_flaws(cert):
    """
    Check if certificate has any flaws based on criteria from label_certs.py
    Returns: (bool has_flaws, list flaws)
    """
    flaws = []

    # Expired
    if cert.not_valid_after < datetime.datetime.utcnow():
        flaws.append("expired")

    # Short key
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        if pub_key.key_size < 2048:
            flaws.append("short_key")

    # SHA1 signature
    sig_algo = cert.signature_hash_algorithm.name.lower()
    if "sha1" in sig_algo:
        flaws.append("sha1_signature")

    # Missing SAN
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value.get_values_for_type(x509.DNSName)
        if not san:
            flaws.append("missing_SAN")
    except x509.ExtensionNotFound:
        flaws.append("missing_SAN")

    # Low entropy serial
    serial = cert.serial_number
    bit_length = serial.bit_length()
    if bit_length < 20:
        flaws.append("low_entropy_serial")

    return (len(flaws) > 0, flaws)

def fetch_crtsh_certs(domain_pattern):
    """Fetch certificate metadata from crt.sh for a domain pattern"""
    base_url = f"https://crt.sh/?q={domain_pattern}&output=json"
    print(f"\nFetching list from crt.sh for domain pattern: {domain_pattern}")
    
    try:
        response = requests.get(base_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {domain_pattern}: {e}")
        return None

def download_and_check_cert(cert_id):
    """
    Download certificate by ID from crt.sh and check if it's clean
    Returns: (bool is_clean, str sha256) or (False, None) if error
    """
    # Skip if already downloaded
    if str(cert_id) in cert_index:
        print(f"Skipping cert ID {cert_id} (already processed)")
        return (False, None)

    # Download PEM
    try:
        print(f"Downloading cert ID {cert_id}...")
        response = requests.get(f"https://crt.sh/?d={cert_id}", timeout=15)
        response.raise_for_status()
        pem_data = response.text
        
        # Verify it's actually a certificate
        if "-----BEGIN CERTIFICATE-----" not in pem_data:
            print(f"Warning: Downloaded content for {cert_id} doesn't appear to be a certificate")
            return (False, None)
            
        # Parse and hash
        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
            sha256 = get_cert_hash(cert)
        except Exception as e:
            print(f"Error parsing certificate {cert_id}: {e}")
            return (False, None)

        # Check if we already have this cert under a different ID
        for existing_id, existing_info in cert_index.items():
            if isinstance(existing_info, dict) and existing_info.get("hash") == sha256:
                print(f"Skipping cert ID {cert_id} (duplicate of {existing_id})")
                return (False, None)
            elif isinstance(existing_info, str) and existing_info == sha256:
                print(f"Skipping cert ID {cert_id} (duplicate of {existing_id})")
                return (False, None)

        # Check for flaws
        has_any_flaws, flaws = has_flaws(cert)
        
        # If clean, save to file
        if not has_any_flaws:
            output_path = os.path.join(OUTPUT_DIR, f"{sha256}.pem")
            with open(output_path, "w") as f:
                f.write(pem_data)
            
            # Update index with more info
            cert_index[str(cert_id)] = {
                "hash": sha256,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat()
            }
            
            print(f"✅ Saved CLEAN cert {sha256}")
            return (True, sha256)
        else:
            # Still record in index that we've seen this cert, but mark as having flaws
            cert_index[str(cert_id)] = {
                "hash": sha256,
                "flaws": flaws,
                "skipped": True
            }
            print(f"❌ Skipping cert with flaws: {flaws}")
            return (False, sha256)
            
    except requests.exceptions.RequestException as e:
        print(f"Download failed for cert ID {cert_id}: {e}")
        return (False, None)
    except Exception as e:
        print(f"Unexpected error for cert ID {cert_id}: {e}")
        return (False, None)

def main():
    start_time = time.time()
    total_certs_found = 0
    domains_processed = 0
    clean_certs_count = 0
    
    # Count existing clean certs
    existing_clean_certs = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
    clean_certs_count = existing_clean_certs
    
    print(f"Starting with {existing_clean_certs} existing clean certificates")
    print(f"Target: {TARGET_CLEAN_CERTS} clean certificates")
    
    try:
        for domain in DOMAINS:
            # Check if we've reached our target
            if clean_certs_count >= TARGET_CLEAN_CERTS:
                print(f"\n>>> Target reached: {clean_certs_count} clean certificates collected <<<")
                break
                
            # Fetch certificates for this domain
            certs = fetch_crtsh_certs(domain)
            
            # If fetch returned None or empty list, skip this domain
            if not certs:
                print(f"No certificates found for {domain}, skipping.")
                continue
                
            print(f"Found {len(certs)} cert records for {domain}.")
            total_certs_found += len(certs)
            
            # Process certificates
            certs_processed = 0
            clean_certs_this_domain = 0
            
            for entry in certs:
                # Check if we've reached our target
                if clean_certs_count >= TARGET_CLEAN_CERTS:
                    print(f"\n>>> Target reached: {clean_certs_count} clean certificates collected <<<")
                    break
                    
                cert_id = entry.get("id")
                if not cert_id:
                    continue
                    
                is_clean, _ = download_and_check_cert(cert_id)
                certs_processed += 1
                
                if is_clean:
                    clean_certs_count += 1
                    clean_certs_this_domain += 1
                    
                    # Show progress
                    remaining = TARGET_CLEAN_CERTS - clean_certs_count
                    print(f"Progress: {clean_certs_count}/{TARGET_CLEAN_CERTS} clean certs ({remaining} remaining)")
                
                # Save index periodically
                if certs_processed % 20 == 0:
                    with open(INDEX_FILE, "w") as f:
                        json.dump(cert_index, f, indent=2)
                
                # Polite delay to avoid rate limiting
                time.sleep(0.5)
                
                # If we've processed enough certs from this domain, move on
                # This ensures we get diversity across domains
                if certs_processed >= 100 or clean_certs_this_domain >= 20:
                    print(f"Processed enough from {domain}, moving to next domain")
                    break
            
            domains_processed += 1
            print(f"Completed domain {domains_processed}/{len(DOMAINS)}: {domain} - Found {clean_certs_this_domain} clean certs")
            
            # Save index after each domain
            with open(INDEX_FILE, "w") as f:
                json.dump(cert_index, f, indent=2)
                
            # Add a delay between domains to be polite
            time.sleep(2)
            
    finally:
        # Always save the index when done or interrupted
        with open(INDEX_FILE, "w") as f:
            json.dump(cert_index, f, indent=2)
        
        # Print summary
        elapsed_time = time.time() - start_time
        final_count = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
        
        print(f"\n=== Clean Certificate Harvest Summary ===")
        print(f"Domains processed: {domains_processed}/{len(DOMAINS)}")
        print(f"Total certificates found in CT logs: {total_certs_found}")
        print(f"Clean certificates collected: {final_count}")
        print(f"Time elapsed: {elapsed_time:.1f} seconds ({elapsed_time/60:.1f} minutes)")
        
        if final_count >= TARGET_CLEAN_CERTS:
            print(f"\n✅ SUCCESS: Target of {TARGET_CLEAN_CERTS} clean certificates reached!")
        else:
            print(f"\n⚠️ NOTE: Only collected {final_count} clean certificates, below target of {TARGET_CLEAN_CERTS}")
            
        print("\nDone harvesting clean certificates.")

if __name__ == "__main__":
    main()
