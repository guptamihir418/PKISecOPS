#!/usr/bin/env python3

"""
================================================================================
harvest_certs.py

Purpose:
--------
This script downloads a large dataset of real-world X.509 certificates from
public Certificate Transparency logs via the crt.sh web interface, across multiple
domain patterns. This builds a broad, diverse foundational dataset.

What it does:
-------------
1. For each domain pattern in a list, queries crt.sh to retrieve cert metadata.
2. Downloads the PEM-encoded certs by their unique ID.
3. Computes SHA256 on DER bytes to avoid duplicates.
4. Saves each unique cert to:
       cert_data/raw/<sha256>.pem
5. Updates index.json so it can resume later.

Typical usage:
--------------
> conda activate cert-poc
> python3 harvest_certs.py

Author:
-------
Mihir Gupta, 2025
For AI Certificate Service POC (PKISecOPS project)
================================================================================
"""

import requests
import os
import json
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import time

# Expanded domain list to collect 10k-15k certificates
DOMAINS = [
    # Major tech companies
    "%25.google.com",
    "%25.microsoft.com",
    "%25.amazon.com",
    "%25.cloudflare.com",
    "%25.facebook.com",
    "%25.apple.com",
    "%25.paypal.com",
    "%25.github.com",
    "%25.netflix.com",
    "%25.twitter.com",
    "%25.linkedin.com",
    "%25.adobe.com",
    "%25.salesforce.com",
    "%25.oracle.com",
    "%25.ibm.com",
    "%25.intel.com",
    "%25.cisco.com",
    "%25.amd.com",
    "%25.nvidia.com",
    "%25.qualcomm.com",
    
    # Financial services
    "%25.visa.com",
    "%25.mastercard.com",
    "%25.amex.com",
    "%25.chase.com",
    "%25.bankofamerica.com",
    "%25.wellsfargo.com",
    "%25.citibank.com",
    "%25.capitalone.com",
    "%25.jpmorgan.com",
    "%25.fidelity.com",
    "%25.schwab.com",
    
    # E-commerce
    "%25.walmart.com",
    "%25.target.com",
    "%25.ebay.com",
    "%25.etsy.com",
    "%25.shopify.com",
    "%25.bestbuy.com",
    "%25.costco.com",
    
    # Cloud providers
    "%25.aws.amazon.com",
    "%25.azure.com",
    "%25.gcp.com",
    "%25.digitalocean.com",
    "%25.heroku.com",
    "%25.linode.com",
    "%25.vultr.com",
    
    # Social media
    "%25.instagram.com",
    "%25.tiktok.com",
    "%25.snapchat.com",
    "%25.pinterest.com",
    "%25.reddit.com",
    "%25.tumblr.com",
    
    # News and media
    "%25.cnn.com",
    "%25.nytimes.com",
    "%25.bbc.com",
    "%25.washingtonpost.com",
    "%25.reuters.com",
    "%25.bloomberg.com",
    
    # Telecommunications
    "%25.verizon.com",
    "%25.att.com",
    "%25.tmobile.com",
    "%25.sprint.com",
    "%25.comcast.com",
    "%25.charter.com",
    
    # Education
    "%25.edu",
    "%25.harvard.edu",
    "%25.mit.edu",
    "%25.stanford.edu",
    "%25.berkeley.edu",
    
    # Government
    "%25.gov",
    "%25.nasa.gov",
    "%25.nih.gov",
    "%25.cdc.gov",
    "%25.whitehouse.gov",
    
    # Top-level domains (to get a diverse set)
    "example.com",
    "example.org",
    "example.net",
    "%25.io",
    "%25.ai",
    "%25.dev",
    "%25.app"
]

OUTPUT_DIR = "../raw"
INDEX_FILE = "../raw/index.json"

# ensure output dir exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# load index if exists
if os.path.exists(INDEX_FILE):
    with open(INDEX_FILE, "r") as f:
        cert_index = json.load(f)
else:
    cert_index = {}

def get_cert_hash(cert):
    der_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der_bytes).hexdigest()

def fetch_crtsh_certs(domain_pattern):
    base_url = f"https://crt.sh/?q={domain_pattern}&output=json"
    print(f"\nFetching list from crt.sh for domain pattern: {domain_pattern}")
    
    # Just try once with a reasonable timeout
    try:
        response = requests.get(base_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Request failed for {domain_pattern}: {e}")
        return None  # Return None instead of raising an exception

def download_and_save(cert_id):
    # Skip if already downloaded
    if str(cert_id) in cert_index:
        print(f"Skipping cert ID {cert_id} (already downloaded)")
        return

    # Download PEM - just try once
    try:
        print(f"Downloading cert ID {cert_id}...")
        response = requests.get(f"https://crt.sh/?d={cert_id}", timeout=15)
        response.raise_for_status()
        pem_data = response.text
        
        # Verify it's actually a certificate
        if "-----BEGIN CERTIFICATE-----" not in pem_data:
            print(f"Warning: Downloaded content for {cert_id} doesn't appear to be a certificate")
            return
            
        # Parse and hash
        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
            sha256 = get_cert_hash(cert)
        except Exception as e:
            print(f"Error parsing certificate {cert_id}: {e}")
            return

        # Skip if we already have this cert under a different ID
        for existing_id, existing_hash in cert_index.items():
            if existing_hash == sha256:
                print(f"Skipping cert ID {cert_id} (duplicate of {existing_id})")
                return

        # Save to file
        output_path = os.path.join(OUTPUT_DIR, f"{sha256}.pem")
        with open(output_path, "w") as f:
            f.write(pem_data)

        # Update index
        cert_index[str(cert_id)] = sha256
        print(f"Saved cert {sha256}")
        
        # Count files periodically
        if len(cert_index) % 100 == 0:
            file_count = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
            print(f"\n>>> Current certificate count: {file_count} <<<\n")
            
        # Polite delay to avoid rate limiting
        time.sleep(1.0)  # reduced delay
        
    except requests.exceptions.RequestException as e:
        print(f"Download failed for cert ID {cert_id}: {e}")
        return
    except Exception as e:
        print(f"Unexpected error for cert ID {cert_id}: {e}")
        return

def main():
    start_time = time.time()
    total_certs_found = 0
    domains_processed = 0
    domains_skipped = 0
    
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    try:
        for domain in DOMAINS:
            # Check if we've reached our target
            current_count = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
            if current_count >= 15000:
                print(f"\n>>> Target reached: {current_count} certificates collected <<<")
                break
                
            # Fetch certificates for this domain
            certs = fetch_crtsh_certs(domain)
            
            # If fetch returned None or empty list, skip this domain
            if not certs:
                print(f"No certificates found for {domain}, skipping.")
                domains_skipped += 1
                continue
                
            print(f"Found {len(certs)} cert records for {domain}.")
            total_certs_found += len(certs)
            
            # Process a subset of certificates if there are too many
            # This helps ensure we get a diverse set across domains
            max_certs_per_domain = 500
            if len(certs) > max_certs_per_domain:
                print(f"Limiting to {max_certs_per_domain} certificates for {domain}")
                certs = certs[:max_certs_per_domain]

            # Process each certificate
            certs_processed = 0
            for entry in certs:
                cert_id = entry.get("id")
                if not cert_id:
                    continue
                    
                download_and_save(cert_id)
                certs_processed += 1
                
                # Save index more frequently for large domains
                if certs_processed % 100 == 0:
                    with open(INDEX_FILE, "w") as f:
                        json.dump(cert_index, f)
                    
            domains_processed += 1
            print(f"Completed domain {domains_processed}/{len(DOMAINS)}: {domain} - Processed {certs_processed} certs")
            
            # Save index after each domain
            with open(INDEX_FILE, "w") as f:
                json.dump(cert_index, f)
            print("Saved index file checkpoint")
                
            # Add a delay between domains to be polite
            time.sleep(2)
    finally:
        # Always save the index when done or interrupted
        with open(INDEX_FILE, "w") as f:
            json.dump(cert_index, f)
        
        # Print summary
        elapsed_time = time.time() - start_time
        final_count = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
        print(f"\n=== Harvest Summary ===")
        print(f"Domains processed successfully: {domains_processed}/{len(DOMAINS)}")
        print(f"Domains skipped due to errors: {domains_skipped}")
        print(f"Total certificates found in CT logs: {total_certs_found}")
        print(f"Unique certificates downloaded: {final_count}")
        print(f"Time elapsed: {elapsed_time:.1f} seconds ({elapsed_time/60:.1f} minutes)")
        
        if final_count >= 10000:
            print("\n✅ SUCCESS: Target of 10,000+ certificates reached!")
        else:
            print(f"\n⚠️ NOTE: Only collected {final_count} certificates, below target of 10,000")
            
        print("\nDone harvesting across domains.")


if __name__ == "__main__":
    main()
