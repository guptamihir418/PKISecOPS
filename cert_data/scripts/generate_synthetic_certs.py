#!/usr/bin/env python3

import os
import json
import hashlib
import subprocess
import tempfile
import random
import string
from pathlib import Path

# Define paths
BASE_DIR = Path('/Users/mihirgupta/Desktop/Projects/PKISecOPS')
TEMP_DIR = Path(tempfile.mkdtemp())

def ensure_dir(directory):
    """Ensure the directory exists"""
    os.makedirs(directory, exist_ok=True)

def generate_cert_id(cert_pem):
    """Generate a unique ID for the certificate based on its PEM content"""
    return hashlib.sha256(cert_pem.encode('utf-8')).hexdigest()

def generate_certificate_with_sha1(subject_name, index):
    """Generate a certificate with SHA-1 signature using OpenSSL"""
    # Create temporary files for the key and certificate
    key_file = TEMP_DIR / f"key_{index}.pem"
    cert_file = TEMP_DIR / f"cert_{index}.pem"
    config_file = TEMP_DIR / f"openssl_{index}.cnf"
    
    # Create OpenSSL config file with SAN
    with open(config_file, 'w') as f:
        f.write(f"""\
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {subject_name}
O = PKISecOPS Synthetic Certs
OU = Security Research
C = US

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {subject_name}
DNS.2 = www.{subject_name}
""")
    
    # Generate private key
    subprocess.run([
        'openssl', 'genrsa',
        '-out', str(key_file),
        '2048'
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Generate self-signed certificate with SHA-1 signature
    subprocess.run([
        'openssl', 'req',
        '-new',
        '-x509',
        '-sha1',  # Use SHA-1 for signing (this is the flaw)
        '-key', str(key_file),
        '-out', str(cert_file),
        '-days', '365',
        '-config', str(config_file)
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Read the certificate
    with open(cert_file, 'r') as f:
        cert_pem = f.read()
    
    # Clean up temporary files
    key_file.unlink()
    cert_file.unlink()
    config_file.unlink()
    
    return cert_pem, ['sha1_signature']

def generate_certificate_with_short_key(subject_name, index):
    """Generate a certificate with a short key (1024 bits) using OpenSSL"""
    # Create temporary files for the key and certificate
    key_file = TEMP_DIR / f"key_{index}.pem"
    cert_file = TEMP_DIR / f"cert_{index}.pem"
    config_file = TEMP_DIR / f"openssl_{index}.cnf"
    
    # Create OpenSSL config file with SAN
    with open(config_file, 'w') as f:
        f.write(f"""\
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {subject_name}
O = PKISecOPS Synthetic Certs
OU = Security Research
C = US

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {subject_name}
DNS.2 = www.{subject_name}
""")
    
    # Generate short private key (1024 bits - this is the flaw)
    subprocess.run([
        'openssl', 'genrsa',
        '-out', str(key_file),
        '1024'  # Short key flaw
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Generate self-signed certificate with SHA-256 signature
    subprocess.run([
        'openssl', 'req',
        '-new',
        '-x509',
        '-sha256',
        '-key', str(key_file),
        '-out', str(cert_file),
        '-days', '365',
        '-config', str(config_file)
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Read the certificate
    with open(cert_file, 'r') as f:
        cert_pem = f.read()
    
    # Clean up temporary files
    key_file.unlink()
    cert_file.unlink()
    config_file.unlink()
    
    return cert_pem, ['short_key']

def generate_certificate_missing_san(subject_name, index):
    """Generate a certificate without Subject Alternative Name (SAN) using OpenSSL"""
    # Create temporary files for the key and certificate
    key_file = TEMP_DIR / f"key_{index}.pem"
    cert_file = TEMP_DIR / f"cert_{index}.pem"
    config_file = TEMP_DIR / f"openssl_{index}.cnf"
    
    # Create OpenSSL config file WITHOUT SAN (this is the flaw)
    with open(config_file, 'w') as f:
        f.write(f"""\
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {subject_name}
O = PKISecOPS Synthetic Certs
OU = Security Research
C = US

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = digitalSignature, keyEncipherment
""")
    
    # Generate private key
    subprocess.run([
        'openssl', 'genrsa',
        '-out', str(key_file),
        '2048'
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Generate self-signed certificate with SHA-256 signature
    subprocess.run([
        'openssl', 'req',
        '-new',
        '-x509',
        '-sha256',
        '-key', str(key_file),
        '-out', str(cert_file),
        '-days', '365',
        '-config', str(config_file)
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Read the certificate
    with open(cert_file, 'r') as f:
        cert_pem = f.read()
    
    # Clean up temporary files
    key_file.unlink()
    cert_file.unlink()
    config_file.unlink()
    
    return cert_pem, ['missing_SAN']

def generate_low_entropy_certificate(subject_name, index):
    """Generate a certificate with low entropy in the serial number using OpenSSL"""
    # Create temporary files for the key and certificate
    key_file = TEMP_DIR / f"key_{index}.pem"
    cert_file = TEMP_DIR / f"cert_{index}.pem"
    config_file = TEMP_DIR / f"openssl_{index}.cnf"
    serial_file = TEMP_DIR / f"serial_{index}.txt"
    
    # Create a low entropy serial number (e.g., all 1's or repeating pattern)
    with open(serial_file, 'w') as f:
        f.write('1111111111111111')  # Low entropy serial
    
    # Create OpenSSL config file with SAN
    with open(config_file, 'w') as f:
        f.write(f"""\
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {subject_name}
O = PKISecOPS Synthetic Certs
OU = Security Research
C = US

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {subject_name}
DNS.2 = www.{subject_name}
""")
    
    # Generate private key
    subprocess.run([
        'openssl', 'genrsa',
        '-out', str(key_file),
        '2048'
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Generate self-signed certificate with SHA-256 signature and low entropy serial
    subprocess.run([
        'openssl', 'req',
        '-new',
        '-x509',
        '-sha256',
        '-key', str(key_file),
        '-out', str(cert_file),
        '-days', '365',
        '-config', str(config_file),
        '-set_serial', '1111111111111111'  # Low entropy serial number
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Read the certificate
    with open(cert_file, 'r') as f:
        cert_pem = f.read()
    
    # Clean up temporary files
    key_file.unlink()
    cert_file.unlink()
    config_file.unlink()
    serial_file.unlink()
    
    return cert_pem, ['low_entropy']

def save_certificate(cert_pem, flaws, output_dir):
    """Save a certificate as a PEM file"""
    # Generate a unique ID for this certificate
    cert_id = generate_cert_id(cert_pem)
    
    # Save as PEM file
    pem_path = output_dir / f"{cert_id}.pem"
    with open(pem_path, 'w') as f:
        f.write(cert_pem)
    
    return cert_id

def generate_synthetic_dataset():
    """Generate a synthetic dataset of certificates with various flaws"""
    # Define output directories for each flaw type
    sha1_dir = BASE_DIR / 'cert_data' / 'sha1_flawed'
    short_key_dir = BASE_DIR / 'cert_data' / 'short_key_flawed'
    missing_san_dir = BASE_DIR / 'cert_data' / 'missing_san_flawed'
    low_entropy_dir = BASE_DIR / 'cert_data' / 'low_entropy_flawed'
    
    # Ensure directories exist
    for directory in [sha1_dir, short_key_dir, missing_san_dir, low_entropy_dir]:
        ensure_dir(directory)
    
    ensure_dir(TEMP_DIR)
    
    try:
        # Generate SHA-1 flawed certificates (1000)
        print("Generating 1000 certificates with sha1_signature flaw...")
        for i in range(1000):
            subject_name = f"sha1-cert-{i+1}.example.com"
            cert_pem, flaws = generate_certificate_with_sha1(subject_name, f"sha1_{i}")
            save_certificate(cert_pem, flaws, sha1_dir)
            
            # Progress indicator
            if (i + 1) % 100 == 0 or i + 1 == 1000:
                print(f"Generated {i + 1}/1000 SHA-1 certificates")
        
        # Generate short key flawed certificates (700)
        print("\nGenerating 700 certificates with short_key flaw...")
        for i in range(700):
            subject_name = f"short-key-cert-{i+1}.example.com"
            cert_pem, flaws = generate_certificate_with_short_key(subject_name, f"short_key_{i}")
            save_certificate(cert_pem, flaws, short_key_dir)
            
            # Progress indicator
            if (i + 1) % 100 == 0 or i + 1 == 700:
                print(f"Generated {i + 1}/700 short key certificates")
        
        # Generate missing SAN flawed certificates (600)
        print("\nGenerating 600 certificates with missing_SAN flaw...")
        for i in range(600):
            subject_name = f"missing-san-cert-{i+1}.example.com"
            cert_pem, flaws = generate_certificate_missing_san(subject_name, f"missing_san_{i}")
            save_certificate(cert_pem, flaws, missing_san_dir)
            
            # Progress indicator
            if (i + 1) % 100 == 0 or i + 1 == 600:
                print(f"Generated {i + 1}/600 missing SAN certificates")
        
        # Generate low entropy flawed certificates (200)
        print("\nGenerating 200 certificates with low_entropy flaw...")
        for i in range(200):
            subject_name = f"low-entropy-cert-{i+1}.example.com"
            cert_pem, flaws = generate_low_entropy_certificate(subject_name, f"low_entropy_{i}")
            save_certificate(cert_pem, flaws, low_entropy_dir)
            
            # Progress indicator
            if (i + 1) % 50 == 0 or i + 1 == 200:
                print(f"Generated {i + 1}/200 low entropy certificates")
    finally:
        # Clean up the temporary directory
        try:
            import shutil
            shutil.rmtree(TEMP_DIR)
        except:
            pass

def main():
    print("Generating synthetic certificates with various flaws...")
    generate_synthetic_dataset()
    print("\nDone! Certificates saved to respective directories:")

if __name__ == "__main__":
    main()
