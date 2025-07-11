#!/usr/bin/env python3

"""
generate_clean_certs.py - Creates synthetic clean X.509 certificates

This script generates synthetic certificates that are guaranteed to be clean
(have no flaws) according to the criteria defined in label_certs.py.
"""

import os
import json
import datetime
import random
import ipaddress
import uuid
import hashlib
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Configuration
OUTPUT_DIR = "../clean"
INDEX_FILE = "../clean/index.json"
TARGET_CLEAN_CERTS = 1800

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load index if exists
if os.path.exists(INDEX_FILE):
    with open(INDEX_FILE, "r") as f:
        cert_index = json.load(f)
else:
    cert_index = {}

# Common domains for certificate generation
DOMAINS = [
    "example.com", "example.org", "example.net", "synthetic-cert.com",
    "cleanpki.org", "securetest.net", "validcert.io", "pkisecops.dev",
    "safecert.app", "trustworthy.cloud", "securepki.tech", "validx509.co",
    "cleanchain.cert", "goodpractice.pki", "strongcrypto.net"
]

# Common organizational names
ORGANIZATIONS = [
    "Example Corporation", "Synthetic Certificates Inc.", "Clean PKI Ltd.",
    "SecureTrust Organization", "Valid Certificates Co.", "PKISecOPS Foundation",
    "TrustChain Systems", "SecureSign Technologies", "CryptoValid Solutions",
    "CertTrust Alliance", "Digital Identity Group", "Secure Infrastructure Inc."
]

# Common organizational units
ORGANIZATIONAL_UNITS = [
    "IT Security", "PKI Team", "Certificate Management", "Security Operations",
    "Infrastructure", "DevSecOps", "Identity Management", "Crypto Services",
    "Trust Services", "Security Engineering", "Digital Trust", "Secure Systems"
]

# Common localities
LOCALITIES = [
    "San Francisco", "New York", "London", "Tokyo", "Berlin", "Sydney",
    "Toronto", "Singapore", "Paris", "Amsterdam", "Stockholm", "Zurich"
]

# Common states/provinces
STATES = [
    "California", "New York", "Texas", "Washington", "Ontario", "British Columbia",
    "Greater London", "New South Wales", "Bavaria", "Île-de-France", "Tokyo Prefecture"
]

# Common countries
COUNTRIES = [
    "US", "CA", "GB", "DE", "JP", "AU", "FR", "SG", "NL", "SE", "CH"
]

def generate_random_serial():
    """Generate a high-entropy random serial number (at least 20 bits)"""
    # Use 128 bits (16 bytes) for good entropy
    return int.from_bytes(os.urandom(16), byteorder='big')

def generate_key_pair(key_size=2048):
    """Generate an RSA key pair with specified key size"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

def generate_name():
    """Generate a random distinguished name"""
    domain = random.choice(DOMAINS)
    subdomain = f"{random.choice(['secure', 'api', 'www', 'mail', 'auth', 'portal', 'app'])}.{domain}"
    
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subdomain),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, random.choice(ORGANIZATIONS)),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, random.choice(ORGANIZATIONAL_UNITS)),
        x509.NameAttribute(NameOID.LOCALITY_NAME, random.choice(LOCALITIES)),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, random.choice(STATES)),
        x509.NameAttribute(NameOID.COUNTRY_NAME, random.choice(COUNTRIES))
    ])

def generate_alt_names(primary_domain):
    """Generate subject alternative names"""
    domain_parts = primary_domain.split('.')
    base_domain = '.'.join(domain_parts[-2:])
    
    # Generate 2-5 alternative names
    alt_names = []
    
    # Add the primary domain
    alt_names.append(x509.DNSName(primary_domain))
    
    # Add some subdomains
    subdomains = ['www', 'api', 'mail', 'auth', 'app', 'portal', 'secure']
    for _ in range(random.randint(1, 4)):
        subdomain = random.choice(subdomains)
        alt_names.append(x509.DNSName(f"{subdomain}.{base_domain}"))
    
    # Maybe add an IP address (50% chance)
    if random.random() > 0.5:
        # Generate a random private IP address
        ip_parts = [10]  # Start with 10 for private IP
        ip_parts.extend([random.randint(0, 255) for _ in range(3)])
        ip_str = '.'.join(map(str, ip_parts))
        alt_names.append(x509.IPAddress(ipaddress.IPv4Address(ip_str)))
    
    return alt_names

def get_primary_domain_from_name(name):
    """Extract the primary domain from a certificate name"""
    for attr in name:
        if attr.oid == NameOID.COMMON_NAME:
            return attr.value
    return "unknown.com"

def generate_clean_certificate():
    """Generate a certificate that meets all 'clean' criteria"""
    # Generate key pair (use 2048 bits or more to avoid 'short_key' flaw)
    key_size = random.choice([2048, 3072, 4096])
    private_key = generate_key_pair(key_size)
    
    # Generate subject name
    subject = generate_name()
    
    # For simplicity, use the same name for issuer (self-signed)
    # In a real scenario, you might want to create a CA hierarchy
    issuer = subject
    
    # Extract primary domain for SAN
    primary_domain = get_primary_domain_from_name(subject)
    
    # Generate a high-entropy serial number (to avoid 'low_entropy_serial' flaw)
    serial = generate_random_serial()
    
    # Set validity period (to avoid 'expired' flaw)
    # Start from a week ago
    valid_from = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    # Valid for 1-2 years
    valid_until = valid_from + datetime.timedelta(days=random.randint(365, 730))
    
    # Create certificate builder
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        serial
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_until
    )
    
    # Add extensions
    
    # Subject Alternative Name (to avoid 'missing_SAN' flaw)
    alt_names = generate_alt_names(primary_domain)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(alt_names),
        critical=False
    )
    
    # Basic Constraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # Key Usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    # Extended Key Usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=False
    )
    
    # Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    
    # Use SHA256 for signature (to avoid 'sha1_signature' flaw)
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    return certificate, private_key

def save_certificate(certificate, private_key, index):
    """Save certificate and private key to files"""
    # Generate a unique ID for this synthetic certificate
    cert_id = f"synthetic-{uuid.uuid4()}"
    
    # Get certificate hash
    der_bytes = certificate.public_bytes(encoding=serialization.Encoding.DER)
    sha256 = hashlib.sha256(der_bytes).hexdigest()
    
    # Save certificate in PEM format
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
    cert_path = os.path.join(OUTPUT_DIR, f"{sha256}.pem")
    
    with open(cert_path, "w") as f:
        f.write(cert_pem)
    
    # Optionally save private key (for testing purposes)
    # key_pem = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # ).decode('utf-8')
    # key_path = os.path.join(OUTPUT_DIR, f"{sha256}.key")
    # with open(key_path, "w") as f:
    #     f.write(key_pem)
    
    # Update index
    index[cert_id] = {
        "hash": sha256,
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_before": certificate.not_valid_before.isoformat(),
        "not_after": certificate.not_valid_after.isoformat(),
        "synthetic": True
    }
    
    return sha256

def main():
    import time
    
    start_time = time.time()
    
    # Count existing clean certs
    existing_clean_certs = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
    
    print(f"Starting with {existing_clean_certs} existing clean certificates")
    print(f"Target: {TARGET_CLEAN_CERTS} clean certificates")
    
    # Calculate how many more we need
    certs_to_generate = max(0, TARGET_CLEAN_CERTS - existing_clean_certs)
    print(f"Generating {certs_to_generate} synthetic clean certificates...")
    
    try:
        for i in range(certs_to_generate):
            # Generate a clean certificate
            certificate, private_key = generate_clean_certificate()
            
            # Save the certificate
            sha256 = save_certificate(certificate, private_key, cert_index)
            
            # Print progress
            print(f"Generated certificate {i+1}/{certs_to_generate}: {sha256}")
            
            # Save index periodically
            if (i + 1) % 50 == 0 or i == certs_to_generate - 1:
                with open(INDEX_FILE, "w") as f:
                    json.dump(cert_index, f, indent=2)
                print(f"Saved index file checkpoint ({i+1} certificates generated)")
    
    finally:
        # Always save the index when done or interrupted
        with open(INDEX_FILE, "w") as f:
            json.dump(cert_index, f, indent=2)
        
        # Print summary
        elapsed_time = time.time() - start_time
        final_count = len([f for f in os.listdir(OUTPUT_DIR) if f.endswith(".pem")])
        
        print(f"\n=== Synthetic Certificate Generation Summary ===")
        print(f"Certificates generated: {certs_to_generate}")
        print(f"Total clean certificates: {final_count}")
        print(f"Time elapsed: {elapsed_time:.1f} seconds ({elapsed_time/60:.1f} minutes)")
        
        if final_count >= TARGET_CLEAN_CERTS:
            print(f"\n✅ SUCCESS: Target of {TARGET_CLEAN_CERTS} clean certificates reached!")
        else:
            print(f"\n⚠️ NOTE: Only have {final_count} clean certificates, below target of {TARGET_CLEAN_CERTS}")
            
        print("\nDone generating synthetic clean certificates.")

if __name__ == "__main__":
    main()
