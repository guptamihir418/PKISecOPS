#!/usr/bin/env python3
import os
import json
import datetime
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

RAW_DIR = "../raw"
LABELED_DIR = "../labeled"

os.makedirs(LABELED_DIR, exist_ok=True)

def has_low_entropy_serial(cert):
    serial = cert.serial_number
    bit_length = serial.bit_length()
    
    # Check for minimum bit length (RFC 5280 recommends at least 20 bits of entropy)
    if bit_length < 20:
        return True
    
    # Convert to hex string for pattern analysis
    hex_serial = format(serial, 'x')
    
    # Check for repeating patterns
    if len(hex_serial) >= 4:
        # Check for repeating digits or simple patterns
        repeating = any(hex_serial.count(digit * 3) > 0 for digit in '0123456789abcdef')
        if repeating:
            return True
            
        # Check for sequential patterns (like 123456 or abcdef)
        for i in range(len(hex_serial) - 3):
            if all(int(hex_serial[i+j], 16) == int(hex_serial[i], 16) + j for j in range(1, 4)):
                return True
                
        # Check if all digits are the same or very similar
        if len(set(hex_serial)) <= 3:
            return True
    
    # Check if the serial number is suspiciously small
    if serial < 10000:
        return True
        
    return False

def get_flaws(cert):
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
    if has_low_entropy_serial(cert):
        flaws.append("low_entropy_serial")

    return flaws

def main():
    files = [f for f in os.listdir(RAW_DIR) if f.endswith(".pem")]
    print(f"Found {len(files)} PEM files to label.")

    for fname in files:
        try:
            path = os.path.join(RAW_DIR, fname)
            with open(path, "rb") as f:
                pem_data = f.read()

            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            flaws = get_flaws(cert)

            labeled_json = {
                "pem": pem_data.decode(),
                "flaws": flaws
            }

            out_file = os.path.join(LABELED_DIR, f"{fname.replace('.pem','.json')}")
            with open(out_file, "w") as out:
                json.dump(labeled_json, out, indent=2)

            print(f"Labeled {fname}: {flaws}")

        except Exception as e:
            print(f"Failed {fname}: {e}")

if __name__ == "__main__":
    main()
