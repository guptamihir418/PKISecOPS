#!/usr/bin/env python3

import os
import json
import hashlib
import sys
import subprocess
import itertools
from itertools import combinations
from pathlib import Path
import tempfile

# Define paths
BASE_DIR = Path('/Users/mihirgupta/Desktop/Projects/PKISecOPS')
SYNTHETIC_DIR = BASE_DIR / 'cert_data' / 'synthetic'

# Create a temporary directory that will be automatically cleaned up
TEMP_DIR = Path(tempfile.mkdtemp(prefix="synthetic_certs_"))

# Define flaw weights (higher = more common)
FLAW_WEIGHTS = {
    'sha1_signature': 10,  # Most common
    'short_key': 7,
    'missing_SAN': 6,
    'low_entropy': 2   # Least common
}

# Define total certificates to generate
TOTAL_CERTS = 8000

def ensure_dir(directory):
    """Ensure the directory exists"""
    os.makedirs(directory, exist_ok=True)

def generate_cert_id(cert_pem):
    """Generate a unique ID for the certificate based on its PEM content"""
    return hashlib.sha256(cert_pem.encode('utf-8')).hexdigest()

def generate_certificate(subject_name, index, flaws):
    """Generate a certificate with the specified flaws"""
    # Convert tuple to list if needed
    if isinstance(flaws, tuple):
        flaws = list(flaws)
    
    # Create temporary files for the key and certificate
    key_file = TEMP_DIR / f"key_{index}.pem"
    cert_file = TEMP_DIR / f"cert_{index}.pem"
    config_file = TEMP_DIR / f"openssl_{index}.cnf"
    
    try:
        # Determine key size based on flaws
        key_size = '1024' if 'short_key' in flaws else '2048'
        
        # Determine signature algorithm based on flaws
        sig_alg = '-sha1' if 'sha1_signature' in flaws else '-sha256'
        
        # Determine if SAN should be included
        include_san = 'missing_SAN' not in flaws
        
        # Create a basic OpenSSL config file
        with open(config_file, 'w') as f:
            f.write(f"""\
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = {subject_name}
O = PKISecOPS Synthetic Certs
OU = Security Research
C = US
""")
        
        # Generate private key
        subprocess.run([
            'openssl', 'genrsa',
            '-out', str(key_file),
            key_size
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # For certificates with 3 flaws including sha1_signature, short_key, and missing_SAN,
        # use a simpler approach that's known to work
        if set(flaws) == set(['sha1_signature', 'short_key', 'missing_SAN']):
            # Generate a basic certificate without extensions
            cert_cmd = [
                'openssl', 'req',
                '-new',
                '-x509',
                '-sha1',  # Force SHA-1
                '-key', str(key_file),
                '-out', str(cert_file),
                '-days', '365',
                '-subj', f"/CN={subject_name}/O=PKISecOPS Synthetic Certs/OU=Security Research/C=US"
            ]
        else:
            # Standard approach for other combinations
            cert_cmd = [
                'openssl', 'req',
                '-new',
                '-x509',
                sig_alg,
                '-key', str(key_file),
                '-out', str(cert_file),
                '-days', '365',
                '-config', str(config_file)
            ]
            
            # Add SAN extension if needed
            if include_san:
                cert_cmd.extend([
                    '-addext', f"subjectAltName=DNS:{subject_name},DNS:www.{subject_name}"
                ])
        
        # Add low entropy serial if needed
        if 'low_entropy' in flaws:
            cert_cmd.extend(['-set_serial', '1111111111111111'])
        
        # Generate certificate
        subprocess.run(cert_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Read the certificate
        with open(cert_file, 'r') as f:
            cert_pem = f.read()
        
        return cert_pem
    
    except Exception as e:
        print(f"Error generating certificate with flaws {flaws}: {e}")
        # Return None to indicate failure
        return None
    
    finally:
        # Clean up temporary files
        for file in [key_file, cert_file, config_file]:
            if file.exists():
                try:
                    file.unlink()
                except:
                    pass

def save_certificate(cert_pem, flaws, output_dir):
    """Save a certificate as a PEM file"""
    # Convert tuple to list if needed
    if isinstance(flaws, tuple):
        flaws = list(flaws)
    # If flaws is a string, split it by underscore to get individual flaws
    elif isinstance(flaws, str):
        flaws = flaws.split('_')
        
    # Generate a unique ID for this certificate
    cert_id = generate_cert_id(cert_pem)
    
    # Create subdirectory based on number of flaws
    flaw_count = len(flaws)
    flaw_dir = output_dir / f"{flaw_count}_flaws"
    ensure_dir(flaw_dir)
    
    # Save as PEM file directly in the flaws count directory
    pem_path = flaw_dir / f"{cert_id}.pem"
    with open(pem_path, 'w') as f:
        f.write(cert_pem)
    
    return cert_id

def calculate_distribution(total_certs):
    """Calculate the distribution of certificates across flaw combinations"""
    all_flaws = list(FLAW_WEIGHTS.keys())
    
    # Get all possible combinations of 2, 3, and 4 flaws
    combos_2 = list(combinations(all_flaws, 2))
    combos_3 = list(combinations(all_flaws, 3))
    combos_4 = [tuple(all_flaws)]  # Only one combination of all 4 flaws
    
    # Define the distribution percentages for each flaw count category
    # Allocate more certificates to 2-flaw combinations, fewer to 4-flaw
    distribution_percentages = {
        2: 0.50,  # 50% of certificates have 2 flaws
    }
    
    # Define the percentage of certificates for each category
    certs_per_category = {
        2: int(0.5 * total_certs),  # 50% have 2 flaws
        3: int(0.4 * total_certs),  # 40% have 3 flaws
        4: int(0.1 * total_certs)   # 10% have 4 flaws
    }
    
    # Ensure we allocate exactly the right number of certificates
    allocated = sum(certs_per_category.values())
    if allocated < total_certs:
        certs_per_category[2] += (total_certs - allocated)
    
    # These are already defined above
    # combos_2 = list(combinations(all_flaws, 2))
    # combos_3 = list(combinations(all_flaws, 3))
    # combos_4 = [tuple(all_flaws)]
    
    # Calculate weights for each combination
    combo_weights = {}
    
    # For 2-flaw combinations
    for combo in combos_2:
        # Reduce weight if low_entropy is in the combo
        if 'low_entropy' in combo:
            weight = FLAW_WEIGHTS[combo[0]] * FLAW_WEIGHTS[combo[1]] * 0.5
        else:
            weight = FLAW_WEIGHTS[combo[0]] * FLAW_WEIGHTS[combo[1]]
        combo_weights[combo] = weight
    
    # For 3-flaw combinations
    for combo in combos_3:
        # Reduce weight if low_entropy is in the combo
        if 'low_entropy' in combo:
            weight = FLAW_WEIGHTS[combo[0]] * FLAW_WEIGHTS[combo[1]] * FLAW_WEIGHTS[combo[2]] * 0.5
        else:
            weight = FLAW_WEIGHTS[combo[0]] * FLAW_WEIGHTS[combo[1]] * FLAW_WEIGHTS[combo[2]]
        combo_weights[combo] = weight
    
    # For 4-flaw combination (only one)
    combo_weights[combos_4[0]] = 1  # Just use 1 since there's only one combo
    
    # Organize by number of flaws
    distribution = {
        '2_flaws': {},
        '3_flaws': {},
        '4_flaws': {}
    }
    
    # Process each category (2, 3, 4 flaws)
    for flaw_count, category_total in certs_per_category.items():
        if flaw_count == 2:
            combos = combos_2
        elif flaw_count == 3:
            combos = combos_3
        else:  # flaw_count == 4
            combos = combos_4
        
        # Get weights for this category
        category_weights = {combo: weight for combo, weight in combo_weights.items() if len(combo) == flaw_count}
        total_category_weight = sum(category_weights.values())
        
        # Calculate certificates for each combo in this category
        category_counts = {}
        allocated = 0
        
        for combo in combos:
            weight = category_weights[combo]
            count = int((weight / total_category_weight) * category_total)
            combo_name = "_".join(combo)  # Convert tuple to string for key
            category_counts[combo_name] = count
            allocated += count
        
        # Adjust to ensure we allocate exactly the right number for this category
        if allocated < category_total:
            # Find the combo with highest weight in this category
            highest_weight_combo = max([(combo, category_weights[combo]) for combo in combos], 
                                      key=lambda x: x[1])[0]
            highest_name = "_".join(highest_weight_combo)
            category_counts[highest_name] += (category_total - allocated)
        
        # Add to distribution
        distribution[f'{flaw_count}_flaws'] = category_counts
    
    return distribution

def generate_synthetic_dataset():
    """Generate a synthetic dataset of certificates with combinations of flaws"""
    # Create output directory
    output_dir = SYNTHETIC_DIR
    ensure_dir(output_dir)
    
    # Calculate distribution of certificates
    total_certs = 8000
    distribution = calculate_distribution(total_certs)
    
    print(f"Generating {total_certs} synthetic certificates with combinations of flaws...\n")
    
    # Calculate total certificates per category
    two_flaws_total = sum(distribution['2_flaws'].values())
    three_flaws_total = sum(distribution['3_flaws'].values())
    four_flaws_total = sum(distribution['4_flaws'].values())
    
    cert_index = 0
    successful_certs = 0
    failed_certs = 0
    
    # Generate certificates with 2 flaws
    print("Generating certificates with 2 flaws:")
    for combo, count in distribution['2_flaws'].items():
        print(f"  Generating {count} certificates with flaws: {combo}")
        successful_for_combo = 0
        
        for i in range(count):
            # Generate a unique subject name
            subject_name = f"synthetic-2flaws-{combo}-{i + 1}.example.com"
            
            # Generate certificate with the specified flaws
            cert_pem = generate_certificate(subject_name, cert_index, combo)
            
            if cert_pem:
                # Save certificate
                save_certificate(cert_pem, combo, output_dir)
                successful_certs += 1
                successful_for_combo += 1
            else:
                failed_certs += 1
            
            cert_index += 1
            
            if (successful_for_combo % 100 == 0 and successful_for_combo > 0) or successful_for_combo == count:
                print(f"    Generated {successful_for_combo}/{count} certificates with {combo}")
    
    print(f"Total certificates with 2 flaws: {two_flaws_total}\n")
    
    # Generate certificates with 3 flaws
    print("Generating certificates with 3 flaws:")
    for combo, count in distribution['3_flaws'].items():
        print(f"  Generating {count} certificates with flaws: {combo}")
        successful_for_combo = 0
        
        for i in range(count):
            # Generate a unique subject name
            subject_name = f"synthetic-3flaws-{combo}-{i + 1}.example.com"
            
            # Generate certificate with the specified flaws
            cert_pem = generate_certificate(subject_name, cert_index, combo)
            
            if cert_pem:
                # Save certificate
                save_certificate(cert_pem, combo, output_dir)
                successful_certs += 1
                successful_for_combo += 1
            else:
                failed_certs += 1
            
            cert_index += 1
            
            if (successful_for_combo % 100 == 0 and successful_for_combo > 0) or successful_for_combo == count:
                print(f"    Generated {successful_for_combo}/{count} certificates with {combo}")
    
    print(f"Total certificates with 3 flaws: {three_flaws_total}\n")
    
    # Generate certificates with 4 flaws
    print("Generating certificates with 4 flaws:")
    for combo, count in distribution['4_flaws'].items():
        print(f"  Generating {count} certificates with flaws: {combo}")
        successful_for_combo = 0
        
        for i in range(count):
            # Generate a unique subject name
            subject_name = f"synthetic-4flaws-{combo}-{i + 1}.example.com"
            
            # Generate certificate with the specified flaws
            cert_pem = generate_certificate(subject_name, cert_index, combo)
            
            if cert_pem:
                # Save certificate
                save_certificate(cert_pem, combo, output_dir)
                successful_certs += 1
                successful_for_combo += 1
            else:
                failed_certs += 1
            
            cert_index += 1
            
            if (successful_for_combo % 100 == 0 and successful_for_combo > 0) or successful_for_combo == count:
                print(f"    Generated {successful_for_combo}/{count} certificates with {combo}")
    
    print(f"Total certificates with 4 flaws: {four_flaws_total}\n")
    
    print(f"Total certificates attempted: {cert_index}")
    print(f"Successfully generated: {successful_certs}")
    print(f"Failed to generate: {failed_certs}")
    
    return successful_certs

def main():
    generate_synthetic_dataset()
    print(f"\nDone! Certificates saved to synthetic")

if __name__ == "__main__":
    main()
