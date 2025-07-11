#!/usr/bin/env python3

"""
analyze_labels.py - Analyzes the labeled certificates to count different flaw categories
and provides detailed information on flaw combinations
"""

import os
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Define paths
BASE_DIR = Path('/Users/mihirgupta/Desktop/Projects/PKISecOPS')
LABELED_DIR = BASE_DIR / 'cert_data' / 'labeled'
SYNTHETIC_DIR = BASE_DIR / 'cert_data' / 'synthetic'

def analyze_directory(directory_path):
    """Analyze certificates in the specified directory"""
    # Initialize counters
    total_certs = 0
    flaw_counter = Counter()
    certs_by_flaw_count = Counter()
    combinations = Counter()
    combinations_by_count = defaultdict(Counter)
    
    # Check if directory exists
    if not os.path.exists(directory_path):
        print(f"Directory not found: {directory_path}")
        return
    
    # Determine if we're analyzing JSON or PEM files
    is_json = any(f.endswith('.json') for f in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, f)))
    
    # Iterate through all files in the directory and subdirectories
    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            
            # Skip non-certificate files
            if is_json and not filename.endswith('.json'):
                continue
            elif not is_json and not filename.endswith('.pem'):
                continue
                
            total_certs += 1
            
            # Read the file
            try:
                if is_json:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        flaws = data.get('flaws', [])
                else:
                    # For PEM files in synthetic directory, infer flaws from directory structure
                    # Example: /synthetic/2_flaws/abc123.pem
                    parent_dir = os.path.basename(os.path.dirname(file_path))
                    if parent_dir.endswith('_flaws'):
                        # This is just a placeholder, actual flaws can't be determined from PEM filename alone
                        flaws = []
                    else:
                        flaws = []
                
                # Count the number of flaws per certificate
                flaw_count = len(flaws)
                certs_by_flaw_count[flaw_count] += 1
                
                # Count each type of flaw
                for flaw in flaws:
                    flaw_counter[flaw] += 1
                
                # Record the combination
                if flaws:
                    sorted_flaws = tuple(sorted(flaws))
                    combinations[sorted_flaws] += 1
                    combinations_by_count[flaw_count][sorted_flaws] += 1
                    
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
    
    return {
        'total_certs': total_certs,
        'flaw_counter': flaw_counter,
        'certs_by_flaw_count': certs_by_flaw_count,
        'combinations': combinations,
        'combinations_by_count': combinations_by_count
    }

def print_analysis_results(results, title):
    """Print analysis results in a formatted way"""
    total_certs = results['total_certs']
    flaw_counter = results['flaw_counter']
    certs_by_flaw_count = results['certs_by_flaw_count']
    combinations = results['combinations']
    combinations_by_count = results['combinations_by_count']
    
    print(f"\n{'=' * 20} {title} {'=' * 20}")
    print(f"Total certificates analyzed: {total_certs}")
    
    if total_certs == 0:
        print("No certificates found.")
        return
    
    print("\n--- Individual Flaw Distribution ---")
    for flaw, count in sorted(flaw_counter.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_certs) * 100
        print(f"{flaw}: {count} certificates ({percentage:.1f}%)")
    
    print("\n--- Certificates by Number of Flaws ---")
    for num_flaws, count in sorted(certs_by_flaw_count.items()):
        percentage = (count / total_certs) * 100
        print(f"Certificates with {num_flaws} flaws: {count} ({percentage:.1f}%)")
    
    # Calculate some interesting statistics
    certs_with_flaws = total_certs - certs_by_flaw_count[0]
    percentage_with_flaws = (certs_with_flaws / total_certs) * 100 if total_certs > 0 else 0
    
    print(f"\n--- Summary Statistics ---")
    print(f"Certificates with at least one flaw: {certs_with_flaws} ({percentage_with_flaws:.1f}%)")
    print(f"Certificates with no flaws: {certs_by_flaw_count[0]} ({100 - percentage_with_flaws:.1f}%)")
    
    # Print all flaw combinations by count
    print("\n--- Detailed Flaw Combinations ---")
    
    for flaw_count in sorted(combinations_by_count.keys()):
        print(f"\n  {flaw_count}-Flaw Combinations:")
        combos = combinations_by_count[flaw_count]
        
        if not combos:
            print(f"    No combinations with {flaw_count} flaws found.")
            continue
            
        for combo, count in sorted(combos.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_certs) * 100
            combo_str = ', '.join(combo) if combo else 'No flaws'
            print(f"    {combo_str}: {count} certificates ({percentage:.1f}%)")
    
    # Print top combinations overall
    print("\n--- Top 10 Flaw Combinations Overall ---")
    for combo, count in combinations.most_common(10):
        percentage = (count / total_certs) * 100
        combo_str = ', '.join(combo) if combo else 'No flaws'
        print(f"{combo_str}: {count} certificates ({percentage:.1f}%)")

def analyze_labels():
    """Main function to analyze certificate labels"""
    # Check command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == '--synthetic':
        print("Analyzing synthetic certificates...")
        results = analyze_directory(SYNTHETIC_DIR)
        print_analysis_results(results, "Synthetic Certificate Analysis")
    else:
        print("Analyzing labeled certificates...")
        results = analyze_directory(LABELED_DIR)
        print_analysis_results(results, "Labeled Certificate Analysis")
        
        # Also analyze synthetic if it exists
        if os.path.exists(SYNTHETIC_DIR):
            print("\nAlso analyzing synthetic certificates...")
            synthetic_results = analyze_directory(SYNTHETIC_DIR)
            print_analysis_results(synthetic_results, "Synthetic Certificate Analysis")

if __name__ == "__main__":
    analyze_labels()
