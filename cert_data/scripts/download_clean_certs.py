#!/usr/bin/env python3

"""
download_clean_certs.py - Downloads certificates that have no flaws

This script:
1. Reads through all labeled certificates in the labeled directory
2. Identifies certificates with no flaws
3. Saves them to a 'clean' directory for easy access
"""

import os
import json
import shutil
from pathlib import Path

# Directory paths
LABELED_DIR = "../labeled"
CLEAN_DIR = "../clean"

def download_clean_certs():
    """
    Extract and save certificates with no flaws to the clean directory
    """
    # Create the clean directory if it doesn't exist
    os.makedirs(CLEAN_DIR, exist_ok=True)
    
    # Initialize counters
    total_certs = 0
    clean_certs = 0
    
    # Iterate through all JSON files in the labeled directory
    for filename in os.listdir(LABELED_DIR):
        if not filename.endswith('.json'):
            continue
            
        total_certs += 1
        
        # Read the JSON file
        with open(os.path.join(LABELED_DIR, filename), 'r') as f:
            try:
                data = json.load(f)
                flaws = data.get('flaws', [])
                
                # Check if the certificate has no flaws
                if len(flaws) == 0:
                    clean_certs += 1
                    
                    # Extract the PEM data
                    pem_data = data.get('pem', '')
                    
                    if pem_data:
                        # Save the PEM data to a file in the clean directory
                        clean_filename = Path(filename).stem + '.pem'
                        clean_path = os.path.join(CLEAN_DIR, clean_filename)
                        
                        with open(clean_path, 'w') as clean_file:
                            clean_file.write(pem_data)
                        
                        print(f"Saved clean certificate: {clean_filename}")
                    else:
                        print(f"Warning: No PEM data found in {filename}")
                        
            except json.JSONDecodeError:
                print(f"Error decoding JSON in {filename}")
    
    # Print results
    print(f"\n=== Clean Certificate Download Results ===")
    print(f"Total certificates analyzed: {total_certs}")
    print(f"Clean certificates found and saved: {clean_certs}")
    print(f"Clean certificates saved to: {os.path.abspath(CLEAN_DIR)}")
    
    if clean_certs == 0:
        print("\nNo clean certificates were found. Make sure you've run label_certs.py first.")
    
if __name__ == "__main__":
    download_clean_certs()
