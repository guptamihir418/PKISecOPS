#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

# Define paths
BASE_DIR = Path('/Users/mihirgupta/Desktop/Projects/PKISecOPS')
SYNTHETIC_DIR = BASE_DIR / 'cert_data' / 'synthetic'
RAW_DIR = BASE_DIR / 'cert_data' / 'raw'

def copy_pem_files():
    """Copy all PEM files from synthetic directory to raw directory"""
    print(f"Copying PEM files from {SYNTHETIC_DIR} to {RAW_DIR}")
    
    # Count for reporting
    total_files = 0
    copied_files = 0
    
    # Walk through all subdirectories in the synthetic directory
    for root, dirs, files in os.walk(SYNTHETIC_DIR):
        for file in files:
            if file.endswith('.pem'):
                total_files += 1
                source_path = os.path.join(root, file)
                dest_path = os.path.join(RAW_DIR, file)
                
                try:
                    shutil.copy2(source_path, dest_path)
                    copied_files += 1
                    if copied_files % 100 == 0:
                        print(f"Copied {copied_files} files so far...")
                except Exception as e:
                    print(f"Error copying {source_path}: {e}")
    
    print(f"Finished copying {copied_files} out of {total_files} PEM files to {RAW_DIR}")

if __name__ == "__main__":
    copy_pem_files()
