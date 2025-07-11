#!/usr/bin/env python3

"""
reduce_combinations.py - Reduces the number of certificates with specific flaw combinations
to a specified count by moving excess certificates to a backup directory.
"""

import os
import json
import shutil
import argparse
import random
from pathlib import Path
from collections import defaultdict, Counter

# Define paths
BASE_DIR = Path('/Users/mihirgupta/Desktop/Projects/PKISecOPS')
LABELED_DIR = BASE_DIR / 'cert_data' / 'labeled'
BACKUP_DIR = BASE_DIR / 'cert_data' / 'backup'

def ensure_dir(directory):
    """Ensure the directory exists"""
    os.makedirs(directory, exist_ok=True)

def extract_flaws_from_json(file_path):
    """Extract flaws from a JSON file"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            flaws = data.get('flaws', [])
            return tuple(sorted(flaws))
    except Exception as e:
        print(f"Error extracting flaws from {file_path}: {e}")
        return tuple()

def analyze_certificates(directory):
    """Analyze certificates and group them by flaw combination"""
    certs_by_combo = defaultdict(list)
    total_certs = 0
    
    # Check if directory exists
    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return certs_by_combo, total_certs
    
    # Iterate through all JSON files in the directory
    for filename in os.listdir(directory):
        if not filename.endswith('.json'):
            continue
            
        file_path = os.path.join(directory, filename)
        
        # Skip directories
        if os.path.isdir(file_path):
            continue
            
        total_certs += 1
        
        # Extract flaws directly from the JSON file
        flaws = extract_flaws_from_json(file_path)
        
        # Add to the appropriate combination group
        certs_by_combo[flaws].append(file_path)
    
    return certs_by_combo, total_certs

def reduce_combinations(directory, target_counts, dry_run=False, debug=False):
    """
    Reduce the number of certificates with specific flaw combinations
    
    Args:
        directory: Directory containing certificates
        target_counts: Dict mapping flaw combinations to target counts
        dry_run: If True, only print what would be done without moving files
    """
    # Create backup directory if not in dry run mode
    if not dry_run:
        ensure_dir(BACKUP_DIR)
    
    # Analyze certificates
    certs_by_combo, total_certs = analyze_certificates(directory)
    
    print(f"\nAnalyzed {total_certs} certificates in {directory}")
    print(f"Found {len(certs_by_combo)} unique flaw combinations")
    
    # Track files to move
    files_to_move = []
    
    # Debug: Print all combinations found
    if debug:
        print("\nDebug: All combinations found:")
        for c, files in sorted(certs_by_combo.items()):
            c_str = ', '.join(c) if c else 'No flaws'
            print(f"  {c_str}: {len(files)} certificates (tuple: {c})")
        print("\nDebug: Target combinations:")
        for c, count in target_counts.items():
            c_str = ', '.join(c) if c else 'No flaws'
            print(f"  {c_str}: target {count} (tuple: {c})")
    
    # Process each combination
    for combo, cert_files in sorted(certs_by_combo.items()):
        combo_str = ', '.join(combo) if combo else 'No flaws'
        current_count = len(cert_files)
        
        # Check if this combination needs reduction
        match_found = False
        target_combo = None
        
        # Look for exact match in target_counts
        for target_combo in target_counts.keys():
            if set(combo) == set(target_combo):
                match_found = True
                target = target_counts[target_combo]
                
                if debug:
                    print(f"\nDebug: Match found between {combo} and {target_combo}")
                
                if current_count > target:
                    # Randomly select files to keep
                    files_to_keep = random.sample(cert_files, target)
                    files_to_remove = [f for f in cert_files if f not in files_to_keep]
                    
                    print(f"\nReducing '{combo_str}' from {current_count} to {target} certificates")
                    print(f"  Moving {len(files_to_remove)} certificates to backup")
                    
                    files_to_move.extend(files_to_remove)
                else:
                    print(f"\nCombination '{combo_str}' has {current_count} certificates, which is <= target {target}")
                    print(f"  No reduction needed")
                break
        
        if not match_found:
            if debug and combo and any(f in combo for f in ['expired']):
                print(f"\nDebug: No match found for '{combo_str}' in target_counts")
                print(f"  Keys in target_counts: {list(target_counts.keys())}")
            else:
                print(f"\nCombination '{combo_str}' has {current_count} certificates")
                print(f"  No target specified, leaving unchanged")
    
    # Move files if not in dry run mode
    if not dry_run and files_to_move:
        print(f"\nMoving {len(files_to_move)} files to backup directory...")
        for file_path in files_to_move:
            filename = os.path.basename(file_path)
            dest_path = os.path.join(BACKUP_DIR, filename)
            
            try:
                shutil.move(file_path, dest_path)
                print(f"  Moved {filename}")
            except Exception as e:
                print(f"  Error moving {filename}: {e}")
    elif dry_run and files_to_move:
        print(f"\nDRY RUN: Would move {len(files_to_move)} files to backup directory")
    
    print("\nDone!")

def parse_combination(combo_str):
    """Parse a combination string into a tuple of flaws"""
    return tuple(sorted([s.strip() for s in combo_str.split(',') if s.strip()]))

def main():
    parser = argparse.ArgumentParser(description='Reduce the number of certificates with specific flaw combinations')
    parser.add_argument('--dry-run', action='store_true', help='Only print what would be done without moving files')
    parser.add_argument('--combo', action='append', default=[], 
                        help='Flaw combination to reduce in format "flaw1,flaw2:count" (can be specified multiple times)')
    parser.add_argument('--debug', action='store_true', help='Show debug information')
    
    # Check if labeled directory exists
    if not os.path.exists(LABELED_DIR):
        print(f"Error: Labeled directory not found at {LABELED_DIR}")
        print("This script requires the labeled directory to determine certificate flaws.")
        return
    
    args = parser.parse_args()
    
    # Parse target counts
    target_counts = {}
    for combo_spec in args.combo:
        if ':' not in combo_spec:
            print(f"Invalid combination specification: {combo_spec}")
            print("Format should be 'flaw1,flaw2:count'")
            continue
            
        combo_str, count_str = combo_spec.split(':', 1)
        try:
            count = int(count_str)
            if count < 0:
                raise ValueError("Count must be non-negative")
                
            combo = parse_combination(combo_str)
            target_counts[combo] = count
            print(f"Will reduce combination '{', '.join(combo) if combo else 'No flaws'}' to {count} certificates")
            
            # Debug: Print the exact tuple that will be used as a key
            if args.debug:
                print(f"Debug: Looking for tuple {combo} of type {type(combo)}")
        except ValueError as e:
            print(f"Invalid count in combination specification: {combo_spec}")
            print(f"Error: {e}")
    
    if not target_counts:
        print("No valid combination specifications provided")
        print("Example usage: python reduce_combinations.py --combo 'sha1_signature,short_key:100' --combo 'missing_SAN:50'")
        return
    
    # Reduce combinations
    reduce_combinations(str(LABELED_DIR), target_counts, args.dry_run, args.debug)

if __name__ == "__main__":
    main()
