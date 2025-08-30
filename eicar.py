#!/usr/bin/env python3
"""
EICAR Test File

The EICAR Standard Anti-Virus Test File is a special test file 
that all antivirus programs should detect as malicious, even though
it's completely harmless. It's used to test that antivirus software
is working correctly without using real malware.

For more information: http://www.eicar.org/86-0-intended-use.html
"""

import sys
import os

# The EICAR test string
EICAR_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def create_eicar_file(output_path=None):
    """
    Create an EICAR test file at the specified path,
    or in the current directory if not specified.
    
    Args:
        output_path (str, optional): Path where to create the file. 
                                    Defaults to eicar.txt in current directory.
    
    Returns:
        str: Path to the created file
    """
    if output_path is None:
        output_path = os.path.join(os.getcwd(), "eicar.txt")
    
    try:
        with open(output_path, 'w') as f:
            f.write(EICAR_STRING)
        print(f"EICAR test file created at: {output_path}")
        return output_path
    except IOError as e:
        print(f"Error creating EICAR file: {e}", file=sys.stderr)
        return None

def print_eicar():
    """Print the EICAR test string to the console"""
    print("EICAR test string:")
    print(EICAR_STRING)
    print("\nLength:", len(EICAR_STRING), "bytes")

if __name__ == "__main__":
    # Show warning and info
    print("\nWARNING: This script creates the EICAR test file.")
    print("It is NOT malware but will trigger antivirus detection.")
    print("It's used to verify that antivirus software is working correctly.\n")
    
    # Print the EICAR string
    print_eicar()
    
    # Ask if user wants to create the file
    answer = input("\nDo you want to create the EICAR test file? (y/n): ")
    if answer.lower() == 'y':
        path = input("Enter output path (press Enter for default eicar.txt): ").strip()
        if not path:
            path = None
        create_eicar_file(path)
    else:
        print("EICAR test file was not created.")