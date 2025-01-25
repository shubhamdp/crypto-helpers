#! /usr/bin/env python3

import click
import argparse
import sys

from loader import load_key

def extract_ec_key_bytes(key_data):
    private_key = load_key(key_data)

    # Extract private key bytes (32 bytes for P-256)
    private_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder="big")
    
    # Extract public key bytes (65 bytes: 1-byte prefix + 32-byte X + 32-byte Y)
    public_numbers = private_key.public_key().public_numbers()
    public_bytes = b"\x04" + public_numbers.x.to_bytes(32, byteorder="big") + public_numbers.y.to_bytes(32, byteorder="big")

    return private_bytes.hex(), public_bytes.hex()


# write a click cli which takes key as a file
@click.command()
@click.argument('key', type=click.File('rb'))
def main(key):
    key_data = key.read()
    private_hex, public_hex = extract_ec_key_bytes(key_data)
    print("Private key: ", private_hex)
    print("Public  key: ", public_hex)

if __name__ == "__main__":
    main()
