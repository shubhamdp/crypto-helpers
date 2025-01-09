import subprocess

# List of files
files = [
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-01-Cert.der",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-01-Cert.pem",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-01-Key.der",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-01-Key.pem",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-02-Cert.der",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-02-Cert.pem",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-02-Key.der",
    "credentials/development/attestation/Matter-Development-DAC-FFF1-8001-Revoked-02-Key.pem",
    "credentials/development/attestation/Matter-Development-PAI-FFF1-noPID-CRL.der",
    "credentials/development/attestation/Matter-Development-PAI-FFF1-noPID-CRL.pem",
    "credentials/test/attestation/Chip-Test-DAC-FFF1-8001-Signed-By-Revoked-PAI-Cert.der",
    "credentials/test/attestation/Chip-Test-DAC-FFF1-8001-Signed-By-Revoked-PAI-Cert.pem",
    "credentials/test/attestation/Chip-Test-PAI-FFF1-noPID-Revoked-Cert.der",
    "credentials/test/attestation/Chip-Test-PAI-FFF1-noPID-Revoked-Cert.pem",
    "credentials/test/attestation/Chip-Test-PAA-FFF1-CRL.der",
    "credentials/test/attestation/Chip-Test-PAA-FFF1-CRL.pem",
]

def detect_file_type(file_name):
    """Detect if the file represents a certificate, key, or CRL based on markers in the name."""
    if "Cert" in file_name:
        return "x509"
    elif "Key" in file_name:
        return "ec"
    elif "CRL" in file_name:
        return "crl"
    return None

def dump_certificate(file_path, file_type, format_type):
    """Dump the certificate, key, or CRL content to text format."""
    try:
        result = subprocess.run(
            ["openssl", file_type, "-inform", format_type, "-in", file_path, "-text", "-noout"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error processing {file_path}: {e.stderr}")
        return None

def compare_files(der_file, pem_file):
    """Compare DER and PEM files."""
    file_type = detect_file_type(der_file)
    if not file_type:
        print(f"Unknown file type for {der_file}")
        return False
    
    der_content = dump_certificate(der_file, file_type, "DER")
    pem_content = dump_certificate(pem_file, file_type, "PEM")
    
    if der_content and pem_content and der_content == pem_content:
        print(f"PASS: {der_file} matches {pem_file}")
        return True
    else:
        print(f"FAIL: {der_file} does not match {pem_file}")
        return False

def main():
    # Create pairs of DER and PEM files
    pairs = {}
    for file in files:
        base_name = file.rsplit('.', 1)[0]
        extension = file.rsplit('.', 1)[-1]
        if base_name not in pairs:
            pairs[base_name] = {}
        pairs[base_name][extension] = file
    
    # Compare each DER and PEM pair
    for base_name, pair in pairs.items():
        if "der" in pair and "pem" in pair:
            compare_files(pair["der"], pair["pem"])
        else:
            print(f"Missing DER or PEM file for {base_name}")

if __name__ == "__main__":
    main()
