#!/usr/bin/env python3

import datetime
from typing import List, Optional, Tuple, Union
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import CertificateRevocationList, RevokedCertificate, Name
import os

class CRLGenerator:
    def __init__(self, issuer_cert_path: str, issuer_key_path: str):
        """Initialize CRL Generator with issuer certificate and private key."""
        self.issuer_cert = self._load_certificate(issuer_cert_path)
        self.issuer_key = self._load_private_key(issuer_key_path)
        
    def _load_certificate(self, cert_path: str) -> x509.Certificate:
        """Load a certificate from PEM or DER file."""
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            try:
                return x509.load_pem_x509_certificate(cert_data)
            except ValueError:
                return x509.load_der_x509_certificate(cert_data)

    def _load_private_key(self, key_path: str) -> rsa.RSAPrivateKey:
        """Load a private key from PEM or DER file."""
        with open(key_path, 'rb') as f:
            key_data = f.read()
            try:
                return serialization.load_pem_private_key(key_data, password=None)
            except ValueError:
                return serialization.load_der_private_key(key_data, password=None)

    def _load_crl(self, crl_path: str) -> Optional[CertificateRevocationList]:
        """Load a CRL from PEM or DER file."""
        if not os.path.exists(crl_path):
            return None
        
        with open(crl_path, 'rb') as f:
            crl_data = f.read()
            try:
                return x509.load_pem_x509_crl(crl_data)
            except ValueError:
                return x509.load_der_x509_crl(crl_data)

    def _get_crl_number(self, crl: Optional[CertificateRevocationList]) -> int:
        """Get the CRL number from an existing CRL or return 0."""
        if crl is None:
            return 0
        
        try:
            crl_number_ext = crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER)
            return crl_number_ext.value.crl_number + 1
        except x509.ExtensionNotFound:
            return 0

    def _get_existing_serial_numbers(self, crl: Optional[CertificateRevocationList]) -> set:
        """Get set of serial numbers from existing CRL."""
        if crl is None:
            return set()
        return {cert.serial_number for cert in crl}

    def generate_crl(self, 
                    revoked_certs: List[Tuple[x509.Certificate, datetime.datetime, Optional[x509.Name]]],
                    existing_crl_path: Optional[str] = None,
                    next_update_days: int = 36525,
                    include_issuing_distribution_point: bool = False,
                    distribution_point_url: Optional[str] = None) -> CertificateRevocationList:
        """
        Generate or update a CRL with the given revoked certificates.
        
        Args:
            revoked_certs: List of tuples containing (certificate, revocation_date, certificate_issuer)
                          where certificate_issuer is optional and can be None
            existing_crl_path: Path to existing CRL to update (optional)
            next_update_days: Number of days until next update
            include_issuing_distribution_point: Whether to include IDP extension
            distribution_point_url: URL for the distribution point
        """
        # Load existing CRL if provided
        existing_crl = None
        if existing_crl_path:
            existing_crl = self._load_crl(existing_crl_path)
        
        # Get set of existing serial numbers
        existing_serials = self._get_existing_serial_numbers(existing_crl)
        
        builder = x509.CertificateRevocationListBuilder()
        
        # Set the issuer
        builder = builder.issuer_name(self.issuer_cert.subject)
        
        # Set validity period
        last_update = datetime.datetime.utcnow()
        next_update = last_update + datetime.timedelta(days=next_update_days)
        builder = builder.last_update(last_update)
        builder = builder.next_update(next_update)
        
        # Add Authority Key Identifier extension
        try:
            aki = self.issuer_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(aki.value),
                critical=False
            )
        except x509.ExtensionNotFound:
            pass
        
        # Get next CRL number
        crl_number = self._get_crl_number(existing_crl)
        builder = builder.add_extension(
            x509.CRLNumber(crl_number),
            critical=False
        )
        
        # Add Issuing Distribution Point if requested
        if include_issuing_distribution_point and distribution_point_url:
            builder = builder.add_extension(
                x509.IssuingDistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(distribution_point_url)],
                    relative_name=None,
                    only_contains_user_certs=False,
                    only_contains_ca_certs=False,
                    only_some_reasons=None,
                    indirect_crl=False,
                    only_contains_attribute_certs=False
                ),
                critical=True
            )
        
        # Add existing revoked certificates if updating
        if existing_crl:
            for revoked_cert in existing_crl:
                builder = builder.add_revoked_certificate(revoked_cert)
        
        # Add new revoked certificates
        for cert, revocation_date, cert_issuer in revoked_certs:
            # Skip if certificate is already in the CRL
            if cert.serial_number in existing_serials:
                print(f"Warning: Certificate with serial number {cert.serial_number} is already in the CRL. Skipping.")
                continue
                
            revoked_builder = x509.RevokedCertificateBuilder()\
                .serial_number(cert.serial_number)\
                .revocation_date(revocation_date)
            
            # Add Certificate Issuer extension if provided
            if cert_issuer is not None:
                revoked_builder = revoked_builder.add_extension(
                    x509.CertificateIssuer([x509.DirectoryName(cert_issuer)]),
                    critical=True
                )
            
            revoked_cert = revoked_builder.build()
            builder = builder.add_revoked_certificate(revoked_cert)
            existing_serials.add(cert.serial_number)  # Add to set to prevent duplicates in current batch
        
        # Sign the CRL
        return builder.sign(
            private_key=self.issuer_key,
            algorithm=hashes.SHA256()
        )

    def save_crl(self, crl: CertificateRevocationList, output_path: str):
        with open(output_path, 'wb') as f:
            f.write(crl.public_bytes(encoding=serialization.Encoding.PEM))
        
        with open(output_path.replace('.pem', '.der'), 'wb') as f:
            f.write(crl.public_bytes(encoding=serialization.Encoding.DER))

def main():
    # Example usage
    issuer_cert_path = "Matter-Development-PAI-FFF1-Delegated-CRL-Signer-Cert.pem"
    issuer_key_path = "Matter-Development-PAI-FFF1-Delegated-CRL-Signer-Key.pem"
    revoked_cert_path1 = "Matter-Development-DAC-FFF1-8001-Revoked-01-Cert.pem"
    revoked_cert_path2 = "Matter-Development-DAC-FFF1-8001-Revoked-02-Cert.pem"
    revoked_cert_path3 = "Matter-Development-DAC-FFF1-8001-Revoked-03-Cert.pem"
    existing_crl_path = "Matter-Development-PAI-FFF1-noPID-Delegated-CRL-One-CertificateIssuer-Entry-Ext.pem"
    
    # Create CRL generator
    generator = CRLGenerator(issuer_cert_path, issuer_key_path) # This is delegated crl signer
    
    # Load revoked certificate
    revoked_cert1 = generator._load_certificate(revoked_cert_path1)
    revoked_cert2 = generator._load_certificate(revoked_cert_path2)
    revoked_cert3 = generator._load_certificate(revoked_cert_path3)
    revocation_date = datetime.datetime.utcnow()
    
    # Example with Certificate Issuer extension
    alt_issuer_name = revoked_cert1.issuer
    
    # Generate CRL with Certificate Issuer extension, updating existing CRL if it exists
    crl = generator.generate_crl(
        revoked_certs=[
            (revoked_cert1, revocation_date, revoked_cert1.issuer),
            (revoked_cert2, revocation_date, None),
            (revoked_cert3, revocation_date, None)
        ],
        existing_crl_path=existing_crl_path,
        # next_update_days=365,
        # include_issuing_distribution_point=True,
        # distribution_point_url="https://example.com/crl"
    )
    
    # Save updated CRL in both formats
    generator.save_crl(crl, existing_crl_path)

if __name__ == "__main__":
    main()
