#!/usr/bin/env python3
# Copyright 2024 Espressif Systems (Shanghai) PTE LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import uuid
import click
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))
import MatterOID  # noqa: E402 isort:skip

VALID_DAYS = 365 * 100

def load_cert(cert):
    try:
        return x509.load_pem_x509_certificate(cert)
    except:
        pass  # fall back to DER

    return x509.load_der_x509_certificate(cert)

def load_key(key):
    try:
        return serialization.load_pem_private_key(key, password=None)
    except:
        pass  # fall back to DER

    return serialization.load_der_private_key(key, password=None)

def load_csr(csr):
    try:
        return x509.load_pem_x509_csr(csr)
    except:
        pass  # fall back to DER

    return x509.load_der_x509_csr(csr)

# I think we need a constructor or a fn to set the ca cert, ca key, ca vid, ca pid
# also, we should have some functionality which would self generate the csr and key
# For generating self signed certificates, we need to pass in the ca key but not the ca cert
# so I guess, based on the values provided in the constructor should be enough to
# predict what we should do

class MatterCertGenerator:
    def __init__(self, ca_key: bytes, ca_cert: Optional[bytes] = None, ca_vid: Optional[str] = None, ca_pid: Optional[str] = None):
        self.ca_cert = load_cert(ca_cert) if ca_cert else None
        self.ca_key = load_key(ca_key) if ca_key else None

        self.ca_vid = str(ca_vid)
        self.ca_pid = str(ca_pid)

    def set_vid(self, vid):
        self.ca_vid = str(vid)
    
    def set_pid(self, pid):
        self.ca_pid = str(pid)
    
    def set_ca_cert(self, ca_cert: bytes):
        self.ca_cert = load_cert(ca_cert)
        self.ca_vid = self.extract_vid(self.ca_cert)
        self.ca_pid = self.extract_pid(self.ca_cert)
    
    def set_ca_key(self, ca_key: bytes):
        self.ca_key = load_key(ca_key)

    def extract_matter_rdn(self, cert, oid):
        try:
            return cert.subject.get_attributes_for_oid(oid)[0].value
        except IndexError:
            return None

    def extract_pid(self, cert):
        return self.extract_matter_rdn(cert, MatterOID.PRODUCT_ID)

    def extract_vid(self, cert):
        return self.extract_matter_rdn(cert, MatterOID.VENDOR_ID)

    def generate_dac(self, csr: bytes, cn: Optional[str] = None):
        csr = load_csr(csr)

        x509_attrs = []
        if cn:
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        else :
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, '{}'.format(uuid.uuid4())))
        x509_attrs.append(x509.NameAttribute(MatterOID.VENDOR_ID, self.ca_vid))
        x509_attrs.append(x509.NameAttribute(MatterOID.PRODUCT_ID, self.ca_pid))
        cert_subject = x509.Name(x509_attrs)

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(cert_subject)
        cert = cert.issuer_name(self.ca_cert.subject)
        cert = cert.public_key(csr.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=VALID_DAYS))
        cert = cert.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=False, crl_sign=False,
                                                encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()), critical=False)
        cert = cert.sign(self.ca_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)

    def generate_pai(self, csr: bytes, cn: Optional[str] = None):
        csr = load_csr(csr)

        x509_attrs = []
        if cn:
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        else :
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, '{}'.format(uuid.uuid4())))
        x509_attrs.append(x509.NameAttribute(MatterOID.VENDOR_ID, self.ca_vid))
        if self.ca_pid:
            x509_attrs.append(x509.NameAttribute(MatterOID.PRODUCT_ID, self.ca_pid))
        cert_subject = x509.Name(x509_attrs)

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(cert_subject)
        cert = cert.issuer_name(self.ca_cert.subject)
        cert = cert.public_key(csr.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=VALID_DAYS))
        cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()), critical=False)
        cert = cert.sign(self.ca_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)

    # Its a self signed one
    def generate_paa(self, csr: bytes, cn: Optional[str] = None):
        csr = load_csr(csr)

        x509_attrs = []
        if cn:
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        else :
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, '{}'.format(uuid.uuid4())))
        if self.ca_vid:
            x509_attrs.append(x509.NameAttribute(MatterOID.VENDOR_ID, self.ca_vid))
        cert_subject = x509.Name(x509_attrs)

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(cert_subject)
        cert = cert.issuer_name(cert_subject)
        cert = cert.public_key(csr.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=VALID_DAYS))
        cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(csr.public_key()), critical=False)
        cert = cert.sign(self.ca_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)

    def generate_paa_delegated_crl_signer(self, csr: bytes, cn: Optional[str] = None):
        csr = load_csr(csr)

        x509_attrs = []
        if cn:
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        if self.ca_vid:
            x509_attrs.append(x509.NameAttribute(MatterOID.PRODUCT_ID, self.ca_vid))
        cert_subject = x509.Name(x509_attrs)

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(cert_subject)
        cert = cert.issuer_name(self.ca_cert.subject)
        cert = cert.public_key(csr.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=VALID_DAYS))
        cert = cert.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=False, crl_sign=True,
                                                encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()), critical=False)
        cert = cert.sign(self.ca_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)

    def generate_pai_delegated_crl_signer(self, csr: bytes, cn: Optional[str] = None): 
        csr = load_csr(csr)

        x509_attrs = []
        if cn:
            x509_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        if self.ca_vid:
            x509_attrs.append(x509.NameAttribute(MatterOID.PRODUCT_ID, self.ca_vid))
        if self.ca_pid:
            x509_attrs.append(x509.NameAttribute(MatterOID.PRODUCT_ID, self.ca_pid))
        cert_subject = x509.Name(x509_attrs)

        cert = x509.CertificateBuilder()
        cert = cert.subject_name(cert_subject)
        cert = cert.issuer_name(self.ca_cert.subject)
        cert = cert.public_key(csr.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=VALID_DAYS))
        cert = cert.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        cert = cert.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=False, crl_sign=True,
                                                encipher_only=False, decipher_only=False), critical=True)
        cert = cert.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        cert = cert.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()), critical=False)
        cert = cert.sign(self.ca_key, hashes.SHA256())

        return cert.public_bytes(serialization.Encoding.PEM)


def generate_private_key():
    """
    Generate an EC P-256 private key suitable for Matter device attestation.
    
    Returns:
        bytes: PEM-encoded private key
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def generate_csr(private_bytes: bytes):
    """
    Generate a Certificate Signing Request (CSR) for Matter device.
    
    Args:
        private_key_pem: PEM-encoded private key

    Returns:
        bytes: PEM-encoded CSR
    """
    # Load the private key
    private_key = load_key(private_bytes)

    # Create CSR builder with Matter-specific attributes
    builder = x509.CertificateSigningRequestBuilder()
    
    # Set the subject with required Matter attributes
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'CSR'),
    ])
    
    builder = builder.subject_name(subject)

    # Sign the CSR with the private key
    csr = builder.sign(
        private_key,
        hashes.SHA256()
    )

    # Return the CSR in PEM format
    return csr.public_bytes(serialization.Encoding.PEM)

# Helper functions below
def generate_csr_and_key():
    private_key = generate_private_key()
    csr = generate_csr(private_key)
    return private_key, csr

def generate_paa(vid, pid, cn: str):
    private_key = generate_private_key()
    csr = generate_csr(private_key)
    return {
        'paa_cert': MatterCertGenerator(private_key, None, vid, pid).generate_paa(csr, cn),
        'paa_key': private_key
    }

def generate_pai(ca_cert, ca_key, vid, pid, cn: str):
    private_key = generate_private_key()
    csr = generate_csr(private_key)
    return {
        'paa_cert': ca_cert,
        'pai_cert': MatterCertGenerator(ca_key, ca_cert, vid, pid).generate_pai(csr, cn),
        'pai_key': private_key
    }

def generate_dac(ca_cert, ca_key, vid, pid, cn: str):
    private_key = generate_private_key()
    csr = generate_csr(private_key)
    return {
        'pai_cert': ca_cert,
        'dac_cert': MatterCertGenerator(ca_key, ca_cert, vid, pid).generate_dac(csr, cn),
        'dac_key': private_key
    }

def generate_complete_chain(vid: str, pid: str, cn: str):
    paa = generate_paa(vid, pid, cn + " paa")
    pai = generate_pai(paa['paa_cert'], paa['paa_key'], vid, pid, cn + " pai")
    dac = generate_dac(pai['pai_cert'], pai['pai_key'], vid, pid, cn + " dac")
    return {
        'paa_cert': paa['paa_cert'].decode('utf-8'),
        'pai_cert': pai['pai_cert'].decode('utf-8'),
        'dac_cert': dac['dac_cert'].decode('utf-8'),
        'paa_key': paa['paa_key'].decode('utf-8'),
        'pai_key': pai['pai_key'].decode('utf-8'),
        'dac_key': dac['dac_key'].decode('utf-8'),
    }

def generate_paa_delegated_crl_signer(ca_cert, ca_key, vid, pid, cn: str):
    private_key = generate_private_key()
    csr = generate_csr(private_key)
    return {
        'paa_cert': ca_cert,
        'paa_delegated_crl_signer_key': private_key,
        'paa_delegated_crl_signer': MatterCertGenerator(ca_key, ca_cert, vid, pid).generate_paa_delegated_crl_signer(csr, cn)
    }

def generate_pai_delegated_crl_signer(ca_cert, ca_key, vid, pid, cn: str):
    private_key = generate_private_key()
    csr = generate_csr(private_key)
    return {
        'pai_cert': ca_cert,
        'pai_delegated_crl_signer_key': private_key,
        'pai_delegated_crl_signer': MatterCertGenerator(ca_key, ca_cert, vid, pid).generate_pai_delegated_crl_signer(csr, cn)
    }   

if __name__ == '__main__':
    main()
