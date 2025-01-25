#! /usr/bin/env python3

from cryptography import x509
from cryptography.hazmat.primitives import serialization

def load_cert(cert: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(cert)
    except:
        pass  # fall back to DER

    return x509.load_der_x509_certificate(cert)


def load_cert_from_file(cert_file: str) -> x509.Certificate:
    with open(cert_file, "rb") as f:
        return load_cert(f.read())


def load_key(key: bytes):
    try:
        return serialization.load_pem_private_key(key, password=None)
    except:
        pass  # fall back to DER

    return serialization.load_der_private_key(key, password=None)


def load_key_from_file(key_file: str):
    with open(key_file, "rb") as f:
        return load_key(f.read())


def load_csr(csr: bytes) -> x509.CertificateSigningRequest:
    try:
        return x509.load_pem_x509_csr(csr)
    except:
        pass  # fall back to DER

    return x509.load_der_x509_csr(csr)


def load_csr_from_file(csr_file: str) -> x509.CertificateSigningRequest:
    with open(csr_file, "rb") as f:
        return load_csr(f.read())


def load_crl(crl: bytes) -> x509.CertificateRevocationList:
    try:
        return x509.load_pem_x509_crl(crl)
    except:
        pass  # fall back to DER

    return x509.load_der_x509_crl(crl)


def load_crl_from_file(crl_file: str) -> x509.CertificateRevocationList:
    with open(crl_file, "rb") as f:
        return load_crl(f.read())
