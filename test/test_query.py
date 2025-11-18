"""
Test Query Script

test_query.py
"""
import pytest
import query
import ssl


def test_query_load_certificate():
    """
    Test Query Script with loading a single certificate.
    """
    certificate_record = query.load_certificate(
        ssl.create_default_context(),
        "mail.ru"
    )
    print(certificate_record)


def test_query_load_certificates():
    """
    Test Query Script with loading multiple certificates at once and get the RSA public keys of available certificates.
    """
    domains_list = [
        "google.com",
        "mail.ru",
        "microsoft.com",
        "facebook.com",
        "cloudflare.com",
        "amazonaws.com",
        "googleapis.com",
        "dzen.ru",
        "youtube.com",
        "apple.com"
    ]
    certificate_records = query.load_certificates(domains_list)
    print(certificate_records)
