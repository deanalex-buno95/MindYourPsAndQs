"""
Test Query Script

test_query.py
"""
from pprint import pprint
import asyncio
import pytest
import query
import ssl


@pytest.mark.asyncio
async def test_query_load_certificate():
    """
    Test Query Script with loading a single certificate.
    """
    print("\nTesting Query Script with loading a single certificate…\n")
    test_domain = "mail.ru"
    certificate = await query.load_certificate(
        ssl.create_default_context(),
        test_domain
    )
    print(f"Certificate of '{test_domain}': {certificate}")


def test_query_get_public_key():
    """
    Test Query Script with getting the RSA public key values.
    """
    print("\nTesting Query Script with getting the RSA public key values…\n")
    test_domain = "mail.ru"
    certificate = asyncio.run(
        query.load_certificate(
            ssl.create_default_context(),
            test_domain
        )
    )
    public_key = query.get_rsa_public_key(certificate)
    if public_key:
        print(f"RSA public key of '{test_domain}':")
        print(f"- Modulus (in hex): {hex(public_key[0])}")
        print(f"- Public exponent: {public_key[1]}")
    else:
        print(f"No RSA public key found for '{test_domain}'.")


@pytest.mark.asyncio
async def test_query_process_domain():
    """
    Test Query Script with processing a single domain.
    """
    print("\nTesting Query Script with processing a single domain.\n")
    test_domain = "mail.ru"
    domain_record = await query.process_domain(
        test_domain,
        ssl.create_default_context(),
    )
    if domain_record:
        print(f"Domain '{test_domain}':")
        pprint(domain_record)
    else:
        print(f"No domain record for '{test_domain}'.")


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
