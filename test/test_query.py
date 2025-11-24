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
    context = ssl.create_default_context()
    test_domain = "mail.ru"
    certificate = asyncio.run(
        query.load_certificate(
            context,
            test_domain
        )
    )
    public_key = query.get_rsa_public_key(certificate)
    if public_key:
        print(f"RSA public key of '{test_domain}':")
        print(f"- Modulus (in hex): {(public_key[0])}")
        print(f"- Public exponent: {public_key[1]}")
    else:
        print(f"No RSA public key found for '{test_domain}'.")


@pytest.mark.asyncio
async def test_query_process_domain():
    """
    Test Query Script with processing a single domain.
    """
    print("\nTesting Query Script with processing a single domain.\n")
    context = ssl.create_default_context()
    test_domain = "mail.ru"
    domain_record = await query.process_domain(
        context,
        test_domain,
    )
    if domain_record:
        print(f"Domain '{test_domain}':")
        pprint(domain_record)
    else:
        print(f"No domain record for '{test_domain}'.")


def test_query_generate_domains_from_csv():
    """
    Test Query Script with generating multiple domains from a CSV file.
    """
    print("\nTesting Query Script with generating multiple domains from a CSV file.\n")
    test_number_of_domains = 10
    tranco_csv = "input_file/tranco.csv"
    domain_generator = query.generate_domains_from_csv(tranco_csv)
    i = 0
    for domain in domain_generator:
        if i == test_number_of_domains:
            break
        print(domain)
        i += 1


@pytest.mark.asyncio
async def test_query_process_domains():
    """
    Test Query Script with processing multiple domains.
    """
    print("\nTesting Query Script with processing multiple domains.\n")
    tranco_csv = "input_file/tranco.csv"
    domain_generator = query.generate_domains_from_csv(tranco_csv)
    rsa_keys_collected = await query.process_domains(
        domain_generator=domain_generator,
        target_count=20,
        max_concurrent=20,
        batch_size=20
    )
    print("List of RSA public keys collected:")
    for rsa_key in rsa_keys_collected:
        print(rsa_key)
    print("-" * 67)
