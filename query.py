"""
Query Script (query.py)

Retrieve the RSA public keys of at least 10K websites.
"""
import csv
import time
from typing import Any, Iterator

import asyncio
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


async def load_certificate(context: ssl.SSLContext, domain: str, port: int = 443) -> x509.Certificate | None:
    """
    Load a certificate from a website domain.

    :param context: TLS/SSL context
    :param domain: Website domain to load for public key extraction.
    :param port: Port number for the connection (default: 443).
    :return: X509 certificate or None.
    """
    try:
        # Asynchronous implementation (Socket is internally run here)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=domain,
                port=port,
                ssl=context,
                server_hostname=domain
            ),
            timeout=15  # Maximum time to get a connection (set to 15 seconds).
        )  # Get StreamReader, StreamWriter from a successful connection.

        # Get the peer certificate in serialized binary (DER) format.
        ssl_object = writer.get_extra_info("ssl_object")
        der_cert = ssl_object.getpeercert(binary_form=True)

        # Close connection.
        writer.close()
        await writer.wait_closed()

        # Deserialize the peer certificate.
        return x509.load_der_x509_certificate(der_cert, default_backend())
    except (ssl.SSLError, asyncio.TimeoutError):  # Catch these specific errors.
        return None
    except Exception:  # Catch any other exception.
        return None


def get_rsa_public_key(certificate: x509.Certificate | None) -> tuple[int, int] | None:
    """
    Retrieve the RSA public key from the certificate, if available.

    :param certificate: X509 certificate of a domain.
    :return: Public key (`n_hex`, `e`).
    """
    # Check if a certificate actually exists.
    if not certificate:
        return None

    # Try to get public key.
    try:
        public_key = certificate.public_key()

        # Check if the public key is from RSA, then retrieve the public numbers.
        if isinstance(public_key, RSAPublicKey):
            public_numbers = public_key.public_numbers()
            n_hex = hex(public_numbers.n)
            e = public_numbers.e
            return n_hex, e
        else:
            return None
    except Exception:  # Catch any exceptions.
        return None


async def process_domain(domain: str, context: ssl.SSLContext) -> dict[str, Any] | None:
    """
    Asynchronously process a single domain:
    - Load certificate from a website domain.
    - Retrieve the domain's RSA public key.

    :param domain: Website domain to load for public key extraction.
    :param context: TLS/SSL context for connection.
    :return: Either a dictionary of the domain and public key components, or None if the public key taken is not RSA.
    """
    certificate = await load_certificate(context, domain)
    rsa_public_key = get_rsa_public_key(certificate)

    if rsa_public_key:
        return {
            "domain": domain,
            "modulus_hex": rsa_public_key[0],
            "public_exponent": rsa_public_key[1],
        }

    return None


def generate_domains_from_csv(
    filename: str,
    rows_skipped: int = 0
) -> Iterator[str]:
    """
    Generate domains from a CSV file (use up to 1M sites).

    :param filename: CSV filename.
    :param rows_skipped: Number of rows to skip when generating domains.
    :return: Iterator of domain names.
    """
    with open(filename) as csvfile:
        # Get rows of domains.
        domains = csv.reader(csvfile)

        # Skip rows if necessary.
        for _ in range(rows_skipped):
            next(domains)

        for domain in domains:
            # Yield the domain.
            yield domain[0]


async def process_domains(
    domain_generator: Iterator[str],
    target_count: int = 10000,
    max_concurrent: int = 500,
    batch_size: int = 5000,
) -> list[dict[str, Any]]:
    """
    Asynchronously process a maximum of 1M domains:
    - Stop the process when at least `target_count` domains have been loaded.
    - Return the list of domains with retrieved RSA public keys.

    :param domain_generator: Iterator of domain names.
    :param target_count: Maximum number of domains to retrieve.
    :param max_concurrent: Maximum number of concurrent requests.
    :param batch_size: Number of domains to retrieve at a time.
    :return: List of at least 10K domains with retrieved RSA public keys.
    """
    context = ssl.create_default_context()
    semaphore = asyncio.Semaphore(max_concurrent)  # Rate limiter
    rsa_keys_collected = []
    domains_processed = 0

    async def process_domain_with_semaphore(domain: str):
        """
        Wrapper function for `process_domain` with semaphore control.
        """
        async with semaphore:
            return await process_domain(domain, context)

    batch = []  # Batch used

    print("-" * 67)
    print(f"Number of RSA public keys to collect: {target_count}")
    print(f"Processing domains...")

    start_time = time.time()  # Start time.

    for domain in domain_generator:  # Iterate through each generator.

        # Base case: Already have 10K+ domains
        if len(rsa_keys_collected) >= target_count:
            print("-" * 67)
            print(f"Target already reached! Collected {len(rsa_keys_collected)} RSA public keys!")
            break

        # Append domain to batch.
        batch.append(domain)

        # Process batch when full (reaches batch_size, default 500)
        if len(batch) >= batch_size:

            # Process the domains in the batch.
            tasks = [process_domain_with_semaphore(domain) for domain in batch]
            results = await asyncio.gather(*tasks)

            # Filter out and add the found RSA public keys into the collection.
            found_rsa_public_keys = [result for result in results if result is not None]
            rsa_keys_collected.extend(found_rsa_public_keys)

            # Progress updated.
            domains_processed += len(batch)
            print("-" * 67)
            print(f"Number of domains processed: {domains_processed}")
            print(f"Number of RSA public keys found: {len(rsa_keys_collected)}")

            # Empty batch.
            batch = []

    if batch and len(rsa_keys_collected) < target_count:
        # Process the domains in the partial batch.
        tasks = [process_domain_with_semaphore(domain) for domain in batch]
        results = await asyncio.gather(*tasks)

        # Filter out and add the remaining found RSA public keys into the collection.
        found_rsa_public_keys = [domain for domain in results if domain]
        rsa_keys_collected.extend(found_rsa_public_keys)

        # Progress updated.
        domains_processed += len(batch)
        print("-" * 67)
        print(f"Number of domains processed: {domains_processed}")
        print(f"Number of RSA public keys found: {len(rsa_keys_collected)}")

    end_time = time.time()  # End time.

    # Print out final results.
    print("-" * 67)
    print("Process Complete!")
    print(f"Number of domains processed: {domains_processed}")
    print(f"Number of RSA public keys found: {len(rsa_keys_collected)}")
    print(f"Time elapsed: {(end_time - start_time):.2f} seconds.")
    print("-" * 67)

    return rsa_keys_collected


async def main():
    """
    Main entry point.
    """
    # Create the domain generator.
    domains = generate_domains_from_csv("input_file/tranco.csv")

    # Process the domains to collect the RSA public keys.
    rsa_public_keys_collected = await process_domains(domains)

    # Write the RSA public keys into the output CSV file.
    fieldnames = ["domain", "modulus_hex", "public_exponent"]
    with open("output_file/rsa_public_keys.csv", "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rsa_public_keys_collected)


if __name__ == "__main__":
    asyncio.run(main())
