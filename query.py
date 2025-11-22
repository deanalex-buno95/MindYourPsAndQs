"""
Query Script (query.py)

Retrieve the RSA public keys of at least 10K websites.
"""
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
        # Synchronous Socket Module Use…
        # with socket.create_connection((domain, port)) as sock:
        #     with context.wrap_socket(sock, server_hostname=domain) as ssock:
        #         # Get the peer certificate in serialized binary (DER) format.
        #         der_cert = ssock.getpeercert(binary_form=True)

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


def get_rsa_public_key(certificate: x509.Certificate) -> tuple[str, int] | None:
    """
    Retrieve the RSA public key from the certificate, if available.

    :param certificate: X509 certificate of a domain.
    :return: Public key (`n_hex`, `e`).
    """
    # Get public key.
    public_key = certificate.public_key()

    # Check if the public key is from RSA, then retrieve the public numbers.
    if isinstance(public_key, RSAPublicKey):
        public_numbers = public_key.public_numbers()
        n_hex = hex(public_numbers.n)
        e = public_numbers.e
        return n_hex, e
    else:
        return None


def load_certificates(domains: list[str], port: int = 443):
    """
    Load a list of certificates from a list of website domains.

    :param domains: List of website domains to load for public key extraction.
    :param port: Port number for the connection (default: 443).
    :return: List of collected certificates.
    """
    # Create a default SSL context to manage TLS/SSL settings to retrieve certificate.
    context = ssl.create_default_context()

    # Get a list of certificate records of each domain.
    certificate_records = []
    for domain in domains:

        # Start a certificate record with the current domain iterated.
        certificate_record = {"domain": domain}

        # Try to get the certificate.
        certificate = load_certificate(context, domain, port)

        # Handle the certificate's public key.
        if certificate:
            certificate_rsa_public_key = get_rsa_public_key(certificate)

            # Add the public numbers if found.
            if certificate_rsa_public_key:
                certificate_record["n_hex"] = certificate_rsa_public_key[0]
                certificate_record["e"] = certificate_rsa_public_key[1]
                certificate_records.append(certificate_record)

    return certificate_records
