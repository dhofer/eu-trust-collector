import argparse
import base64
import logging
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path

import requests
from asn1crypto import pem, x509
from pypdf import PdfReader

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def validate_certificate(pem_cert: str) -> bool:
    """
    Validate a PEM certificate using asn1crypto.
    Returns True if valid, False otherwise.
    """
    try:
        if pem.detect(pem_cert.encode("utf-8")):
            _, _, der_bytes = pem.unarmor(pem_cert.encode("utf-8"))
        else:
            der_bytes = pem_cert.encode("utf-8")

        cert = x509.Certificate.load(der_bytes)
        subject = cert.subject
        for rdn in subject.chosen:
            for name_type_and_value in rdn:
                _ = name_type_and_value["type"].native
                _ = name_type_and_value["value"].native

        return True
    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        return False


def cert_to_pem(cert_base64: str) -> str:
    """Convert base64 certificate to PEM format."""
    try:
        cleaned = cert_base64.replace("\n", "").strip()
        der_bytes = base64.b64decode(cleaned)
        pem = f"-----BEGIN CERTIFICATE-----\n"
        pem += base64.b64encode(der_bytes).decode("ascii")
        pem += "\n-----END CERTIFICATE-----\n"
        return pem
    except Exception as e:
        raise ValueError(f"Failed to convert certificate to PEM: {e}")


def download_aatl_pdf(url: str) -> bytes:
    """Download the AATL PDF file."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.content
    except Exception as e:
        raise Exception(f"Failed to download AATL PDF: {e}")


def process_aatl_list(xml_content: list, validate: bool) -> list[str]:
    """Process AATL XML and extract certificates."""
    # Convert list of bytes to string
    xml_string = b"".join(xml_content).decode("utf-8")

    root = ET.fromstring(xml_string)
    pem_certs = []

    # Process all Identity elements
    for identity in root.findall(".//Identity"):
        # Check if this is an AATL certificate
        source = identity.find(".//Identification/Source")
        if source is not None and source.text == "AATL":
            cert_elem = identity.find("Certificate")
            if cert_elem is not None and cert_elem.text:
                try:
                    pem_cert = cert_to_pem(cert_elem.text)
                    if not validate or validate_certificate(pem_cert):
                        pem_certs.append(pem_cert)
                    else:
                        logger.warning("Certificate validation failed")
                except ValueError as e:
                    logger.error(f"Error processing certificate: {e}")

    return pem_certs


def main():
    parser = argparse.ArgumentParser(
        description="Download and process AATL certificates."
    )
    parser.add_argument(
        "--no-validate", action="store_true", help="Skip certificate validation"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="aatl.pem",
        help="Output file path (default: aatl.pem)",
    )
    args = parser.parse_args()

    aatl_url = "http://trustlist.adobe.com/tl12.acrobatsecuritysettings"

    try:
        # Download the PDF
        logger.info("Downloading AATL PDF...")
        pdf_content = download_aatl_pdf(aatl_url)

        # Extract the XML from the PDF
        logger.info("Extracting XML from PDF...")
        reader = PdfReader(BytesIO(pdf_content))
        xml_content = reader.attachments["SecuritySettings.xml"]

        # Process the trust list
        logger.info("Processing AATL certificates...")
        pem_certs = process_aatl_list(xml_content, not args.no_validate)

        # Save certificates to file
        output_path = Path(args.output)
        with output_path.open("w") as f:
            f.write("".join(pem_certs))

        logger.info(f"\nSaved {len(pem_certs)} certificates to {output_path}")

    except Exception as e:
        logger.error(f"Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()
