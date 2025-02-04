import base64
import logging
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Tuple
import urllib3
from pathlib import Path
import argparse
from asn1crypto import pem, x509

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def validate_certificate(pem_cert: str) -> bool:
    """
    Validate a PEM certificate using asn1crypto.
    Returns True if valid, False otherwise.
    """
    try:
        # Detect and unarmor the PEM certificate, converting it to DER
        if pem.detect(pem_cert.encode("utf-8")):
            _, _, der_bytes = pem.unarmor(pem_cert.encode("utf-8"))
        else:
            # If not armored, assume it's raw DER
            der_bytes = pem_cert.encode("utf-8")

        # Attempt to parse the certificate using asn1crypto's x509 module
        cert = x509.Certificate.load(der_bytes)

        # Access the subject to trigger any potential parsing issues
        subject = cert.subject
        # Access each RelativeDistinguishedName in the subject to trigger potential encoding issues
        for rdn in subject.chosen:
            for name_type_and_value in rdn:
                _ = name_type_and_value["type"].native
                _ = name_type_and_value["value"].native

        return True
    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        return False


def create_session() -> requests.Session:
    """Create and configure a requests session."""
    session = requests.Session()
    session.verify = True
    session.headers.update({"User-Agent": "EU Trust List Collector/1.0"})
    session.timeout = 10
    return session


def download_trust_list(session: requests.Session, url: str) -> ET.Element:
    """Download and parse XML trust list with exponential backoff."""
    max_retries = 5
    base_delay = 1  # starting delay in seconds

    for attempt in range(max_retries):
        try:
            response = session.get(url)
            response.raise_for_status()
            return ET.fromstring(response.content)
        except Exception as e:
            delay = base_delay * (2**attempt)  # exponential backoff
            logger.error(f"{url}: Attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
    raise Exception(
        f"Failed to download trust list from {url} after {max_retries} attempts"
    )


def cert_to_pem(cert_base64: str) -> str:
    """Convert base64 certificate to PEM format."""
    try:
        # Clean the base64 string
        cleaned = cert_base64.replace("\n", "").strip()
        # Decode base64 to bytes
        der_bytes = base64.b64decode(cleaned)
        # Format as PEM
        pem = f"-----BEGIN CERTIFICATE-----\n"
        pem += base64.b64encode(der_bytes).decode("ascii")
        pem += "\n-----END CERTIFICATE-----\n"
        return pem
    except Exception as e:
        raise ValueError(f"Failed to convert certificate to PEM: {e}")


def process_trust_list(root: ET.Element, url: str, validate: bool) -> List[str]:
    """Process trust list XML and extract certificates."""
    ns = {
        "ns1": "http://uri.etsi.org/02231/v2#",
        "ns3": "http://uri.etsi.org/02231/v2/additionaltypes#",
    }

    pem_certs = []

    # Extract and log basic information
    scheme_info = root.find(".//ns1:SchemeInformation", ns)
    territory = scheme_info.find("ns1:SchemeTerritory", ns).text
    logger.info(f"Downloaded {territory}: {url}")

    # Process TSPs
    for tsp in root.findall(".//ns1:TrustServiceProvider", ns):
        tsp_name = tsp.find(".//ns1:TSPName/ns1:Name", ns).text
        logger.info(f"    - {tsp_name}")

        for service in tsp.findall(".//ns1:TSPService", ns):
            service_info = service.find("ns1:ServiceInformation", ns)
            type_id = service_info.find("ns1:ServiceTypeIdentifier", ns).text
            status = service_info.find("ns1:ServiceStatus", ns).text

            # Process QC certificates
            if type_id == "http://uri.etsi.org/TrstSvc/Svctype/CA/QC":
                for ext in service_info.findall(".//ns1:Extension", ns):
                    uri = ext.find(".//ns1:URI", ns)
                    if uri is not None and uri.text in [
                        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals",
                        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures",
                        "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication",
                    ]:
                        if status in [
                            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
                            "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
                        ]:
                            cert = service_info.find(".//ns1:X509Certificate", ns)
                            if cert is not None and cert.text:
                                try:
                                    pem_cert = cert_to_pem(cert.text)
                                    if not validate or validate_certificate(pem_cert):
                                        pem_certs.append(pem_cert)
                                    else:
                                        logger.warning(
                                            f"Certificate validation failed for {tsp_name}"
                                        )
                                except ValueError as e:
                                    logger.error(f"Error processing certificate: {e}")

    return pem_certs


def main():
    parser = argparse.ArgumentParser(
        description="Download and process EU trusted certificates."
    )
    parser.add_argument(
        "--no-validate", action="store_true", help="Skip certificate validation"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="eu-lotl.pem",
        help="Output file path (default: eu-lotl.pem)",
    )
    args = parser.parse_args()

    lotl_url = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
    session = create_session()

    # Download and parse LOTL
    lotl_root = download_trust_list(session, lotl_url)

    # Process all trust lists
    seen_certs = set()
    all_certs = []

    ns = {
        "ns1": "http://uri.etsi.org/02231/v2#",
        "ns3": "http://uri.etsi.org/02231/v2/additionaltypes#",
    }

    for pointer in lotl_root.findall(".//ns1:OtherTSLPointer", ns):
        location = pointer.find("ns1:TSLLocation", ns).text
        mime_type = pointer.find(".//ns3:MimeType", ns).text

        if mime_type == "application/vnd.etsi.tsl+xml":
            territory = pointer.find(".//ns1:SchemeTerritory", ns).text
            logger.info(f"\n\n-- COUNTRY: {territory}")

            try:
                tl_root = download_trust_list(session, location)
                pems = process_trust_list(tl_root, location, not args.no_validate)

                for pem in pems:
                    if pem not in seen_certs:
                        seen_certs.add(pem)
                        all_certs.append(pem)

            except Exception as e:
                logger.error(f"Error processing {location}: {e}")

    # Save certificates to file
    output_path = Path(args.output)
    with output_path.open("w") as f:
        f.write("".join(all_certs))

    logger.info(f"\nSaved {len(all_certs)} certificates to {output_path}")


if __name__ == "__main__":
    main()
