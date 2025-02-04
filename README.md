# Trust Collector

A Python script that downloads qualified trust service providers' certificates from multiple sources:
- European Union List of Trusted Lists (EU-LOTL)
- Adobe Approved Trust List (AATL)

The certificates are saved in PEM format files that can be utilized for validation of PDF signatures
with tools like [pyHanko](https://github.com/MatthiasValvekens/pyHanko).

Please be aware that this is just a quick workaround until pyHanko's qualified-certs feature is available.

## Prerequisites

- Python 3.x
- Install required Python libraries:
  ```bash
  pip install asn1crypto pypdf

## Usage

```bash
# Download certificates
python eu_trust_collector.py

# Use the generated PEM file with pyhanko for PDF signature validation
pyhanko sign validate --trust eu-lotl.pem --no-strict-syntax --pretty-print signed.pdf

