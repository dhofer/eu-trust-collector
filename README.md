# EU Trust Collector

A Python script that downloads all qualified trust service providers' certificates from the European Union
List of Trusted Lists (LOTL) and saves them in a PEM file. This file can be utilized for validation of PDF signatures
with tools like [pyHanko](https://github.com/MatthiasValvekens/pyHanko).

## Prerequisites

- Python 3.x
- Install required Python libraries:
  ```bash
  pip install asn1crypto

## Usage

```bash
# Download certificates
python eu_trust_collector.py

# Use the generated PEM file with pyhanko for PDF signature validation
pyhanko sign validate --trust eu-lotl.pem --no-strict-syntax --pretty-print signed.pdf

