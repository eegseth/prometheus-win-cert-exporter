import datetime
import ssl
import time
from prometheus_client import start_http_server, Gauge
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def hex_string_readable(bytes):
    return ["{:02X}".format(x) for x in bytes]

def get_certificates():
    # Create an empty list to store certificate information
    certificates = []

    for store in ["CA", "ROOT", "MY", "AuthRoot"]:
        for cert, encoding, trust in ssl.enum_certificates(store):
            certificate = x509.load_der_x509_certificate(cert, backend=None)
            # Add certificates to the list
            certificates.append(certificate)

    return certificates

def export_cert_metrics():
    # Create Prometheus metrics
    metric_cert_expiry = Gauge("certificate_expiry_days", "Days remaining until certificate expires", ["name", "thumbprint", "expiry_date"])

    while True:
        # Fetch certificates
        certificates = get_certificates()

        # Iterate over certificates and export metrics
        for cert in certificates:
            # Get certificate information
            name = cert.subject.rfc4514_string()
            fingerprint = hex_string_readable(cert.fingerprint(hashes.SHA1()))
            fingerprint_string = ''.join(fingerprint)
            expiry_date = cert.not_valid_after.date()
            days_remaining = (expiry_date - datetime.date.today()).days

            # Export metrics
            metric_cert_expiry.labels(name=name, thumbprint=fingerprint_string, expiry_date=str(expiry_date)).set(days_remaining)
        
        time.sleep(60)


if __name__ == "__main__":
    # Start Prometheus HTTP server
    start_http_server(8000)

    # Export certificate metrics
    export_cert_metrics()
