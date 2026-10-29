"""Private CA + server certificate, for a relay reached by IP address (no domain needed).

  python mkcert.py 203.0.113.7
    certs/server.crt, certs/server.key   -> deploy to the server
    relay/web/ca.crt                     -> install once on each phone (served at https://<ip>/s/ca.crt)
    certs/ca.key                         -> stays on this PC; re-running reuses it, phones keep working

iOS requires server certificates to be valid for at most 825 days, carry the IP in subjectAltName and the
serverAuth EKU; Chrome requires subjectAltName too.
"""
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(HERE, "certs")
CA_KEY = os.path.join(CERTS, "ca.key")
CA_CRT = os.path.join(HERE, "relay", "web", "ca.crt")


def key_usage(**on):
    names = ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
             "key_cert_sign", "crl_sign", "encipher_only", "decipher_only"]
    return x509.KeyUsage(**{n: on.get(n, False) for n in names})


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MiniDesk Private CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(key_usage(key_cert_sign=True, crl_sign=True), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def san(host):
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def make_server_cert(ca_key, ca_cert, *hosts):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=820))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(key_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([san(h) for h in hosts]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def load_ca():
    """The existing private CA, or None."""
    if not (os.path.exists(CA_KEY) and os.path.exists(CA_CRT)):
        return None
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), None)
    with open(CA_CRT, "rb") as f:
        return ca_key, x509.load_pem_x509_certificate(f.read())


def issue(host):
    """Create or reuse the CA, then write a fresh server certificate for `host`."""
    os.makedirs(CERTS, exist_ok=True)
    if ca := load_ca():
        ca_key, ca_cert = ca
        print("reusing existing CA")
    else:
        ca_key, ca_cert = make_ca()
        with open(CA_KEY, "wb") as f:
            f.write(pem_key(ca_key))
        with open(CA_CRT, "wb") as f:
            f.write(pem_cert(ca_cert))
        print("created new CA (phones must install relay/web/ca.crt)")
    key, cert = make_server_cert(ca_key, ca_cert, host)
    with open(os.path.join(CERTS, "server.key"), "wb") as f:
        f.write(pem_key(key))
    with open(os.path.join(CERTS, "server.crt"), "wb") as f:
        f.write(pem_cert(cert))
    print(f"server certificate for {host} valid until {cert.not_valid_after_utc:%Y-%m-%d}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    issue(sys.argv[1])
