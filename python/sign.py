#!/usr/bin/env python

import requests
import json
import tempfile
from urllib.parse import urljoin
import atexit
from os import unlink
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import jwt
from jwt.algorithms import ECAlgorithm
import uuid
from datetime import timezone, datetime, timedelta

import requests.packages.urllib3 as urllib3
import argparse

class StepClient:
    def __init__(self, ca_url, ca_fingerprint):
        self.url = ca_url
        self.fingerprint = ca_fingerprint
        self.root_pem = self.root()
        self.cert_bundle_fn = self._save_tempfile(self.root_pem)

    # Verifies the root fingerprint and returns the root PEM
    # from the server.
    def root(self):
        # Disable TLS verification warnings for this request.
        urllib3.warnings.simplefilter("ignore")

        with requests.get(urljoin(self.url, f'root/{self.fingerprint}'), verify=False) as r:
            root_pem = r.json()['ca']
            self._compare_fingerprints(root_pem, self.fingerprint)

        # Re-enable TLS verification warnings
        urllib3.warnings.simplefilter("default")
        return root_pem

    # sign() accepts a CSR PEM, and a JWT string.
    # It returns a cryptography.x509.Certificate object.
    # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object
    def sign(self, csr, token):
        r = requests.post(urljoin(self.url, f'1.0/sign'),
						   verify=self.cert_bundle_fn,
						   data=json.dumps({'csr': csr.csr_pem, 'ott': token.token}))
        return x509.load_pem_x509_certificate(str.encode(r.json()['crt']))

    def health(self):
        with requests.get(urljoin(self.url, f'health'),
                    verify=self.cert_bundle_fn) as r:
            print(r.json())

    def _save_tempfile(self, contents):
        f = tempfile.NamedTemporaryFile(mode='w', delete=False)
        f.write(contents)
        f.close()
        atexit.register(self._tempfile_unlinker(f.name))
        return f.name

    def _tempfile_unlinker(self, fn):
        def cleanup():
            unlink(fn)
        return cleanup

    def _compare_fingerprints(self, pem, fingerprint):
        cert = x509.load_pem_x509_certificate(str.encode(pem))
        if cert.fingerprint(hashes.SHA256()) != bytes.fromhex(fingerprint):
            raise ConnectionError("WARNING: fingerprints do not match")

class CSR:
    def __init__(self, cn, dns_sans):
        self.key = self._generate_private_key()
        self.cn = cn
        self.dns_sans = dns_sans
        self.csr_pem_bytes = self._generate_csr() 
        self.csr_pem = self.csr_pem_bytes.decode('UTF-8')

    def _generate_private_key(self):
        return ec.generate_private_key(ec.SECP384R1)

    # Returns CSR PEM bytes
    def _generate_csr(self):
        return x509.CertificateSigningRequestBuilder(
            ).subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.cn)])
            ).add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(san) for san in self.dns_sans]
                ),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=False,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            ).sign(self.key, hashes.SHA256()
            ).public_bytes(serialization.Encoding.PEM)

    # Returns an encrypted PEM of the private key
    def key_pem(self, passphrase):
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes(passphrase, 'UTF-8')),
        )

class CAToken:
    def __init__(self, ca_url, ca_fingerprint, csr, provisioner_name, jwk):
        self.ca_url = ca_url
        self.ca_fingerprint = ca_fingerprint
        self.provisioner_name = provisioner_name
        self.csr = csr

        jwk_privkey = json.loads(jwk)
        key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(jwk_privkey)
        self.token = jwt.encode(
            self.jwt_body(),
            key=key,
			headers={ "kid": jwk_privkey['kid'] },
            algorithm="ES256"
        )

    def jwt_body(self):
        return {
            "aud": urljoin(self.ca_url, '/1.0/sign'),
            "sha": self.ca_fingerprint,
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
            "iat": datetime.now(tz=timezone.utc),
            "nbf": datetime.now(tz=timezone.utc),
            "jti": str(uuid.uuid4()),
            "iss": self.provisioner_name,
            "sans": self.csr.dns_sans,
            "sub": self.csr.cn,
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get a CSR signed with a step-ca server.')
    parser.add_argument('ca_url', type=str, help='The step-ca URL')
    parser.add_argument('ca_fingerprint', type=str, help='The CA fingerprint')
    parser.add_argument('provisioner_name', type=str, help='The CA JWK provisioner to use')
    parser.add_argument('jwk_filename', type=str, help='The JWK private key filename (JSON formatted)')
    args = parser.parse_args()

    with open(args.jwk_filename) as f:
        jwk = f.read()

    step_ca = StepClient(args.ca_url, args.ca_fingerprint)

    # Example uses
    csr = CSR('example.com', [u'example.com', u'mysite.example.com'])
    token = CAToken(step_ca.url, step_ca.fingerprint, csr, args.provisioner_name, jwk)
    certificate = step_ca.sign(csr, token)
    certificate_pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_der_bytes = certificate.public_bytes(serialization.Encoding.DER)
    private_key = csr.key
    encrypted_private_key_pem = csr.key_pem('mysecretpw')
    print(certificate_pem_bytes.decode('UTF-8'))
