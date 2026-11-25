from datetime import datetime
from datetime import timedelta
from datetime import timezone
import inspect

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from saml2 import saml
from saml2 import sigver
from saml2.s_utils import factory
from saml2.saml import assertion_from_string

try:
    XMLSEC_BINARY = sigver.get_xmlsec_binary()
except sigver.SigverError:
    XMLSEC_BINARY = None

requires_xmlsec = pytest.mark.skipif(XMLSEC_BINARY is None, reason="xmlsec1 binary is required")


def _write_key_and_certificate(tmp_path, expired=False):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example")])
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=30 if expired else 1)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=365)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256())
    )

    key_path = tmp_path / "attacker.key"
    cert_path = tmp_path / "attacker.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    cert_text = cert_path.read_text()
    cert_b64 = "".join(line for line in cert_text.splitlines() if "CERTIFICATE" not in line)
    return key_path, cert_path, cert_b64


def _signed_assertion(tmp_path, expired=False):
    key_path, cert_path, cert_b64 = _write_key_and_certificate(tmp_path, expired)
    crypto = sigver.CryptoBackendXmlSec1(XMLSEC_BINARY)
    context = sigver.SecurityContext(
        crypto,
        key_file=str(key_path),
        cert_file=str(cert_path),
        only_use_keys_in_metadata=False,
    )
    assertion = factory(
        saml.Assertion,
        version="2.0",
        id="id-security-test",
        issuer=saml.Issuer(text="https://unknown.example/issuer"),
        issue_instant="2026-01-01T00:00:00Z",
        signature=sigver.pre_signature_part("id-security-test", cert_b64, 1),
    )
    signed = context.sign_assertion(
        str(assertion),
        node_id="id-security-test",
        key_file=str(key_path),
    )
    return signed, assertion_from_string(signed)


def test_security_context_defaults_to_metadata_only():
    default = inspect.signature(sigver.SecurityContext).parameters["only_use_keys_in_metadata"].default
    assert default is True


@requires_xmlsec
def test_self_signed_embedded_certificate_is_rejected_by_default(tmp_path):
    signed, assertion = _signed_assertion(tmp_path)
    crypto = sigver.CryptoBackendXmlSec1(XMLSEC_BINARY)
    context = sigver.SecurityContext(crypto, only_use_keys_in_metadata=True)

    with pytest.raises(sigver.MissingKey):
        context._check_signature(signed, assertion, sigver.class_name(assertion), signed)


@requires_xmlsec
def test_explicit_fallback_accepts_valid_embedded_certificate(tmp_path):
    signed, assertion = _signed_assertion(tmp_path)
    crypto = sigver.CryptoBackendXmlSec1(XMLSEC_BINARY)
    context = sigver.SecurityContext(crypto, only_use_keys_in_metadata=False)

    with pytest.warns(DeprecationWarning, match="embedded in the SAML message"):
        result = context._check_signature(signed, assertion, sigver.class_name(assertion), signed)

    assert result is assertion


@requires_xmlsec
def test_expired_embedded_certificate_is_filtered(tmp_path):
    signed, assertion = _signed_assertion(tmp_path, expired=True)

    assert sigver.cert_from_instance(assertion) == []
    assert len(sigver.cert_from_instance(assertion, ignore_age=True)) == 1

    crypto = sigver.CryptoBackendXmlSec1(XMLSEC_BINARY)
    context = sigver.SecurityContext(crypto, only_use_keys_in_metadata=False)
    with pytest.raises(sigver.MissingKey):
        context._check_signature(signed, assertion, sigver.class_name(assertion), signed)
