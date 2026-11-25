from unittest.mock import Mock

import pytest

from saml2 import SAMLError
from saml2 import config
from saml2.client import Saml2Client
from saml2.response import AuthnResponse
from saml2.saml import Assertion
from saml2.sigver import SignatureMissing


def _response(**kwargs):
    response = AuthnResponse(Mock(), [], "https://sp.example.com", asynchop=False, **kwargs)
    response.authn_statement_ok = lambda optional=False: True
    response.condition_ok = lambda lax=False: True
    response.get_subject = lambda keys=None: None
    return response


def _signed_assertion(assertion_id):
    assertion = Assertion(id=assertion_id)
    assertion.signature = object()
    return assertion


def test_defaults_require_signatures():
    response = _response()

    assert response.require_signature is True
    assert response.require_response_signature is True
    assert response.require_signature_or_response_signature is True


def test_assertion_signature_is_required_even_when_response_is_signed():
    response = _response(want_assertions_signed=True, want_response_signed=True)
    response.response_is_signed = True

    with pytest.raises(SignatureMissing, match="want_assertions_signed"):
        response._assertion(Assertion(id="unsigned"))


def test_response_only_exemption_is_explicit():
    response = _response(want_assertions_signed=False, want_response_signed=True)
    response.response_is_signed = True

    assert response._assertion(Assertion(id="covered-by-response"))


def test_response_only_exemption_requires_a_signed_response():
    response = _response(want_assertions_signed=False, want_response_signed=False)
    response.response_is_signed = False

    with pytest.raises(SignatureMissing, match="neither the assertion nor the response"):
        response._assertion(Assertion(id="unauthenticated"))


def test_each_assertion_is_checked_individually():
    response = _response(want_assertions_signed=False, want_response_signed=False)
    response.response_is_signed = False

    assert response._assertion(_signed_assertion("signed"), verified=True)
    with pytest.raises(SignatureMissing):
        response._assertion(Assertion(id="unsigned"))


def test_advice_assertion_is_authenticated_too():
    response = _response(want_assertions_signed=False, want_response_signed=False)
    response.response_is_signed = False

    with pytest.raises(SignatureMissing, match="advice assertion"):
        response._verify_advice_assertion(Assertion(id="advice-unsigned"))

    response.response_is_signed = True
    response._verify_advice_assertion(Assertion(id="advice-covered-by-response"))


def test_sp_rejects_configuration_without_any_signature_requirement():
    conf = config.SPConfig()
    conf.load_file("server_conf")
    conf.setattr("sp", "want_assertions_signed", False)
    conf.setattr("sp", "want_response_signed", False)
    conf.setattr("sp", "want_assertions_or_response_signed", False)

    with pytest.raises(SAMLError, match="insecure"):
        Saml2Client(conf)


def test_sp_defaults_to_requiring_signatures():
    conf = config.SPConfig()
    conf.load_file("server_conf")
    client = Saml2Client(conf)

    assert client.want_assertions_signed is True
    assert client.want_response_signed is True
    assert client.want_assertions_or_response_signed is True
