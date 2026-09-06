"""Byte-preservation and ownership regressions for pure HBA/ident changes."""

import pytest

from query_passport.contract import ContractError
from query_passport.db_config import (
    build_auth_rules,
    config_digest,
    owned_block,
    propose_config,
)

OWNER = "local-passport"
HBA, IDENT = build_auth_rules(
    "query_man", "passport_probe", "CN=passport-probe", "127.0.0.1/32", "qm"
)
NEW_HBA, NEW_IDENT = build_auth_rules(
    "query_man", "passport_probe", "CN=passport-new", "192.0.2.0/24", "qm_new"
)


def assert_error(code, function, *args, **kwargs):
    with pytest.raises(ContractError) as caught:
        function(*args, **kwargs)
    assert caught.value.code == code
    assert "SYNTHETIC_SECRET" not in str(caught.value)


@pytest.mark.parametrize("body", [HBA, IDENT])
@pytest.mark.parametrize(
    "original",
    [
        "",
        "# original\nlocal all all peer\n",
        "# original\r\nlocal all all peer\r\n",
        "# original\r\nlocal all all peer\n# no final newline",
        "local all all peer",
        "# utf8 한글\n",
        "# comment with continuation \\\n# next line\n",
    ],
)
def test_new_block_is_first_preserves_every_original_byte(body, original):
    proposed = propose_config(original, OWNER, body)
    block = owned_block(proposed, OWNER)
    assert block is not None
    assert proposed == block + original
    assert proposed.startswith(f"# query-passport:{OWNER}:begin")


def test_crlf_is_used_for_new_block_without_rewriting_original():
    original = "# original\r\nlocal all all peer\n# no final newline"
    proposed = propose_config(original, OWNER, HBA)
    block = owned_block(proposed, OWNER)
    assert block is not None
    assert "\n" not in block.replace("\r\n", "")
    assert proposed[len(block) :] == original


@pytest.mark.parametrize("body", [HBA.rstrip("\n"), HBA.replace("\n", "\r\n")])
def test_body_newline_variants_are_validated(body):
    assert propose_config("", OWNER, body) == propose_config("", OWNER, HBA)


@pytest.mark.parametrize("original_body,new_body", [(HBA, NEW_HBA), (IDENT, NEW_IDENT)])
def test_owned_replacement_requires_digest_and_preserves_unowned_text(original_body, new_body):
    original = propose_config("# untouched\n", OWNER, original_body)
    assert_error("TARGET_DRIFT", propose_config, original, OWNER, new_body)
    changed = propose_config(
        original, OWNER, new_body, expected_before_digest=config_digest(original)
    )
    applied = owned_block(changed, OWNER)
    assert applied is not None
    assert changed.endswith("# untouched\n")
    assert applied != owned_block(original, OWNER)


@pytest.mark.parametrize("has_previous", [False, True])
def test_apply_rejects_drift_anywhere_in_observed_file(has_previous):
    original = "# initial\n"
    if has_previous:
        original = propose_config(original, OWNER, HBA)
    observed_digest = config_digest(original)
    changed = original + "# concurrent unrelated change\n"
    assert_error(
        "TARGET_DRIFT",
        propose_config,
        changed,
        OWNER,
        NEW_HBA,
        expected_before_digest=observed_digest,
    )


def test_replacement_below_unowned_content_does_not_silently_reorder_rules():
    current = "host all all all trust\n" + propose_config("", OWNER, HBA)
    assert_error(
        "TARGET_DRIFT",
        propose_config,
        current,
        OWNER,
        NEW_HBA,
        expected_before_digest=config_digest(current),
    )


def test_other_owners_are_never_changed_by_insertion():
    other = propose_config("# unowned", "other-owner", IDENT)
    proposed = propose_config(other, OWNER, HBA)
    applied = owned_block(proposed, OWNER)
    assert applied is not None
    assert owned_block(proposed, "other-owner") == owned_block(other, "other-owner")


@pytest.mark.parametrize(
    "malformed",
    [
        "# query-passport:local-passport:begin\n",
        "# query-passport:local-passport:end\n",
        "# query-passport:local-passport:begin\n# query-passport:other-owner:end\n",
        "# query-passport:local-passport:begin\n# query-passport:other-owner:begin\n"
        "# query-passport:other-owner:end\n# query-passport:local-passport:end\n",
        "# query-passport:local-passport:begin\n# query-passport:local-passport:end\n" * 2,
        " # query-passport:local-passport:begin\n# query-passport:local-passport:end\n",
        "# query-passport:local-passport:BEGIN\n# query-passport:local-passport:end\n",
        "# Query-Passport:local-passport:begin\n# query-passport:local-passport:end\n",
        "# query-passport:local-passport:begin extra\n# query-passport:local-passport:end\n",
        "# continued \\\n# query-passport:local-passport:begin\n# query-passport:local-passport:end\n",
        "# query-passport:local-passport:begin\n# continued \\\n# query-passport:local-passport:end\n",
        "# query-passport:bad--owner:begin\n# query-passport:bad--owner:end\n",
    ],
)
def test_ambiguous_markers_fail_closed_for_all_operations(malformed):
    assert_error("INVALID_INPUT", owned_block, malformed, OWNER)
    assert_error("INVALID_INPUT", propose_config, malformed, OWNER, HBA)


def test_existing_block_without_final_newline_can_be_replaced():
    previous = propose_config("", OWNER, HBA).rstrip("\n")
    changed = propose_config(
        previous, OWNER, NEW_HBA, expected_before_digest=config_digest(previous)
    )
    assert owned_block(changed, OWNER) == changed


def test_digest_is_sensitive_to_every_byte_and_final_newline():
    values = ["# original", "# original\n", "# original\r\n", "# changed\n"]
    assert len({config_digest(text) for text in values}) == len(values)


@pytest.mark.parametrize("identifier", ["all", "replication", "sameuser", "samerole", "Probe_ID"])
def test_hba_identifiers_are_literal_even_for_hba_keywords(identifier):
    hba, ident = build_auth_rules(identifier, identifier, "CN=probe", "::1/128", "probe_map")
    assert hba.splitlines() == [
        f'hostssl "{identifier}" "{identifier}" ::1/128 cert clientname=DN map=probe_map',
        f'host all "{identifier}" all reject',
        f'local all "{identifier}" reject',
    ]
    assert ident == f'probe_map "CN=probe" "{identifier}"\n'
    assert propose_config("", OWNER, hba)
    assert propose_config("", OWNER, ident)


@pytest.mark.parametrize("field", [0, 1, 4])
@pytest.mark.parametrize(
    "bad", ["", "bad-name", "bad name", "a\nall", "a,b", "+role", "/regex", 'a"b', "é", "a" * 64]
)
def test_invalid_identifier_rejected(field, bad):
    arguments = ["query_man", "passport_probe", "CN=probe", "127.0.0.1/32", "probe_map"]
    arguments[field] = bad
    assert_error("INVALID_INPUT", build_auth_rules, *arguments)


@pytest.mark.parametrize(
    "dn",
    [
        "CN=",
        "cn=probe",
        "/CN=probe",
        "CN=probe,O=company",
        "CN=probe+CN=other",
        "CN=probe\\,extra",
        "CN=probe\nall all",
        "CN=Probe",
        "CN=bad--alias",
        "CN=bad_alias",
        "CN=" + "a" * 64,
    ],
)
def test_only_exact_cn_alias_is_supported(dn):
    assert_error("INVALID_INPUT", build_auth_rules, "query_man", "probe", dn, "::1/128", "qm")


@pytest.mark.parametrize(
    "cidr",
    [
        "127.0.0.1",
        "192.0.2.1/24",
        "192.0.2.0/255.255.255.0",
        "192.0.2.0/024",
        "192.000.2.0/24",
        "2001:DB8::/32",
        "2001:db8:0::/32",
        "::1",
        "fe80::%eth0/64",
        " all",
        "all",
        "samehost",
        "127.0.0.1/32\nlocal all all trust",
    ],
)
def test_noncanonical_or_invalid_cidr_is_never_broadened(cidr):
    assert_error("INVALID_INPUT", build_auth_rules, "query_man", "probe", "CN=probe", cidr, "qm")


@pytest.mark.parametrize(
    "body",
    [
        "",
        "host all all all trust\n",
        "include arbitrary.conf\n",
        "CREATE ROLE intruder SUPERUSER;\n",
        HBA + "# extra comment\n",
        HBA.replace("cert", "scram-sha-256"),
        HBA.replace('host all "passport_probe" all reject\n', ""),
        HBA.replace('local all "passport_probe"', 'local all "other"'),
        HBA.replace("\n", "\r"),
        HBA + "\n",
        HBA + "# query-passport:other-owner:begin\n",
        HBA + "\\\n",
        'qm "/.*" "passport_probe"\n',
    ],
)
def test_arbitrary_or_weakened_managed_rules_rejected(body):
    assert_error("INVALID_INPUT", propose_config, "# unrelated", OWNER, body)


@pytest.mark.parametrize("owner", ["", "a\nb", "A", "bad--owner", "x" * 64, "a:end"])
def test_invalid_owner_is_not_interpolated(owner):
    assert_error("INVALID_INPUT", propose_config, "", owner, HBA)


@pytest.mark.parametrize("content", ["\x00", "\ud800", "x" * (1024 * 1024 + 1)])
def test_malformed_or_unbounded_text_rejected(content):
    assert_error("INVALID_INPUT", config_digest, content)
    assert_error("INVALID_INPUT", propose_config, content, OWNER, HBA)
