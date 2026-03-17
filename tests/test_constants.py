from mail_sovereignty.constants import (
    MICROSOFT_KEYWORDS,
    GOOGLE_KEYWORDS,
    AWS_KEYWORDS,
    PROVIDER_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    MAILBOX_ASNS,
    SKIP_DOMAINS,
)


def test_keyword_lists_non_empty():
    assert MICROSOFT_KEYWORDS
    assert GOOGLE_KEYWORDS
    assert AWS_KEYWORDS


def test_provider_keywords_has_all_providers():
    assert set(PROVIDER_KEYWORDS.keys()) == {"microsoft", "google", "aws"}


def test_foreign_sender_keywords_non_empty():
    assert FOREIGN_SENDER_KEYWORDS
    assert "mailchimp" in FOREIGN_SENDER_KEYWORDS
    assert "sendgrid" in FOREIGN_SENDER_KEYWORDS
    assert "smtp2go" in FOREIGN_SENDER_KEYWORDS
    assert "nl2go" in FOREIGN_SENDER_KEYWORDS
    assert "hubspot" in FOREIGN_SENDER_KEYWORDS
    assert "knowbe4" in FOREIGN_SENDER_KEYWORDS
    assert "hornetsecurity" in FOREIGN_SENDER_KEYWORDS
    assert set(FOREIGN_SENDER_KEYWORDS.keys()).isdisjoint(set(PROVIDER_KEYWORDS.keys()))


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS


def test_mailbox_asns_exists_and_has_expected_keys():
    assert isinstance(MAILBOX_ASNS, dict)
    assert 8075 in MAILBOX_ASNS
    assert MAILBOX_ASNS[8075] == "microsoft"
    assert 15169 in MAILBOX_ASNS
    assert MAILBOX_ASNS[15169] == "google"


def test_mailbox_asns_excludes_aws():
    """AWS SES ASNs should not be in MAILBOX_ASNS."""
    aws_asns = {14618, 16509}
    assert aws_asns.isdisjoint(MAILBOX_ASNS.keys())
