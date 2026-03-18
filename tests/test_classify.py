from mail_sovereignty.classify import (
    DomesticConfig,
    _classify_from_spf_asns,
    classify,
    classify_from_autodiscover,
    classify_from_dkim,
    classify_from_mx,
    classify_from_smtp_banner,
    classify_from_spf,
    classify_from_txt_verifications,
    detect_gateway,
    spf_mentions_providers,
)


# ── classify() ──────────────────────────────────────────────────────


class TestClassify:
    def test_microsoft_mx(self):
        assert classify(["bern-ch.mail.protection.outlook.com"], "")[0] == "microsoft"

    def test_google_mx(self):
        assert (
            classify(["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "")[0]
            == "google"
        )

    def test_aws_mx(self):
        assert classify(["inbound-smtp.us-east-1.amazonaws.com"], "")[0] == "aws"

    def test_independent_mx(self):
        assert classify(["mail.example.ch"], "")[0] == "independent"

    def test_spf_fallback_when_no_mx(self):
        assert (
            classify([], "v=spf1 include:spf.protection.outlook.com -all")[0]
            == "microsoft"
        )

    def test_no_mx_no_spf(self):
        assert classify([], "")[0] == "unknown"

    def test_mx_takes_precedence_over_spf(self):
        result = classify(
            ["mail.example.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "independent"

    def test_cname_detects_microsoft(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_cnames={"mail.example.ch": "mail.protection.outlook.com"},
        )
        assert result[0] == "microsoft"

    def test_cname_none_stays_independent(self):
        assert classify(["mail.example.ch"], "", mx_cnames=None)[0] == "independent"

    def test_cname_empty_stays_independent(self):
        assert classify(["mail.example.ch"], "", mx_cnames={})[0] == "independent"

    def test_direct_mx_takes_precedence_over_cname(self):
        result = classify(
            ["mail.protection.outlook.com"],
            "",
            mx_cnames={"mail.protection.outlook.com": "something.else.com"},
        )
        assert result[0] == "microsoft"

    def test_non_hyperscaler_asn_stays_independent(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns={99999},
        )
        assert result[0] == "independent"

    def test_empty_asns_stays_independent(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns=set(),
        )
        assert result[0] == "independent"

    # ── Gateway detection in classify() ──

    def test_seppmail_gateway_with_microsoft_spf(self):
        result = classify(
            ["customer.seppmail.cloud"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_cleanmail_gateway_with_google_spf(self):
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:_spf.google.com -all",
        )
        assert result[0] == "google"

    def test_gateway_no_hyperscaler_spf_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result[0] == "independent"

    def test_gateway_empty_spf_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
        )
        assert result[0] == "independent"

    def test_gateway_microsoft_in_resolved_spf(self):
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:custom.ch -all",
            resolved_spf="v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_gateway_resolved_spf_not_checked_if_raw_matches(self):
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:_spf.google.com -all",
            resolved_spf="v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "google"

    def test_non_gateway_independent_mx_ignores_spf(self):
        """Self-hosted MX (not a gateway) should NOT be reclassified by SPF."""
        result = classify(
            ["nemx9a.ne.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "independent"

    def test_barracuda_gateway_with_microsoft_spf(self):
        result = classify(
            ["mail.barracudanetworks.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_trendmicro_gateway_with_aws_spf(self):
        result = classify(
            ["filter.tmes.trendmicro.eu"],
            "v=spf1 include:amazonses.com -all",
        )
        assert result[0] == "aws"

    def test_hornetsecurity_gateway_with_microsoft_spf(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_abxsec_gateway_with_microsoft_spf(self):
        result = classify(
            ["mta1.abxsec.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_proofpoint_gateway_with_microsoft_spf(self):
        result = classify(
            ["mx1.ppe-hosted.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_proofpoint_pphosted_gateway(self):
        result = classify(
            ["mx1.pphosted.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_sophos_gateway_with_microsoft_spf(self):
        result = classify(
            ["mx.hydra.sophos.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_spamvor_gateway_stays_independent_no_hyperscaler_spf(self):
        result = classify(
            ["relay.spamvor.com"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result[0] == "independent"

    def test_gateway_does_not_override_direct_mx_match(self):
        """If MX directly matches a provider, gateway check is skipped."""
        result = classify(
            ["mail.protection.outlook.com"],
            "v=spf1 include:_spf.google.com -all",
        )
        assert result[0] == "microsoft"

    # ── Autodiscover in classify() ──

    def test_gateway_autodiscover_reveals_microsoft(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 ip4:1.2.3.4 -all",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result[0] == "microsoft"

    def test_gateway_autodiscover_reveals_google(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            autodiscover={"autodiscover_srv": "autodiscover.google.com"},
        )
        assert result[0] == "google"

    def test_gateway_spf_contradicted_by_autodiscover(self):
        """If SPF says google but autodiscover says microsoft, autodiscover wins."""
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:_spf.google.com -all",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result[0] == "microsoft"

    def test_non_gateway_independent_uses_autodiscover_fallback(self):
        """Non-gateway independent MX should use autodiscover as fallback."""
        result = classify(
            ["mail.example.ch"],
            "",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result[0] == "microsoft"

    def test_non_gateway_independent_no_autodiscover_stays_independent(self):
        """Non-gateway independent MX without autodiscover stays independent."""
        result = classify(
            ["mail.example.ch"],
            "",
            autodiscover=None,
        )
        assert result[0] == "independent"

    def test_gateway_empty_autodiscover_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            autodiscover={},
        )
        assert result[0] == "independent"

    def test_gateway_autodiscover_none_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            autodiscover=None,
        )
        assert result[0] == "independent"

    # ── SPF-only resolved fallback ──

    def test_spf_only_resolved_fallback(self):
        """No MX, raw SPF has no keywords, resolved_spf has Microsoft -> microsoft."""
        result = classify(
            [],
            "v=spf1 include:custom.ch -all",
            resolved_spf="v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"

    def test_spf_only_raw_takes_precedence(self):
        """No MX, raw SPF has Google, resolved_spf has Microsoft -> google (raw wins)."""
        result = classify(
            [],
            "v=spf1 include:_spf.google.com -all",
            resolved_spf="v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "google"

    def test_spf_only_no_resolved_stays_unknown(self):
        """No MX, raw SPF has no keywords, no resolved_spf -> unknown."""
        result = classify(
            [],
            "v=spf1 ip4:1.2.3.4 -all",
            resolved_spf=None,
        )
        assert result[0] == "unknown"

    # ── Reason field ──

    def test_reason_present_for_microsoft_mx(self):
        _, reason = classify(["bern-ch.mail.protection.outlook.com"], "")
        assert "Microsoft" in reason

    def test_reason_present_for_independent(self):
        _, reason = classify(["mail.example.ch"], "")
        assert "self-hosted" in reason

    def test_reason_present_for_unknown(self):
        _, reason = classify([], "")
        assert "no MX" in reason

    def test_reason_present_for_gateway(self):
        _, reason = classify(
            ["customer.seppmail.cloud"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert "gateway" in reason

    # ── DKIM in classify() ──

    def test_non_gateway_dkim_reveals_microsoft(self):
        result = classify(
            ["mail.example.ch"],
            "",
            dkim={"selector1": "selector1-example._domainkey.example.onmicrosoft.com"},
        )
        assert result[0] == "microsoft"
        assert "DKIM" in result[1]

    def test_non_gateway_dkim_reveals_google(self):
        result = classify(
            ["mail.example.ch"],
            "",
            dkim={"google": "google._domainkey.example.google.com"},
        )
        assert result[0] == "google"

    # ── TXT verification in gateway ──

    def test_gateway_txt_verification_microsoft(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            txt_verifications={"microsoft": "abc123"},
        )
        assert result[0] == "microsoft"
        assert "TXT verification" in result[1]


# ── Gateway SPF hardening tests (Step 6) ────────────────────────────


class TestGatewayHardening:
    def test_gateway_spf_confirmed_by_dkim(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
            dkim={"selector1": "selector1._domainkey.example.onmicrosoft.com"},
        )
        assert result[0] == "microsoft"
        assert "SPF+DKIM confirm" in result[1]

    def test_gateway_spf_confirmed_by_autodiscover(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result[0] == "microsoft"
        assert "SPF+autodiscover confirm" in result[1]

    def test_gateway_spf_contradicted_by_dkim(self):
        """DKIM overrides SPF when they disagree."""
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 include:_spf.google.com -all",
            dkim={"selector1": "selector1._domainkey.example.onmicrosoft.com"},
        )
        assert result[0] == "microsoft"
        assert "DKIM overrides SPF" in result[1]

    def test_gateway_no_spf_dkim_only(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            dkim={"selector1": "selector1._domainkey.example.onmicrosoft.com"},
        )
        assert result[0] == "microsoft"
        assert "DKIM signs via" in result[1]

    def test_gateway_no_spf_txt_verification_only(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            txt_verifications={"google": "abc123"},
        )
        assert result[0] == "google"
        assert "TXT verification" in result[1]

    def test_gateway_no_signals_falls_through(self):
        """Gateway with no SPF/AD/DKIM/TXT -> falls through to independent."""
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result[0] == "independent"

    def test_gateway_spf_alone_when_no_other_signals(self):
        """SPF trusted alone when no DKIM or autodiscover available."""
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result[0] == "microsoft"
        assert "SPF points to" in result[1]


# ── classify_from_autodiscover() ────────────────────────────────────


class TestClassifyFromAutodiscover:
    def test_none_returns_none(self):
        assert classify_from_autodiscover(None) is None

    def test_empty_dict_returns_none(self):
        assert classify_from_autodiscover({}) is None

    def test_microsoft_cname(self):
        assert (
            classify_from_autodiscover(
                {"autodiscover_cname": "autodiscover.outlook.com"}
            )
            == "microsoft"
        )

    def test_google_srv(self):
        assert (
            classify_from_autodiscover({"autodiscover_srv": "autodiscover.google.com"})
            == "google"
        )

    def test_unrecognized_returns_none(self):
        assert (
            classify_from_autodiscover(
                {"autodiscover_cname": "autodiscover.custom-host.ch"}
            )
            is None
        )


# ── classify_from_dkim() ───────────────────────────────────────────


class TestClassifyFromDkim:
    def test_none_returns_none(self):
        assert classify_from_dkim(None) is None

    def test_empty_dict_returns_none(self):
        assert classify_from_dkim({}) is None

    def test_microsoft_onmicrosoft(self):
        assert (
            classify_from_dkim(
                {"selector1": "selector1._domainkey.tenant.onmicrosoft.com"}
            )
            == "microsoft"
        )

    def test_google(self):
        assert (
            classify_from_dkim({"google": "google._domainkey.example.google.com"})
            == "google"
        )

    def test_googlemail(self):
        assert (
            classify_from_dkim({"google": "google._domainkey.googlemail.com"})
            == "google"
        )

    def test_unrecognized_returns_none(self):
        assert (
            classify_from_dkim({"selector1": "selector1._domainkey.custom.ch"}) is None
        )


# ── classify_from_txt_verifications() ──────────────────────────────


class TestClassifyFromTxtVerifications:
    def test_none_returns_none(self):
        assert classify_from_txt_verifications(None) is None

    def test_empty_dict_returns_none(self):
        assert classify_from_txt_verifications({}) is None

    def test_microsoft(self):
        assert classify_from_txt_verifications({"microsoft": "abc123"}) == "microsoft"

    def test_google(self):
        assert classify_from_txt_verifications({"google": "abc123"}) == "google"

    def test_microsoft_takes_precedence(self):
        assert (
            classify_from_txt_verifications({"microsoft": "a", "google": "b"})
            == "microsoft"
        )

    def test_unknown_provider_returns_none(self):
        assert classify_from_txt_verifications({"aws": "abc"}) is None


# ── detect_gateway() ────────────────────────────────────────────────


class TestDetectGateway:
    def test_seppmail(self):
        assert detect_gateway(["customer.seppmail.cloud"]) == "seppmail"

    def test_cleanmail(self):
        assert detect_gateway(["mx.cleanmail.ch"]) == "cleanmail"

    def test_barracuda(self):
        assert detect_gateway(["mail.barracudanetworks.com"]) == "barracuda"

    def test_trendmicro(self):
        assert detect_gateway(["filter.tmes.trendmicro.eu"]) == "trendmicro"

    def test_hornetsecurity(self):
        assert detect_gateway(["mx01.hornetsecurity.com"]) == "hornetsecurity"

    def test_abxsec(self):
        assert detect_gateway(["mta1.abxsec.com"]) == "abxsec"

    def test_proofpoint(self):
        assert detect_gateway(["mx1.ppe-hosted.com"]) == "proofpoint"

    def test_proofpoint_pphosted(self):
        assert detect_gateway(["mx1.pphosted.com"]) == "proofpoint"

    def test_sophos(self):
        assert detect_gateway(["mx.hydra.sophos.com"]) == "sophos"

    def test_spamvor(self):
        assert detect_gateway(["relay.spamvor.com"]) == "spamvor"

    def test_fortimail(self):
        assert detect_gateway(["mail.fortimailcloud.com"]) == "fortimail"

    def test_fortimail_keyword(self):
        assert detect_gateway(["fortimail.example.de"]) == "fortimail"

    def test_nospamproxy(self):
        assert detect_gateway(["mx.nospamproxy.de"]) == "nospamproxy"

    def test_nospamproxy_asscan(self):
        assert detect_gateway(["mx.as-scan.de"]) == "nospamproxy"

    def test_antispameurope(self):
        assert detect_gateway(["mx.antispameurope.com"]) == "antispameurope"

    def test_retarus(self):
        assert detect_gateway(["mx.retarus.com"]) == "retarus"

    def test_mimecast(self):
        assert detect_gateway(["eu.mimecast.com"]) == "mimecast"

    def test_spamexperts(self):
        assert detect_gateway(["mx.spamexperts.eu"]) == "spamexperts"

    def test_spamexperts_net(self):
        assert detect_gateway(["mx.spamexperts.net"]) == "spamexperts"

    def test_spamexperts_com(self):
        assert detect_gateway(["mx.spamexperts.com"]) == "spamexperts"

    def test_no_gateway(self):
        assert detect_gateway(["mail.example.ch"]) is None

    def test_empty_list(self):
        assert detect_gateway([]) is None

    def test_case_insensitive(self):
        assert detect_gateway(["CUSTOMER.SEPPMAIL.CLOUD"]) == "seppmail"


# ── classify_from_mx() ──────────────────────────────────────────────


class TestClassifyFromMx:
    def test_empty_returns_none(self):
        assert classify_from_mx([]) is None

    def test_microsoft(self):
        assert classify_from_mx(["mail.protection.outlook.com"]) == "microsoft"

    def test_google(self):
        assert classify_from_mx(["aspmx.l.google.com"]) == "google"

    def test_unrecognized_returns_independent(self):
        assert classify_from_mx(["mail.custom.ch"]) == "independent"

    def test_case_insensitive(self):
        assert classify_from_mx(["MAIL.PROTECTION.OUTLOOK.COM"]) == "microsoft"


# ── classify_from_spf() ─────────────────────────────────────────────


class TestClassifyFromSpf:
    def test_empty_returns_none(self):
        assert classify_from_spf("") is None

    def test_none_returns_none(self):
        assert classify_from_spf(None) is None

    def test_microsoft(self):
        assert (
            classify_from_spf("v=spf1 include:spf.protection.outlook.com -all")
            == "microsoft"
        )

    def test_unrecognized_returns_none(self):
        assert classify_from_spf("v=spf1 include:custom.ch -all") is None


# ── spf_mentions_providers() ─────────────────────────────────────────


class TestSpfMentionsProviders:
    def test_empty_returns_empty(self):
        assert spf_mentions_providers("") == set()

    def test_single_provider(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com -all"
        )
        assert result == {"microsoft"}

    def test_multiple_providers(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"
        )
        assert result == {"microsoft", "google"}

    def test_detects_mailchimp(self):
        result = spf_mentions_providers(
            "v=spf1 include:servers.mcsv.net include:spf.mandrillapp.com -all"
        )
        assert "mailchimp" in result

    def test_detects_sendgrid(self):
        result = spf_mentions_providers("v=spf1 include:sendgrid.net -all")
        assert result == {"sendgrid"}

    def test_mixed_main_and_foreign(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:spf.mandrillapp.com -all"
        )
        assert result == {"microsoft", "mailchimp"}

    def test_detects_smtp2go(self):
        result = spf_mentions_providers("v=spf1 include:spf.smtp2go.com -all")
        assert "smtp2go" in result

    def test_detects_nl2go(self):
        result = spf_mentions_providers("v=spf1 include:spf.nl2go.com -all")
        assert "nl2go" in result

    def test_foreign_sender_not_in_classify(self):
        assert classify([], "v=spf1 include:spf.mandrillapp.com -all")[0] == "unknown"

    def test_foreign_sender_not_in_classify_from_spf(self):
        assert classify_from_spf("v=spf1 include:spf.mandrillapp.com -all") is None


# ── classify_from_smtp_banner() ────────────────────────────────────


class TestClassifyFromSmtpBanner:
    def test_empty_returns_none(self):
        assert classify_from_smtp_banner("") is None

    def test_both_empty_returns_none(self):
        assert classify_from_smtp_banner("", "") is None

    def test_microsoft_banner(self):
        assert (
            classify_from_smtp_banner(
                "220 BL02EPF0001CA17.mail.protection.outlook.com "
                "Microsoft ESMTP MAIL Service ready"
            )
            == "microsoft"
        )

    def test_microsoft_outlook_com(self):
        assert (
            classify_from_smtp_banner("220 something.outlook.com ready") == "microsoft"
        )

    def test_google_banner(self):
        assert classify_from_smtp_banner("220 mx.google.com ESMTP ready") == "google"

    def test_google_esmtp_in_ehlo(self):
        assert (
            classify_from_smtp_banner("220 custom.example.ch", "250 Google ESMTP ready")
            == "google"
        )

    def test_aws_banner(self):
        assert (
            classify_from_smtp_banner("220 inbound-smtp.eu-west-1.amazonaws.com ESMTP")
            == "aws"
        )

    def test_postfix_returns_none(self):
        assert classify_from_smtp_banner("220 mail.example.ch ESMTP Postfix") is None

    def test_exim_returns_none(self):
        assert classify_from_smtp_banner("220 mail.example.ch ESMTP Exim 4.96") is None

    def test_case_insensitive(self):
        assert (
            classify_from_smtp_banner(
                "220 MAIL.PROTECTION.OUTLOOK.COM MICROSOFT ESMTP MAIL SERVICE"
            )
            == "microsoft"
        )


# ── Domestic ISP classification ────────────────────────────────────


DE_DOMESTIC = DomesticConfig(
    asns={3320: "Deutsche Telekom", 24940: "Hetzner", 8560: "IONOS"},
    domains=["strato.de", "hetzner.com", "ionos.com"],
    country_tlds=[".de"],
    target_country="DE",
    label="german-isp",
)

CH_DOMESTIC = DomesticConfig(
    asns={3303: "Swisscom", 29691: "Hostpoint"},
    domains=["cyon.net", "hostpoint.ch"],
    country_tlds=[".ch", ".swiss"],
    target_country="CH",
    label="swiss-isp",
)


class TestDomesticClassification:
    def test_asn_match(self):
        result = classify(
            ["mail.example.de"],
            "",
            mx_asns={24940},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_geoip_match_non_hyperscaler(self):
        result = classify(
            ["mail.example.de"],
            "",
            mx_asns={99999},
            mx_geoip_countries={"DE"},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_geoip_match_hyperscaler_only_stays_independent(self):
        result = classify(
            ["mail.example.de"],
            "",
            mx_asns={8075},
            mx_geoip_countries={"DE"},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "independent"

    def test_geoip_match_no_asns(self):
        """GeoIP match with no ASN data at all should classify as domestic."""
        result = classify(
            ["mail.example.de"],
            "",
            mx_asns=None,
            mx_geoip_countries={"DE"},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_ptr_domain_match(self):
        result = classify(
            ["mail.example.de"],
            "",
            mx_ptrs={"1.2.3.4": "mail.strato.de"},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_ptr_tld_match(self):
        result = classify(
            ["mail.example.com"],
            "",
            mx_ptrs={"1.2.3.4": "server.someprovider.de"},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_mx_domain_match(self):
        result = classify(
            ["mail.hetzner.com"],
            "",
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_mx_tld_match(self):
        result = classify(
            ["mail.someprovider.de"],
            "",
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_no_domestic_config_stays_independent(self):
        result = classify(
            ["mail.example.de"],
            "",
            domestic=None,
        )
        assert result[0] == "independent"

    def test_hyperscaler_mx_not_overridden(self):
        result = classify(
            ["bern-ch.mail.protection.outlook.com"],
            "",
            mx_asns={3303},
            domestic=CH_DOMESTIC,
        )
        assert result[0] == "microsoft"

    def test_gateway_with_domestic_backend(self):
        """Gateway with no hyperscaler SPF + domestic ASN -> domestic."""
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 ip4:1.2.3.4 -all",
            mx_asns={3303},
            domestic=CH_DOMESTIC,
        )
        assert result[0] == "swiss-isp"

    def test_gateway_with_hyperscaler_spf_not_domestic(self):
        """Gateway with hyperscaler SPF should return hyperscaler, not domestic."""
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 include:spf.protection.outlook.com -all",
            mx_asns={3303},
            domestic=CH_DOMESTIC,
        )
        assert result[0] == "microsoft"

    def test_swiss_domestic_ch_tld(self):
        result = classify(
            ["mail.gemeinde.ch"],
            "",
            domestic=CH_DOMESTIC,
        )
        assert result[0] == "swiss-isp"

    def test_no_signals_stays_independent(self):
        result = classify(
            ["mail.example.com"],
            "",
            mx_asns={99999},
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "independent"


# ── _classify_from_spf_asns() ─────────────────────────────────────


class TestClassifyFromSpfAsns:
    def test_none_returns_none(self):
        assert _classify_from_spf_asns(None) is None

    def test_empty_set_returns_none(self):
        assert _classify_from_spf_asns(set()) is None

    def test_microsoft_asn(self):
        assert _classify_from_spf_asns({8075}) == "microsoft"

    def test_google_asn(self):
        assert _classify_from_spf_asns({15169}) == "google"

    def test_unknown_asn_returns_none(self):
        assert _classify_from_spf_asns({99999}) is None

    def test_microsoft_takes_priority_over_google(self):
        """When both Microsoft and Google ASNs present, microsoft wins."""
        assert _classify_from_spf_asns({8075, 15169}) == "microsoft"

    def test_all_microsoft_asns(self):
        assert _classify_from_spf_asns({8070}) == "microsoft"
        assert _classify_from_spf_asns({3598}) == "microsoft"


# ── SPF-ASN integration in classify() ────────────────────────────


class TestClassifySpfAsnIntegration:
    def test_spf_asn_microsoft_over_independent(self):
        """Independent MX + Microsoft SPF ASN -> microsoft."""
        result = classify(
            ["mail.example.de"],
            "v=spf1 ip4:40.92.0.0/24 -all",
            spf_asns={8075},
        )
        assert result[0] == "microsoft"

    def test_spf_asn_after_autodiscover(self):
        """Autodiscover takes precedence over SPF ASN."""
        result = classify(
            ["mail.example.de"],
            "",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
            spf_asns={15169},  # Google ASN -- should be ignored
        )
        assert result[0] == "microsoft"

    def test_spf_asn_before_domestic(self):
        """SPF ASN takes precedence over domestic ISP classification."""
        result = classify(
            ["mail.example.de"],
            "v=spf1 ip4:40.92.0.0/24 -all",
            mx_asns={24940},  # Hetzner -- domestic
            spf_asns={8075},  # Microsoft
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "microsoft"

    def test_spf_asn_none_no_change(self):
        """Backward compat: spf_asns=None doesn't change classification."""
        result = classify(
            ["mail.example.de"],
            "",
            spf_asns=None,
            domestic=DE_DOMESTIC,
        )
        # Should use .de TLD heuristic -> german-isp
        assert result[0] == "german-isp"

    def test_spf_asn_empty_set_no_change(self):
        """Empty spf_asns set doesn't change classification."""
        result = classify(
            ["mail.example.de"],
            "",
            spf_asns=set(),
            domestic=DE_DOMESTIC,
        )
        assert result[0] == "german-isp"

    def test_spf_asn_google_over_independent(self):
        """Independent MX + Google SPF ASN -> google."""
        result = classify(
            ["mail.example.com"],
            "v=spf1 ip4:74.125.0.0/24 -all",
            spf_asns={15169},
        )
        assert result[0] == "google"
