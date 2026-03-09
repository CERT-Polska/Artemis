from artemis.modules.cors_misconfiguration import analyze_cors_headers


def test_wildcard_credentials():

    issues = analyze_cors_headers(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    codes = {i.code for i in issues}

    assert "CORS_WILDCARD_WITH_CREDENTIALS" in codes


def test_origin_reflection():

    origin = "https://attacker.example"

    issues = analyze_cors_headers(
        {"Access-Control-Allow-Origin": origin},
        sent_origin=origin,
    )

    codes = {i.code for i in issues}

    assert "CORS_ORIGIN_REFLECTION" in codes