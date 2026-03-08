from artemis.modules.cookie_security import analyze_cookie_headers


def test_flags_missing_httponly_and_samesite():
    issues = analyze_cookie_headers(
        {"Set-Cookie": "sid=abc123; Secure"},
        request_url="https://example.com/",
    )
    codes = {i.code for i in issues}
    assert "COOKIE_MISSING_HTTPONLY" in codes
    assert "COOKIE_MISSING_SAMESITE" in codes


def test_flags_samesite_none_without_secure_high():
    issues = analyze_cookie_headers(
        {"Set-Cookie": "sid=abc123; SameSite=None; HttpOnly"},
        request_url="https://example.com/",
    )
    codes = {i.code for i in issues}
    assert "COOKIE_SAMESITE_NONE_WITHOUT_SECURE" in codes


def test_flags_missing_secure_on_https():
    issues = analyze_cookie_headers(
        {"Set-Cookie": "sid=abc123; HttpOnly; SameSite=Lax"},
        request_url="https://example.com/",
    )
    codes = {i.code for i in issues}
    assert "COOKIE_MISSING_SECURE" in codes