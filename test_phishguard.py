# test_phishguard.py
# Simple tests to make sure PhishGuard works properly

from fastapi.testclient import TestClient
from analyzer import analyze_message, check_url
from app import app

client = TestClient(app)


def test_low_risk_warranty_message():
    # Make sure 'warranty' does NOT falsely trigger 'warrant' and 'groups' does NOT trigger 'ups'
    msg = "Your 1-year product warranty registration is complete for all groups."
    res = analyze_message(msg)
    assert res["verdict"] == "LOW RISK"
    assert res["overall_score"] == 0


def test_paypal_homograph():
    msg = "Dear Customer, unauthorized transaction on PayPal. Suspend within 24 hours: https://p\u0430ypal.com/login"
    res = analyze_message(msg)
    assert res["verdict"] == "HIGH RISK"
    assert res["overall_score"] >= 50


def test_usps_subdomain_scam():
    url_info = check_url("https://usps.com.track-redelivery-usa.xyz/login")
    assert url_info["real_domain"] == "track-redelivery-usa.xyz"
    assert url_info["points"] >= 50


def test_job_scam_and_api_endpoint():
    response = client.post(
        "/api/analyze",
        json={"text": "We are hiring for a remote part-time job. Earn $500 a day via WhatsApp to apply at https://bit.ly/job"}
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "HIGH RISK"
    assert response.json()["scam_type"] == "Job / Task Scam"


def test_url_credential_spoofing_bypass():
    # Ensure user@host credential trick resolves to the actual destination domain
    url_info = check_url("https://www.paypal.com:443@evil.xyz/login")
    assert url_info["real_domain"] == "evil.xyz"
    assert url_info["points"] >= 50


def test_invalid_and_oversized_api_payloads():
    # Non-object JSON should return 400 instead of 500
    res_list = client.post("/api/analyze", json=["not", "an", "object"])
    assert res_list.status_code == 400

    # Malformed JSON should return 400 instead of 500
    res_bad = client.post(
        "/api/analyze",
        content=b"{invalid json",
        headers={"Content-Type": "application/json"}
    )
    assert res_bad.status_code == 400

    # Oversized payload (>64KB) should return 413
    res_large = client.post(
        "/api/analyze",
        content=b'{"text":"' + (b"A" * 70000) + b'"}',
        headers={"Content-Type": "application/json"}
    )
    assert res_large.status_code == 413


def test_security_headers():
    res = client.get("/")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"
    assert "Content-Security-Policy" in res.headers


def test_irs_sample_brand_disambiguation():
    # Verify requested credentials (SSN) and payment cards (Apple gift cards) do not trigger false brand impersonation
    msg = (
        "FINAL WARNING: IRS warrant issued for back taxes. "
        "Verify your Social Security Number or pay with Apple gift cards immediately at http://192.168.45.210/irs"
    )
    res = analyze_message(msg)
    assert res["verdict"] == "HIGH RISK"
    assert res["scam_type"] == "Government Impersonation (IRS)"
    assert res["verified_brand_help"] is not None
    assert res["verified_brand_help"]["brand"] == "IRS"
    assert res["verified_brand_help"]["official_domain"] == "irs.gov"

    # Make sure SSA and Apple are NOT flagged as impersonated brands
    for r in res["reasons"]:
        assert "SOCIAL SECURITY" not in r
        assert "APPLE" not in r

    # Verify genuine Apple impersonation still works
    apple_msg = "Apple Support: Unusual sign-in to your Apple ID. Verify at https://apple-login.top/account"
    res_apple = analyze_message(apple_msg)
    assert res_apple["verified_brand_help"]["brand"] == "APPLE"

    # Verify genuine Social Security Administration impersonation still works
    ssa_msg = "Social Security Administration alert: Your benefits have been suspended. Verify at https://ssa-portal.xyz/login"
    res_ssa = analyze_message(ssa_msg)
    assert res_ssa["verified_brand_help"]["brand"] == "SOCIAL SECURITY"


def test_homoglyph_amazon_recruiting_job_scam():
    msg = (
        "Hі, mу namе iѕ Cаmіla, and Ι’m getting іn touch wіth уou оn bеhаlf оf Αmazоn Recruitіng.\n\n"
        "Bаsed οn yοur рrоfilе, you соuld be well suitеd fοr а part-timе rеmоtе oррortunitу currently аvаіlablе wіth uѕ. "
        "Τhе work maіnlу centerѕ оn mаintаinіng uрdated produсt informatіon for mеrсhаntѕ.\n\n"
        "🎓 Gеt acсеss to frеe trаіning frοm thе bеgіnning οf thе rοle.\n"
        "⏳ Wοrk only 60–90 minutеs per dаy оn а flехible 4-day wеeklу schеdulе.\n"
        "💵 Εarn $250–$500 dаіlу, inсluding a $1,000 bаse ѕаlаrу fοr 4 wοrkdаyѕ, with 15–20 days of paid аnnuаl leаvе.\n\n"
        "Wе hаvе 20 рoѕіtіonѕ available now. Ιf yοu arе at leaѕt 22 yeаrѕ old and intеrested, рleaѕe tеxt+16312949254 to leаrn mοre."
    )
    res = analyze_message(msg)
    assert res["verdict"] == "HIGH RISK"
    assert res["overall_score"] >= 80
    assert "Job / Task Scam" in res["scam_type"]
    assert res["verified_brand_help"] is not None
    assert res["verified_brand_help"]["brand"] == "AMAZON"
    assert any("lookalike characters" in r for r in res["reasons"])
    assert any("+16312949254" in r for r in res["reasons"])


