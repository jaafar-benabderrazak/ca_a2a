from pathlib import Path


def _read(p: str) -> str:
    return Path(p).read_text(encoding="utf-8", errors="ignore")


def test_service_connect_flags_present():
    txt = _read("deploy-sso-phase2.sh")
    assert "--service-connect-configuration" in txt
    assert "portMappings" in txt and "\"name\": \"http\"" in txt


def test_per_agent_sg_vars_present():
    for p in ["deploy.sh", "deploy-manual.sh", "deploy-sso-phase1.sh", "deploy-sso-phase2.sh"]:
        txt = _read(p)
        assert "ORCHESTRATOR_SG" in txt
        assert "EXTRACTOR_SG" in txt
        assert "VALIDATOR_SG" in txt
        assert "ARCHIVIST_SG" in txt

