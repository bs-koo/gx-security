"""The installed wheel must retain the scanners and rule packs it calls."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_distribution_build_copies_real_assets(tmp_path):
    spec = importlib.util.spec_from_file_location("gxsec_setup", ROOT / "setup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / "gxsec" / "_assets"
    module.copy_runtime_assets(target)
    assert (target / "scan_all.py").exists()
    assert (target / "tools" / "scanner_contract.py").exists()
    rule_files = list((target / "skills").glob("detecting-*/rules/*.yml"))
    assert len(rule_files) == 10
    assert any(p.name == "xss-frontend.yml" for p in rule_files)
    assert not list(target.rglob("*.pyc"))
