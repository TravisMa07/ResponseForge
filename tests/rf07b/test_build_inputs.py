"""An installer template included in the wheel must change the build identity."""

from scripts import shuffle_runtime


def test_changed_installer_template_changes_source_build_fingerprint(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    source = root / "src/responseforge/integrations/wazuh"
    source.mkdir(parents=True)
    template = source / "Install.ps1"
    template.write_text("# original synthetic installer input\n")
    script = root / "scripts/shuffle_runtime.py"
    script.parent.mkdir()
    script.write_text("# fixed synthetic build driver identity\n")
    monkeypatch.setattr(shuffle_runtime, "ROOT", root)
    monkeypatch.setattr(shuffle_runtime, "RUNTIME", root / "deploy/shuffle/runtime")
    monkeypatch.setattr(shuffle_runtime, "__file__", str(script))
    before = shuffle_runtime.fingerprint()
    template.write_text("# changed synthetic installer input\n")
    assert shuffle_runtime.fingerprint() != before
