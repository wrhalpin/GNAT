"""
tests/unit/test_xsoar_generator.py
====================================

Unit tests for gnat.codegen.xsoar_generator.generate_xsoar_pack().
"""

import json
import os
import zipfile

import pytest

from gnat.codegen.xsoar_generator import (
    _method_to_xsoar_command,
    _render_integration_py,
    _render_integration_yml,
    _render_pack_metadata,
    _render_release_notes,
    _to_kebab,
    _to_pascal,
    generate_xsoar_pack,
)

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

class TestToPascal:
    def test_snake_case(self):
        assert _to_pascal("threat_q") == "ThreatQ"

    def test_kebab_case(self):
        assert _to_pascal("threat-q") == "ThreatQ"

    def test_single_word(self):
        assert _to_pascal("splunk") == "Splunk"

    def test_multi_word(self):
        assert _to_pascal("recorded_future") == "RecordedFuture"


class TestToKebab:
    def test_snake_to_kebab(self):
        assert _to_kebab("recorded_future") == "recorded-future"

    def test_already_kebab(self):
        assert _to_kebab("crowdstrike") == "crowdstrike"


# ---------------------------------------------------------------------------
# Command definition builder
# ---------------------------------------------------------------------------

class TestMethodToXSOARCommand:

    def test_returns_dict_with_required_keys(self):
        meta = {"type": "read", "signature": "(stix_type, page_size)",
                "doc": "List objects.", "platform_specific": False}
        cmd = _method_to_xsoar_command("list_objects", meta, "threatq")
        assert isinstance(cmd, dict)
        assert "name" in cmd
        assert "arguments" in cmd
        assert "outputs" in cmd

    def test_command_name_prefixed(self):
        meta = {"type": "read", "signature": "(stix_type)", "doc": "", "platform_specific": False}
        cmd = _method_to_xsoar_command("get_object", meta, "crowdstrike")
        assert cmd["name"] == "crowdstrike-get-object"

    def test_write_command_has_dangerous_flag(self):
        meta = {"type": "write", "signature": "(stix_type, payload)",
                "doc": "Upsert.", "platform_specific": False}
        cmd = _method_to_xsoar_command("upsert_object", meta, "xsoar")
        assert cmd.get("dangerous") is True

    def test_read_command_no_dangerous_flag(self):
        meta = {"type": "read", "signature": "(stix_type)", "doc": "", "platform_specific": False}
        cmd = _method_to_xsoar_command("list_objects", meta, "xsoar")
        assert "dangerous" not in cmd

    def test_args_extracted_from_signature(self):
        meta = {"type": "read", "signature": "(stix_type, page_size)",
                "doc": "", "platform_specific": False}
        cmd = _method_to_xsoar_command("list_objects", meta, "splunk")
        arg_names = [a["name"] for a in cmd["arguments"]]
        assert "stix_type" in arg_names
        assert "page_size" in arg_names

    def test_empty_signature_no_args(self):
        meta = {"type": "read", "signature": "()", "doc": "", "platform_specific": False}
        cmd = _method_to_xsoar_command("health_check", meta, "splunk")
        assert cmd["arguments"] == []

    def test_output_context_path_contains_method(self):
        meta = {"type": "read", "signature": "(stix_type)", "doc": "", "platform_specific": False}
        cmd = _method_to_xsoar_command("list_objects", meta, "threatq")
        cp = cmd["outputs"][0]["contextPath"]
        assert "list_objects" in cp
        assert "Threatq" in cp or "GNAT" in cp


# ---------------------------------------------------------------------------
# Renderer smoke tests
# ---------------------------------------------------------------------------

class TestRenderers:

    def test_pack_metadata_is_valid_json(self):
        content = _render_pack_metadata("ThreatQ", "threatq")
        data = json.loads(content)
        assert data["name"] == "GNAT ThreatQ"
        assert "currentVersion" in data

    def test_pack_metadata_version_passed_through(self):
        content = _render_pack_metadata("Splunk", "splunk", version="2.3.4")
        data = json.loads(content)
        assert data["currentVersion"] == "2.3.4"

    def test_release_notes_contains_version(self):
        rn = _render_release_notes("1.2.3")
        assert "1.2.3" in rn

    def test_integration_yml_contains_connector_name(self):
        yml = _render_integration_yml("threatq", "ThreatQ", [], "api_key")
        assert "ThreatQ" in yml
        assert "api_key" in yml or "API Key" in yml

    def test_integration_yml_oauth2_has_client_id(self):
        yml = _render_integration_yml("threatq", "ThreatQ", [], "oauth2")
        assert "client_id" in yml or "Client ID" in yml

    def test_integration_yml_basic_has_username(self):
        yml = _render_integration_yml("proofpoint", "Proofpoint", [], "basic")
        assert "username" in yml or "Username" in yml

    def test_integration_yml_includes_commands(self):
        cmds = [
            {"name": "threatq-list-objects", "description": "List objects",
             "arguments": [{"name": "stix_type", "required": True,
                            "description": "Type", "type": "String"}],
             "outputs": [{"contextPath": "GNAT.Threatq.list_objects",
                          "description": "Result", "type": "Unknown"}]},
        ]
        yml = _render_integration_yml("threatq", "ThreatQ", cmds, "api_key")
        assert "threatq-list-objects" in yml
        assert "stix_type" in yml

    def test_integration_py_imports_gnat(self):
        py = _render_integration_py("ThreatQ", "threatq", [], "api_key")
        assert "from gnat.clients import CLIENT_REGISTRY" in py
        assert 'CONNECTOR_KEY = "threatq"' in py

    def test_integration_py_contains_main(self):
        py = _render_integration_py("Splunk", "splunk", [], "basic")
        assert "def main():" in py
        assert "def build_connector():" in py

    def test_integration_py_write_command_uses_allow_write(self):
        cmds = [
            {"name": "xsoar-upsert-object", "description": "Upsert",
             "arguments": [], "outputs": [], "dangerous": True},
        ]
        py = _render_integration_py("XSOAR", "xsoar", cmds, "api_key")
        assert "allow_write=True" in py


# ---------------------------------------------------------------------------
# generate_xsoar_pack() — end-to-end
# ---------------------------------------------------------------------------

class TestGenerateXSOARPack:

    def test_returns_zip_path(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        assert zip_path.endswith(".zip")
        assert os.path.isfile(zip_path)

    def test_zip_contains_pack_metadata(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        assert any("pack_metadata.json" in n for n in names)

    def test_zip_contains_integration_yml(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        assert any(".yml" in n for n in names)

    def test_zip_contains_integration_py(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        assert any(".py" in n for n in names)

    def test_zip_contains_release_notes(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        assert any("ReleaseNotes" in n for n in names)

    def test_pack_metadata_valid_json(self, tmp_path):
        zip_path = generate_xsoar_pack("crowdstrike", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            meta_name = next(n for n in zf.namelist() if "pack_metadata" in n)
            data = json.loads(zf.read(meta_name))
        assert data["currentVersion"] == "1.0.0"
        assert "crowdstrike" in data.get("tags", [])

    def test_version_in_zip_name(self, tmp_path):
        zip_path = generate_xsoar_pack("splunk", output_dir=str(tmp_path),
                                        version="2.0.0")
        assert "2.0.0" in os.path.basename(zip_path)

    def test_unknown_connector_raises_key_error(self, tmp_path):
        with pytest.raises(KeyError, match="not found in CLIENT_REGISTRY"):
            generate_xsoar_pack("nonexistent_platform", output_dir=str(tmp_path))

    def test_overwrite_false_raises_if_exists(self, tmp_path):
        generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        with pytest.raises(FileExistsError):
            generate_xsoar_pack("threatq", output_dir=str(tmp_path), overwrite=False)

    def test_overwrite_true_replaces_file(self, tmp_path):
        zip1 = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        mtime1 = os.path.getmtime(zip1)
        import time
        time.sleep(0.05)
        zip2 = generate_xsoar_pack("threatq", output_dir=str(tmp_path), overwrite=True)
        assert zip1 == zip2
        assert os.path.getmtime(zip2) >= mtime1

    def test_auth_type_override(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path),
                                        auth_type="basic")
        with zipfile.ZipFile(zip_path) as zf:
            yml_name = next(n for n in zf.namelist() if n.endswith(".yml"))
            yml = zf.read(yml_name).decode()
        assert "username" in yml or "Username" in yml

    def test_integration_py_references_connector(self, tmp_path):
        zip_path = generate_xsoar_pack("xsoar", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            py_name = next(n for n in zf.namelist() if n.endswith(".py"))
            py = zf.read(py_name).decode()
        assert 'CONNECTOR_KEY = "xsoar"' in py

    def test_write_methods_flagged_dangerous_in_yml(self, tmp_path):
        zip_path = generate_xsoar_pack("threatq", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            yml_name = next(n for n in zf.namelist() if n.endswith(".yml"))
            yml = zf.read(yml_name).decode()
        assert "dangerous: true" in yml

    def test_platform_specific_method_in_yml(self, tmp_path):
        """link_incident on XSOAR connector should appear as an XSOAR command."""
        zip_path = generate_xsoar_pack("xsoar", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            yml_name = next(n for n in zf.namelist() if n.endswith(".yml"))
            yml = zf.read(yml_name).decode()
        assert "link-incident" in yml

    def test_output_dir_created_if_absent(self, tmp_path):
        new_dir = str(tmp_path / "new" / "sub")
        assert not os.path.exists(new_dir)
        zip_path = generate_xsoar_pack("netskope", output_dir=new_dir)
        assert os.path.isfile(zip_path)

    def test_greymatter_link_investigation_in_yml(self, tmp_path):
        zip_path = generate_xsoar_pack("greymatter", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            yml_name = next(n for n in zf.namelist() if n.endswith(".yml"))
            yml = zf.read(yml_name).decode()
        assert "link-investigation" in yml

    def test_servicenow_annotate_incident_in_yml(self, tmp_path):
        zip_path = generate_xsoar_pack("servicenow", output_dir=str(tmp_path))
        with zipfile.ZipFile(zip_path) as zf:
            yml_name = next(n for n in zf.namelist() if n.endswith(".yml"))
            yml = zf.read(yml_name).decode()
        assert "annotate-incident" in yml
