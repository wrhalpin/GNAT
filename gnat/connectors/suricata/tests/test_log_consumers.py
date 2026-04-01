"""
tests for Suricata, Snort, and Zeek log-consumer connectors.

These connectors read log files instead of making HTTP calls,
so tests use temporary files and StringIO rather than HTTP mocks.
"""

import configparser
import json
import os
import tempfile
import unittest

from gnat.connectors.snort import (
    SnortConfig,
    SnortConfigError,
    SnortFastReader,
    SnortJSONReader,
    SnortLogError,
    SnortSTIXMapper,
    load_snort_config,
)
from gnat.connectors.suricata import (
    SuricataConfig,
    SuricataConfigError,
    SuricataEVEReader,
    SuricataLogError,
    SuricataSTIXMapper,
    load_suricata_config,
)
from gnat.connectors.zeek import (
    ZeekConfig,
    ZeekConfigError,
    ZeekJSONReader,
    ZeekLogCommands,
    ZeekLogError,
    ZeekSTIXMapper,
    ZeekTSVReader,
    load_zeek_config,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _write_temp(content: str, suffix: str = ".log") -> str:
    """Write content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# SURICATA
# ═══════════════════════════════════════════════════════════════════════════════

_EVE_ALERT = {
    "timestamp": "2024-03-10T12:00:00.123456+0000",
    "flow_id": 123456789,
    "in_iface": "eth0",
    "event_type": "alert",
    "src_ip": "1.2.3.4",
    "src_port": 49152,
    "dest_ip": "10.0.0.1",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2001219,
        "rev": 5,
        "signature": "ET SCAN SSH Brute Force",
        "category": "Attempted Information Leak",
        "severity": 2,
    },
}

_EVE_FLOW = {
    "timestamp": "2024-03-10T12:01:00.000000+0000",
    "event_type": "flow",
    "src_ip": "1.2.3.4",
    "dest_ip": "10.0.0.1",
    "flow": {"pkts_toserver": 10},
}


class TestSuricataConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = SuricataConfig()
        self.assertEqual(cfg.eve_log_path, "/var/log/suricata/eve.json")

    def test_missing_path_raises(self):
        with self.assertRaises(SuricataConfigError):
            SuricataConfig(eve_log_path="")

    def test_load_from_ini(self):
        p = configparser.ConfigParser()
        p.read_dict({"suricata": {"eve_log_path": "/tmp/eve.json"}})  # nosec B108
        cfg = load_suricata_config(p)
        self.assertEqual(cfg.eve_log_path, "/tmp/eve.json")  # nosec B108

    def test_load_missing_section_raises(self):
        with self.assertRaises(SuricataConfigError):
            load_suricata_config(configparser.ConfigParser())


class TestSuricataEVEReader(unittest.TestCase):
    def test_iter_alerts_from_file(self):
        lines = [json.dumps(_EVE_ALERT), json.dumps(_EVE_FLOW)]
        path = _write_temp("\n".join(lines))
        try:
            cfg = SuricataConfig(eve_log_path=path)
            reader = SuricataEVEReader(cfg)
            alerts = list(reader.iter_alerts())
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["event_type"], "alert")
        finally:
            os.unlink(path)

    def test_iter_events_all_types(self):
        lines = [json.dumps(_EVE_ALERT), json.dumps(_EVE_FLOW)]
        path = _write_temp("\n".join(lines))
        try:
            cfg = SuricataConfig(eve_log_path=path)
            reader = SuricataEVEReader(cfg)
            all_events = list(reader.iter_events())
            self.assertEqual(len(all_events), 2)
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        cfg = SuricataConfig(eve_log_path="/nonexistent/eve.json")
        reader = SuricataEVEReader(cfg)
        with self.assertRaises(SuricataLogError):
            list(reader.iter_alerts())

    def test_invalid_json_lines_skipped(self):
        lines = ["not json", json.dumps(_EVE_ALERT), "also not json"]
        path = _write_temp("\n".join(lines))
        try:
            cfg = SuricataConfig(eve_log_path=path)
            reader = SuricataEVEReader(cfg)
            alerts = list(reader.iter_alerts())
            self.assertEqual(len(alerts), 1)
        finally:
            os.unlink(path)

    def test_normalise_alert(self):
        norm = SuricataEVEReader.normalise_alert(_EVE_ALERT)
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["dst_ip"], "10.0.0.1")
        self.assertEqual(norm["signature"], "ET SCAN SSH Brute Force")
        self.assertEqual(norm["severity"], 3)  # Suricata severity 2 → GNAT 3 (high)
        self.assertEqual(norm["signature_id"], 2001219)
        self.assertEqual(norm["action"], "allowed")

    def test_severity_mapping(self):
        for sev_raw, expected in [(1, 4), (2, 3), (3, 2), (4, 1)]:
            event = {**_EVE_ALERT, "alert": {**_EVE_ALERT["alert"], "severity": sev_raw}}
            norm = SuricataEVEReader.normalise_alert(event)
            self.assertEqual(norm["severity"], expected, f"severity_raw={sev_raw}")

    def test_count_alerts(self):
        lines = [json.dumps(_EVE_ALERT), json.dumps(_EVE_FLOW), json.dumps(_EVE_ALERT)]
        path = _write_temp("\n".join(lines))
        try:
            cfg = SuricataConfig(eve_log_path=path)
            reader = SuricataEVEReader(cfg)
            self.assertEqual(reader.count_alerts(), 2)
        finally:
            os.unlink(path)


class TestSuricataSTIXMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = SuricataSTIXMapper()
        self.norm = SuricataEVEReader.normalise_alert(_EVE_ALERT)

    def test_bundle_structure(self):
        bundle = self.mapper.alert_to_stix_bundle(self.norm)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("observed-data", types)

    def test_observed_data_extension(self):
        bundle = self.mapper.alert_to_stix_bundle(self.norm)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_suricata_alert", obs)
        self.assertEqual(obs["x_suricata_alert"]["signature"], "ET SCAN SSH Brute Force")
        self.assertEqual(obs["x_suricata_alert"]["severity"], 3)

    def test_network_traffic_ports(self):
        bundle = self.mapper.alert_to_stix_bundle(self.norm)
        nt = next(o for o in bundle["objects"] if o["type"] == "network-traffic")
        self.assertEqual(nt["src_port"], 49152)
        self.assertEqual(nt["dst_port"], 22)

    def test_deduplication(self):
        bundle = self.mapper.alerts_to_stix_bundle([self.norm, self.norm])
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "1.2.3.4"]), 1)


# ═══════════════════════════════════════════════════════════════════════════════
# SNORT
# ═══════════════════════════════════════════════════════════════════════════════

_SNORT3_JSON_ALERT = {
    "timestamp": "01/15-12:00:00.123456",
    "gid": 1,
    "sid": 1000001,
    "rev": 1,
    "msg": "ET MALWARE C2 Traffic",
    "proto": "TCP",
    "src_addr": "192.168.1.100",
    "src_port": 49152,
    "dst_addr": "1.2.3.4",
    "dst_port": 443,
    "action": "alert",
    "priority": 2,
    "classification": "Potential Corporate Privacy Violation",
}

_SNORT2_FAST_LINE = (
    "01/15-12:00:00.123456  [**] [1:1000001:1] ET MALWARE C2 Traffic [**] "
    "[Priority: 2] {TCP} 192.168.1.100:49152 -> 1.2.3.4:443"
)


class TestSnortConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = SnortConfig()
        self.assertEqual(cfg.log_format, "json")

    def test_invalid_format_raises(self):
        with self.assertRaises(SnortConfigError):
            SnortConfig(log_format="xml")

    def test_load_from_ini(self):
        p = configparser.ConfigParser()
        p.read_dict({"snort": {"alert_log_path": "/tmp/snort.json", "log_format": "fast"}})  # nosec B108
        cfg = load_snort_config(p)
        self.assertEqual(cfg.log_format, "fast")


class TestSnortJSONReader(unittest.TestCase):
    def test_iter_alerts(self):
        path = _write_temp(json.dumps(_SNORT3_JSON_ALERT))
        try:
            cfg = SnortConfig(alert_log_path=path)
            reader = SnortJSONReader(cfg)
            alerts = list(reader.iter_alerts())
            self.assertEqual(len(alerts), 1)
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        cfg = SnortConfig(alert_log_path="/nonexistent.json")
        reader = SnortJSONReader(cfg)
        with self.assertRaises(SnortLogError):
            list(reader.iter_alerts())

    def test_normalise_alert(self):
        norm = SnortJSONReader.normalise_alert(_SNORT3_JSON_ALERT)
        self.assertEqual(norm["signature"], "ET MALWARE C2 Traffic")
        self.assertEqual(norm["sid"], 1000001)
        self.assertEqual(norm["src_ip"], "192.168.1.100")
        self.assertEqual(norm["dst_ip"], "1.2.3.4")
        self.assertEqual(norm["severity"], 3)  # priority 2 → high

    def test_priority_to_severity(self):
        for prio, expected in [(1, 4), (2, 3), (3, 2), (4, 1)]:
            alert = {**_SNORT3_JSON_ALERT, "priority": prio}
            norm = SnortJSONReader.normalise_alert(alert)
            self.assertEqual(norm["severity"], expected)


class TestSnortFastReader(unittest.TestCase):
    def test_parse_fast_line(self):
        result = SnortFastReader._parse_fast_line(_SNORT2_FAST_LINE)
        self.assertIsNotNone(result)
        self.assertEqual(result["sid"], 1000001)
        self.assertEqual(result["signature"], "ET MALWARE C2 Traffic")
        self.assertEqual(result["src_ip"], "192.168.1.100")
        self.assertEqual(result["dst_ip"], "1.2.3.4")
        self.assertEqual(result["src_port"], 49152)
        self.assertEqual(result["dst_port"], 443)
        self.assertEqual(result["priority"], 2)

    def test_parse_invalid_line_returns_none(self):
        result = SnortFastReader._parse_fast_line("not a snort alert")
        self.assertIsNone(result)

    def test_iter_alerts_from_file(self):
        path = _write_temp(_SNORT2_FAST_LINE + "\n")
        try:
            cfg = SnortConfig(alert_log_path=path, log_format="fast")
            reader = SnortFastReader(cfg)
            alerts = list(reader.iter_alerts())
            self.assertEqual(len(alerts), 1)
        finally:
            os.unlink(path)

    def test_blank_lines_skipped(self):
        content = _SNORT2_FAST_LINE + "\n\n" + _SNORT2_FAST_LINE + "\n"
        path = _write_temp(content)
        try:
            cfg = SnortConfig(alert_log_path=path, log_format="fast")
            reader = SnortFastReader(cfg)
            alerts = list(reader.iter_alerts())
            self.assertEqual(len(alerts), 2)
        finally:
            os.unlink(path)


class TestSnortSTIXMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = SnortSTIXMapper()
        self.norm = SnortJSONReader.normalise_alert(_SNORT3_JSON_ALERT)

    def test_bundle_structure(self):
        bundle = self.mapper.alert_to_stix_bundle(self.norm)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("observed-data", types)

    def test_observed_data_extension(self):
        bundle = self.mapper.alert_to_stix_bundle(self.norm)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_snort_alert", obs)
        self.assertEqual(obs["x_snort_alert"]["sid"], 1000001)

    def test_deduplication(self):
        bundle = self.mapper.alerts_to_stix_bundle([self.norm, self.norm])
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "192.168.1.100"]), 1)


# ═══════════════════════════════════════════════════════════════════════════════
# ZEEK
# ═══════════════════════════════════════════════════════════════════════════════

_ZEEK_TSV_NOTICE = (
    "#separator \\t\n"
    "#set_separator ,\n"
    "#empty_field (empty)\n"
    "#unset_field -\n"
    "#path notice\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tnote\tmsg\tsub\tactions\tdropped\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tenum\tstring\tstring\tset[enum]\tbool\n"
    "1709640000.123456\tCabc123\t1.2.3.4\t49152\t10.0.0.1\t22\ttcp\tSSH::Password_Guessing\tSSH brute force\t10 attempts\tNotice::ACTION_LOG\tF\n"
)

_ZEEK_JSON_CONN = {
    "ts": 1709640000.123456,
    "uid": "Cabc123",
    "id.orig_h": "1.2.3.4",
    "id.orig_p": 49152,
    "id.resp_h": "10.0.0.1",
    "id.resp_p": 22,
    "proto": "tcp",
    "service": "ssh",
    "duration": 5.0,
    "orig_bytes": 2048,
    "resp_bytes": 1024,
    "conn_state": "SF",
    "history": "ShADadfF",
}


class TestZeekConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = ZeekConfig()
        self.assertEqual(cfg.log_format, "tsv")

    def test_invalid_format_raises(self):
        with self.assertRaises(ZeekConfigError):
            ZeekConfig(log_format="xml")

    def test_log_path(self):
        cfg = ZeekConfig(log_dir="/tmp/zeek")  # nosec B108
        self.assertEqual(cfg.log_path("conn"), "/tmp/zeek/conn.log")  # nosec B108

    def test_log_path_json(self):
        cfg = ZeekConfig(log_dir="/tmp/zeek", log_format="json")  # nosec B108
        self.assertEqual(cfg.log_path("conn"), "/tmp/zeek/conn.json")  # nosec B108

    def test_load_from_ini(self):
        p = configparser.ConfigParser()
        p.read_dict({"zeek": {"log_dir": "/tmp/zeek", "log_format": "json"}})  # nosec B108
        cfg = load_zeek_config(p)
        self.assertEqual(cfg.log_format, "json")


class TestZeekTSVReader(unittest.TestCase):
    def test_parse_notice_tsv(self):
        path = _write_temp(_ZEEK_TSV_NOTICE, suffix=".log")
        try:
            cfg = ZeekConfig(log_dir=os.path.dirname(path))
            reader = ZeekTSVReader(cfg)
            records = list(reader.iter_records("notice", path=path))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["id.orig_h"], "1.2.3.4")
            self.assertEqual(records[0]["note"], "SSH::Password_Guessing")
            self.assertEqual(records[0]["dropped"], "F")
        finally:
            os.unlink(path)

    def test_comments_skipped(self):
        path = _write_temp(_ZEEK_TSV_NOTICE, suffix=".log")
        try:
            cfg = ZeekConfig()
            reader = ZeekTSVReader(cfg)
            records = list(reader.iter_records("notice", path=path))
            # Only one data line, not 8 comment lines
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        cfg = ZeekConfig(log_dir="/nonexistent")
        reader = ZeekTSVReader(cfg)
        with self.assertRaises(ZeekLogError):
            list(reader.iter_records("conn"))

    def test_unset_fields_are_none(self):
        # The TSV uses "-" for unset
        content = (
            "#separator \\t\n#fields\tts\tuid\tid.orig_h\n"
            "#types\ttime\tstring\taddr\n"
            "1234.0\t-\t1.2.3.4\n"
        )
        path = _write_temp(content, suffix=".log")
        try:
            cfg = ZeekConfig()
            reader = ZeekTSVReader(cfg)
            records = list(reader.iter_records("test", path=path))
            self.assertIsNone(records[0]["uid"])
        finally:
            os.unlink(path)


class TestZeekJSONReader(unittest.TestCase):
    def test_iter_records(self):
        path = _write_temp(json.dumps(_ZEEK_JSON_CONN), suffix=".json")
        try:
            cfg = ZeekConfig(log_format="json")
            reader = ZeekJSONReader(cfg)
            records = list(reader.iter_records("conn", path=path))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["id.orig_h"], "1.2.3.4")
        finally:
            os.unlink(path)

    def test_invalid_json_skipped(self):
        content = "not json\n" + json.dumps(_ZEEK_JSON_CONN) + "\nalso not json\n"
        path = _write_temp(content, suffix=".json")
        try:
            cfg = ZeekConfig(log_format="json")
            reader = ZeekJSONReader(cfg)
            records = list(reader.iter_records("conn", path=path))
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)


class TestZeekLogCommands(unittest.TestCase):
    def test_normalise_notice(self):
        tsv_record = {
            "ts": "1709640000.123456",
            "uid": "Cabc123",
            "id.orig_h": "1.2.3.4",
            "id.orig_p": "49152",
            "id.resp_h": "10.0.0.1",
            "id.resp_p": "22",
            "proto": "tcp",
            "note": "SSH::Password_Guessing",
            "msg": "SSH brute force",
            "sub": "10 attempts",
            "actions": "Notice::ACTION_LOG",
            "dropped": "F",
        }
        norm = ZeekLogCommands.normalise_notice(tsv_record)
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["note"], "SSH::Password_Guessing")
        self.assertFalse(norm["dropped"])

    def test_normalise_connection(self):
        norm = ZeekLogCommands.normalise_connection(_ZEEK_JSON_CONN)
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["dst_ip"], "10.0.0.1")
        self.assertEqual(norm["service"], "ssh")
        self.assertEqual(norm["conn_state"], "SF")


class TestZeekSTIXMapper(unittest.TestCase):
    def setUp(self):
        self.mapper = ZeekSTIXMapper()
        self.notice = ZeekLogCommands.normalise_notice(
            {
                "ts": "1709640000.0",
                "uid": "Cabc123",
                "id.orig_h": "1.2.3.4",
                "id.orig_p": "49152",
                "id.resp_h": "10.0.0.1",
                "id.resp_p": "22",
                "proto": "tcp",
                "note": "SSH::Password_Guessing",
                "msg": "SSH brute force",
                "dropped": "F",
            }
        )
        self.conn = ZeekLogCommands.normalise_connection(_ZEEK_JSON_CONN)

    def test_notice_bundle_structure(self):
        bundle = self.mapper.notice_to_stix_bundle(self.notice)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)
        self.assertIn("observed-data", types)

    def test_notice_extension(self):
        bundle = self.mapper.notice_to_stix_bundle(self.notice)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_zeek_notice", obs)
        self.assertEqual(obs["x_zeek_notice"]["note"], "SSH::Password_Guessing")

    def test_connection_bundle(self):
        bundle = self.mapper.connection_to_stix_bundle(self.conn)
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("network-traffic", types)

    def test_connection_byte_counts(self):
        bundle = self.mapper.connection_to_stix_bundle(self.conn)
        nt = next(o for o in bundle["objects"] if o["type"] == "network-traffic")
        self.assertEqual(nt.get("src_byte_count"), 2048)
        self.assertEqual(nt.get("dst_byte_count"), 1024)

    def test_notices_bundle_deduplication(self):
        bundle = self.mapper.notices_to_stix_bundle([self.notice, self.notice])
        ip_objs = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        self.assertEqual(len([o for o in ip_objs if o["value"] == "1.2.3.4"]), 1)

    def test_connection_extension(self):
        bundle = self.mapper.connection_to_stix_bundle(self.conn)
        obs = next(o for o in bundle["objects"] if o["type"] == "observed-data")
        self.assertIn("x_zeek_conn", obs)
        self.assertEqual(obs["x_zeek_conn"]["conn_state"], "SF")


if __name__ == "__main__":
    unittest.main(verbosity=2)
