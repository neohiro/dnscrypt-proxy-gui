"""Tests for dnscrypt-proxy.toml generation and sanitisation logic."""
import tomllib

import pytest

from conftest import mod


class TestCleanServerName:
    def test_strips_invalid_characters(self, gui):
        assert gui._clean_server_name("my server.example!") == "myserverexample"

    def test_all_invalid_falls_back(self, gui):
        assert gui._clean_server_name("---") == "server"

    def test_unicode_stripped(self, gui):
        assert gui._clean_server_name("sérvér") == "srvr"


class TestConfigGeneration:
    def test_generated_config_is_valid_toml(self, gui, sample_servers):
        content = gui._generate_config_content(sample_servers)
        parsed = tomllib.loads(content)
        assert isinstance(parsed.get("static"), dict) and parsed["static"]

    def test_listen_address(self, gui, sample_servers):
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        assert parsed["listen_addresses"] == ["127.0.0.1:53"]

    def test_server_names_sanitised_and_unique(self, gui, sample_servers):
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        names = parsed["server_names"]
        assert len(names) == len(set(names))
        for name in names:
            assert all(c.isalnum() or c == "_" for c in name)

    def test_static_sections_cover_every_server(self, gui, sample_servers):
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        static = parsed["static"]
        stamps = {v["stamp"] for v in static.values()}
        for server in sample_servers:
            assert server["stamp"] in stamps

    def test_requirement_flags_propagate(self, gui, sample_servers):
        gui.require_dnssec_var.set(True)
        gui.require_nolog_var.set(True)
        gui.require_nofilter_var.set(False)
        gui.block_ipv6_var.set(True)
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        assert parsed["require_dnssec"] is True
        assert parsed["require_nolog"] is True
        assert parsed["require_nofilter"] is False
        assert parsed["block_ipv6"] is True

    def test_cache_values_parsed_from_strings(self, gui, sample_servers):
        gui.cache_size_var.set("1024")
        gui.cache_min_ttl_var.set("120")
        gui.cache_neg_ttl_var.set("30")
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        assert parsed["cache_size"] == 1024
        assert parsed["cache_min_ttl"] == 120
        assert parsed["cache_neg_ttl"] == 30

    def test_colliding_names_keep_distinct_stamps(self, gui):
        servers = [
            {"name": "srv-a", "stamp": "sdns://AAAAAAAAAAA=", "proto_type": "DNSCrypt",
             "no-log": "✓", "dnssec": "✓", "no-filter": "✓", "description": ""},
            {"name": "srv.a", "stamp": "sdns://BBBBBBBBBBB=", "proto_type": "DNSCrypt",
             "no-log": "✓", "dnssec": "✓", "no-filter": "✓", "description": ""},
        ]
        content = gui._generate_config_content(servers)
        parsed = tomllib.loads(content)
        stamps = sorted(v["stamp"] for v in parsed["static"].values())
        assert stamps == ["sdns://AAAAAAAAAAA=", "sdns://BBBBBBBBBBB="]
        assert len(parsed["server_names"]) == 2

    def test_anonymized_routes_only_for_dnscrypt(self, gui, sample_servers):
        gui.server_relay_map = {
            "example-a": ["relay-one"],
            "example-b.doh": ["relay-one"],
        }
        gui.relay_data = [
            {"name": "relay-one", "stamp": "sdns://AQRRRUxBWSAAAAA="},
        ]
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        routes = parsed.get("anonymized_dns", {}).get("routes", [])
        route_servers = {r["server_name"] for r in routes}
        assert any(name.startswith("examplea") for name in route_servers)
        assert not any(name.startswith("exampleb") for name in route_servers), (
            "DoH servers must never receive anonymized-DNS routes"
        )

    def test_route_via_relays_are_defined_in_static(self, gui, sample_servers):
        """Every relay referenced by a route must have a [static] definition,
        otherwise dnscrypt-proxy refuses to start."""
        gui.server_relay_map = {"example-a": ["relay-one"]}
        gui.relay_data = [
            {"name": "relay-one", "stamp": "sdns://AQRRRUxBWSAAAAA="},
        ]
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        routes = parsed.get("anonymized_dns", {}).get("routes", [])
        assert routes, "expected at least one anonymized route"
        static_keys = set(parsed["static"].keys())
        for route in routes:
            for via in route["via"]:
                assert via in static_keys, (
                    f"route references relay '{via}' with no [static] section"
                )


class TestCoerceInt:
    """Covers the shared clamping helper used by UI fields and config gen."""

    def test_valid_passthrough(self, gui):
        assert gui._coerce_int("512", 512, 64, 1 << 20) == 512

    def test_whitespace_tolerated(self, gui):
        assert gui._coerce_int(" 1024 ", 512, 64, 1 << 20) == 1024

    def test_garbage_falls_back_to_default(self, gui):
        assert gui._coerce_int("abc", 512, 64, 1 << 20) == 512
        assert gui._coerce_int(None, 512, 64, 1 << 20) == 512

    def test_clamped_to_bounds(self, gui):
        assert gui._coerce_int("-50", 512, 64, 1000) == 64
        assert gui._coerce_int("99999", 512, 64, 1000) == 1000

    def test_ttl_defaults(self, gui, sample_servers):
        gui.cache_min_ttl_var.set("not-a-number")
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        assert parsed["cache_min_ttl"] == 60


class TestMacServiceFiltering:
    def test_legend_and_disabled_services_are_skipped(self, gui, monkeypatch):
        class FakeResult:
            stdout = (
                "An asterisk (*) denotes that a network service is disabled.\n"
                "Wi-Fi\n"
                "*Bluetooth PAN\n"
                "Thunderbolt Bridge\n"
                "\n"
            )

        monkeypatch.setattr(gui, "_run_hidden", lambda cmd, check=True: FakeResult())
        assert gui._list_mac_services() == ["Wi-Fi", "Thunderbolt Bridge"]

    def test_snapshot_marks_missing_servers_as_none(self, gui, monkeypatch):
        class FakeResult:
            def __init__(self, stdout):
                self.stdout = stdout

        services = {"Wi-Fi"}
        monkeypatch.setattr(
            gui, "_list_mac_services", lambda: list(services)
        )
        outputs = iter([
            FakeResult("There aren't any DNS Servers set on Wi-Fi."),
        ])

        def fake_run(cmd, check=False, capture_output=True, **kwargs):
            return next(outputs)

        import subprocess as _subprocess
        monkeypatch.setattr(_subprocess, "run", fake_run)
        snapshot = gui._snapshot_dns_macos()
        assert snapshot == {"Wi-Fi": None}


class TestStaleRelayRegression:
    def test_unknown_relay_is_dropped_not_emitted(self, gui, sample_servers):
        """If a mapped relay vanished from the upstream list the generated
        config must still be internally consistent (route <-> static)."""
        gui.server_relay_map = {"example-a": ["vanished-relay"]}
        gui.relay_data = []  # relay no longer exists upstream
        parsed = tomllib.loads(gui._generate_config_content(sample_servers))
        routes = parsed.get("anonymized_dns", {}).get("routes", [])
        static_keys = set(parsed["static"].keys())
        for route in routes:
            for via in route["via"]:
                assert via in static_keys, f"dangling relay '{via}'"

class TestMalformedRelayMappings:
    """Hand-edited or corrupted settings must never crash generation."""

    def _generate(self, gui, sample_servers, relay_map):
        gui.server_relay_map = relay_map
        gui.relay_data = [{"name": "relay-one", "stamp": "sdns://AQRRRUxBWSAAAAA="}]
        return tomllib.loads(gui._generate_config_content(sample_servers))

    @pytest.mark.parametrize("bad_value", [5, {"a": 1}, None, True, [["nested"]]])
    def test_garbage_mapping_types_are_ignored(self, gui, sample_servers, bad_value):
        parsed = self._generate(gui, sample_servers, {"example-a": bad_value})
        assert parsed.get("anonymized_dns", {}).get("routes", []) == []

    def test_duplicate_relays_in_one_mapping_deduped(self, gui, sample_servers):
        parsed = self._generate(gui, sample_servers, {"example-a": ["relay-one", "relay-one"]})
        routes = parsed["anonymized_dns"]["routes"]
        assert len(routes) == 1
        assert routes[0]["via"] == ["relayone"]

    def test_non_string_entries_within_list_skipped(self, gui, sample_servers):
        parsed = self._generate(gui, sample_servers, {"example-a": ["relay-one", 7]})
        assert parsed["anonymized_dns"]["routes"][0]["via"] == ["relayone"]

    def test_valid_string_shorthand_still_works(self, gui, sample_servers):
        parsed = self._generate(gui, sample_servers, {"example-a": "relay-one"})
        assert parsed["anonymized_dns"]["routes"][0]["via"] == ["relayone"]


class TestTreeValuesDefaults:
    def test_missing_optional_fields_get_defaults(self):
        values = mod.DNSCryptClientGUI._tree_values({"name": "x"}, "")
        assert values[0] == "x"
        assert values[1] == "?"
        assert values[3:] == ("\u2717", "\u2717", "\u2717")

    def test_present_fields_preserved(self):
        server = {"name": "x", "proto_type": "DoH",
                  "no-log": "\u2713", "dnssec": "\u2713", "no-filter": "\u2717"}
        values = mod.DNSCryptClientGUI._tree_values(server, "via-relay")
        assert values == ("x", "DoH", "via-relay", "\u2713", "\u2713", "\u2717")
