"""
Configuration file loading: sections, keys, types, ranges and error messages.
"""

from __future__ import annotations

import dataclasses
import pathlib

import pytest

from echocorn import config as config_module
from echocorn.config import (
    LOG_LEVELS,
    SCHEMA,
    ConfigError,
    ServerConfig,
    load_settings,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


def write(tmp_path, text):
    path = tmp_path / "echocorn.toml"
    path.write_text(text, encoding="utf-8")
    return path


def load(tmp_path, text):
    return load_settings(write(tmp_path, text))


def test_every_server_setting_has_a_configuration_key():
    """The accepted keys and the dataclass fields must not drift apart."""
    fields = {field.name for field in dataclasses.fields(ServerConfig)} - {"app"}
    mapped = {field for section in SCHEMA.values() for _, field in section.values()}
    assert fields == mapped


def test_every_section_has_a_doc_visible_place_in_the_example(tmp_path):
    """The shipped example exercises every section header."""
    text = (ROOT / "echocorn.toml").read_text(encoding="utf-8")
    for section in SCHEMA:
        assert "[%s]" % section in text


def test_the_shipped_example_matches_the_defaults():
    settings = load_settings(ROOT / "echocorn.toml")
    assert settings.app == "app:app"
    defaults = ServerConfig()
    for name, value in vars(settings.config).items():
        if name == "app":
            continue
        if name == "host":
            assert value in ("", "0.0.0.0")
            continue
        assert value == getattr(defaults, name), name


def test_defaults_are_applied_for_keys_left_out(tmp_path):
    settings = load(tmp_path, 'app = "app:app"\n')
    assert settings.config.port == 8000
    assert settings.config.request_timeout == 10.0
    assert settings.config.workers == 1
    assert settings.config.access_log is True
    assert settings.config.http1_enabled is True
    assert settings.config.http2_enabled is True
    assert settings.config.websockets is True


def test_values_are_read_from_the_sections(tmp_path):
    settings = load(
        tmp_path,
        'app = "myapp:asgi"\n'
        "\n[server]\n"
        'host = "127.0.0.1"\n'
        "port = 9001\n"
        "workers = 4\n"
        "compression = true\n"
        "safe_headers = true\n"
        'bind_domain = "example.com"\n'
        "request_timeout = 2.5\n"
        "max_request_size = 1024\n"
        "\n[http1]\n"
        "enabled = false\n"
        "\n[http2]\n"
        "max_concurrent_streams = 7\n"
        "enabled = true\n"
        "\n[websocket]\n"
        "enabled = false\n"
        "max_message_size = 1024\n"
        "\n[logging]\n"
        'level = "debug"\n'
        "access = false\n",
    )
    assert settings.app == "myapp:asgi"
    assert settings.config.host == "127.0.0.1"
    assert settings.config.port == 9001
    assert settings.config.workers == 4
    assert settings.config.compression is True
    assert settings.config.safe_headers is True
    assert settings.config.bind_domain == "example.com"
    assert settings.config.request_timeout == 2.5
    assert settings.config.max_request_size == 1024
    assert settings.config.http1_enabled is False
    assert settings.config.http2_enabled is True
    assert settings.config.h2_max_concurrent_streams == 7
    assert settings.config.websockets is False
    assert settings.config.max_websocket_message_size == 1024
    assert settings.config.log_level == "DEBUG"
    assert settings.config.access_log is False


def test_a_whole_number_is_accepted_for_a_float(tmp_path):
    text = 'app = "a:b"\n[server]\nrequest_timeout = 5\n'
    assert load(tmp_path, text).config.request_timeout == 5.0


@pytest.mark.parametrize(
    "given, expected",
    [("WARN", "WARN"), ("WARNING", "WARN"), ("CRIT", "CRIT"), ("critical", "CRIT")],
)
def test_level_names_are_canonical_and_only_five_exist(tmp_path, given, expected):
    text = 'app = "a:b"\n[logging]\nlevel = "%s"\n' % given
    assert load(tmp_path, text).config.log_level == expected
    assert LOG_LEVELS == ("CRIT", "ERROR", "WARN", "INFO", "DEBUG")


def test_relative_tls_paths_resolve_from_the_config_file(tmp_path):
    directory = tmp_path / "certs"
    directory.mkdir()
    settings = load(
        tmp_path,
        'app = "a:b"\n[tls]\ncertfile = "certs/cert.pem"\nkeyfile = "certs/key.pem"\n',
    )
    assert pathlib.Path(settings.config.certfile) == directory / "cert.pem"
    assert pathlib.Path(settings.config.keyfile) == directory / "key.pem"


def test_absolute_tls_paths_are_kept(tmp_path):
    # Single quoted TOML strings, which is how a Windows path is written.
    absolute = (tmp_path / "cert.pem").resolve()
    settings = load(
        tmp_path,
        "app = 'a:b'\n[tls]\ncertfile = '%s'\nkeyfile = '%s'\n" % (absolute, absolute),
    )
    assert settings.config.certfile == str(absolute)


def test_empty_tls_paths_mean_no_tls(tmp_path):
    settings = load(tmp_path, 'app = "a:b"\n[tls]\ncertfile = ""\nkeyfile = ""\n')
    assert settings.config.certfile is None
    assert settings.config.keyfile is None


def test_unknown_keys_are_rejected_with_a_suggestion(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[server]\nprot = 8000\n')
    assert "unknown setting 'server.prot'" in str(excinfo.value)
    assert "port" in str(excinfo.value)


def test_an_unknown_section_suggests_a_known_one(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[https]\nport = 8000\n')
    assert "unknown setting 'https'" in str(excinfo.value)
    assert "http" in str(excinfo.value)


def test_a_key_in_the_wrong_section_suggests_the_right_one(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[logging]\nport = 8000\n')
    assert "unknown setting 'logging.port'" in str(excinfo.value)
    assert "server.port" in str(excinfo.value)


def test_a_flat_key_points_at_its_section(tmp_path):
    """An old, flat configuration file is migrated with one clear error."""
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\nport = 8000\n')
    assert "unknown setting 'port'" in str(excinfo.value)
    assert "server.port" in str(excinfo.value)


def test_a_section_that_is_not_a_table_is_reported(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\nserver = 5\n')
    assert "[server] must be a table" in str(excinfo.value)


def test_a_missing_app_key_is_reported(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, "[server]\nport = 8000\n")
    assert "'app' key is required" in str(excinfo.value)


@pytest.mark.parametrize("line", ['app = "app"', 'app = ":attr"', 'app = "module:"', "app = ''"])
def test_the_app_key_must_be_a_module_path(tmp_path, line):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, line + "\n")
    assert "module:callable" in str(excinfo.value)


@pytest.mark.parametrize(
    "line, message",
    [
        ('[server]\nport = "8000"', "server.port must be an integer"),
        ("[server]\nport = 8000.5", "server.port must be an integer"),
        ("[server]\nport = true", "server.port must be an integer"),
        ('[server]\nworkers = "2"', "server.workers must be an integer"),
        ("[server]\ncompression = 1", "server.compression must be true or false"),
        ("[server]\nhost = 8080", "server.host must be a string"),
        ("[server]\nrequest_timeout = true", "server.request_timeout must be a number"),
        ('[tls]\ncertfile = 5', "tls.certfile must be a string path"),
        ("[logging]\nlevel = 5", "logging.level must be a string"),
        ("[http1]\nenabled = 1", "http1.enabled must be true or false"),
        ("[logging]\ncolor = 1", "logging.color must be true or false"),
        ("[redirect]\nport = \"80\"", "redirect.port must be an integer"),
    ],
)
def test_wrong_types_are_reported(tmp_path, line, message):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n' + line + "\n")
    assert message in str(excinfo.value)
    assert "echocorn.toml" in str(excinfo.value)


@pytest.mark.parametrize(
    "line, message",
    [
        ("[server]\nport = 70000", "port must be within"),
        ("[server]\nworkers = 0", "workers must be at least 1"),
        ("[server]\nbacklog = 0", "backlog must be at least 1"),
        ('[logging]\nlevel = "CHATTY"', "logging.level must be one of"),
        ("[server]\nkeep_alive_timeout = -1", "keep_alive_timeout must not be negative"),
        ("[server]\ngraceful_timeout = -1", "graceful_timeout must not be negative"),
        ("[http2]\nmax_concurrent_streams = 0", "must be positive"),
        ("[http2]\nmax_frame_size = 1024", "h2_max_frame_size must be within"),
        ("[http2]\ninitial_window_size = -5", "out of range"),
        ("[http2]\nmax_header_list_size = 10", "at least 256"),
        ("[server]\nmax_header_count = 0", "max_header_count must be positive"),
        ("[server]\nmax_request_size = -1", "must not be negative"),
        ("[websocket]\nmax_message_size = 10", "at least 125"),
        ("[server]\nmax_connections = -1", "must not be negative"),
        ("[server]\nrequest_timeout = -1", "must not be negative"),
        ("[redirect]\nport = 70000", "redirect_port must be within"),
        ("[redirect]\nstatus = 200", "redirect_status must be 301, 302, 307 or 308"),
    ],
)
def test_out_of_range_values_are_reported(tmp_path, line, message):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n' + line + "\n")
    assert message in str(excinfo.value)


def test_at_least_one_protocol_must_stay_enabled(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(
            tmp_path,
            'app = "a:b"\n[http1]\nenabled = false\n[http2]\nenabled = false\n',
        )
    assert "at least one of http1.enabled and http2.enabled" in str(excinfo.value)


def test_websockets_need_http1(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[http1]\nenabled = false\n[websocket]\nenabled = true\n')
    assert "websocket.enabled requires http1.enabled" in str(excinfo.value)


def test_websockets_may_be_enabled_without_http1_when_they_are_off(tmp_path):
    settings = load(
        tmp_path,
        'app = "a:b"\n[http1]\nenabled = false\n[websocket]\nenabled = false\n',
    )
    assert settings.config.websockets is False


def test_colour_and_redirect_keys_are_read(tmp_path):
    settings = load(
        tmp_path,
        'app = "a:b"\n'
        "\n[logging]\n"
        "color = true\n"
        "\n[redirect]\n"
        "enabled = true\n"
        'host = "127.0.0.1"\n'
        "port = 8080\n"
        "status = 301\n"
        "\n[tls]\n"
        'certfile = "cert.pem"\n'
        'keyfile = "key.pem"\n',
    )
    assert settings.config.log_color is True
    assert settings.config.redirect_enabled is True
    assert settings.config.redirect_host == "127.0.0.1"
    assert settings.config.redirect_port == 8080
    assert settings.config.redirect_status == 301


def test_the_redirect_defaults_are_off(tmp_path):
    config = load(tmp_path, 'app = "a:b"\n').config
    assert config.redirect_enabled is False
    assert config.redirect_port == 80
    assert config.redirect_status == 308
    assert config.log_color is False


def test_redirect_needs_tls(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[redirect]\nenabled = true\n')
    assert "redirect.enabled requires tls.certfile and tls.keyfile" in str(excinfo.value)


def test_redirect_needs_its_own_port(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(
            tmp_path,
            'app = "a:b"\n'
            "[server]\nport = 8443\n"
            "[redirect]\nenabled = true\nport = 8443\n"
            '[tls]\ncertfile = "cert.pem"\nkeyfile = "key.pem"\n',
        )
    assert "redirect.port must differ from server.port" in str(excinfo.value)


def test_tls_needs_both_files(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[tls]\ncertfile = "cert.pem"\n')
    assert "tls.certfile and tls.keyfile" in str(excinfo.value)
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[tls]\nkeyfile = "key.pem"\n')
    assert "tls.certfile and tls.keyfile" in str(excinfo.value)


def test_broken_toml_names_the_file(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load(tmp_path, 'app = "a:b"\n[server]\nport = \n')
    assert "not valid TOML" in str(excinfo.value)
    assert "echocorn.toml" in str(excinfo.value)


def test_a_missing_file_is_reported(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_settings(tmp_path / "absent.toml")
    assert "no configuration file at" in str(excinfo.value)


def test_a_directory_is_reported(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_settings(tmp_path)
    assert "is a directory" in str(excinfo.value)


def test_loading_does_not_import_the_application(tmp_path):
    """Loading only validates: the app is imported later, by the runner."""
    settings = load(tmp_path, 'app = "does.not.exist:app"\n')
    assert settings.app == "does.not.exist:app"


def test_the_config_file_is_named_in_every_error(tmp_path):
    path = write(tmp_path, 'app = "a:b"\n[server]\nport = "x"\n')
    with pytest.raises(ConfigError) as excinfo:
        load_settings(path)
    assert str(path) in str(excinfo.value)


def test_there_is_no_environment_variable_override(monkeypatch, tmp_path):
    """The path is an argument now; the environment is not consulted."""
    monkeypatch.setenv("ECHOCORN_CONFIG", str(tmp_path / "elsewhere.toml"))
    assert not hasattr(config_module, "CONFIG_ENV_VAR")
    assert config_module.load_settings.__defaults__ is None
