from pathlib import Path

import pretend  # type: ignore
import pytest
import requests
from packaging.version import Version
from platformdirs import user_cache_path

import pip_audit._cache as cache
from pip_audit import __version__
from pip_audit._cache import _get_cache_dir, _get_pip_cache
from pip_audit._service import EcosystemsService, OsvService, PyPIService, ResolvedDependency


def test_get_cache_dir(monkeypatch):
    # When we supply a cache directory, always use that
    cache_dir = Path("/tmp/foo/cache_dir")
    assert _get_cache_dir(cache_dir) == cache_dir

    cache_dir = Path("/fake/pip/cache/dir")
    get_pip_cache = pretend.call_recorder(lambda: cache_dir)
    monkeypatch.setattr(cache, "_get_pip_cache", get_pip_cache)

    # When `pip cache dir` works, we use it. In this case, it's mocked.
    assert _get_cache_dir(None, use_pip=True) == cache_dir


def test_get_pip_cache():
    # Actually running `pip cache dir` gets us some path that ends with "http"
    cache_dir = _get_pip_cache()
    assert cache_dir.stem == "http"


def test_get_cache_dir_do_not_use_pip():
    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with None, we never use the pip cache if we're told not to.
    assert _get_cache_dir(None, use_pip=False) == expected


def test_get_cache_dir_pip_disabled_in_environment(monkeypatch):
    monkeypatch.setenv("PIP_NO_CACHE_DIR", "1")

    expected = user_cache_path("pip-audit", appauthor=False)

    # Even with use_pip=True, we avoid pip's cache if the environment tells us to.
    assert _get_cache_dir(None, use_pip=True) == expected


def test_get_cache_dir_old_pip(monkeypatch):
    # Check the case where we have an old `pip`
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))

    # In this case, we can't query `pip` to figure out where its HTTP cache is
    # Instead, we use `~/.pip-audit-cache`
    cache_dir = _get_cache_dir(None)
    expected = user_cache_path("pip-audit", appauthor=False)
    assert cache_dir == expected


def test_cache_warns_about_old_pip(monkeypatch, cache_dir):
    monkeypatch.setattr(cache, "_PIP_VERSION", Version("1.0.0"))
    logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(cache, "logger", logger)

    # If we supply a cache directory, we're not relying on finding the `pip` cache so no need to log
    # a warning
    _get_cache_dir(cache_dir)
    assert len(logger.warning.calls) == 0

    # However, if we're not specifying a cache directory, we'll try to call `pip cache dir`. If we
    # have an old `pip`, then we should expect a warning to be logged
    _get_cache_dir(None)
    assert len(logger.warning.calls) == 1


def test_delete_legacy_cache_dir(monkeypatch, tmp_path):
    legacy = tmp_path / "pip-audit-cache"
    legacy.mkdir()
    assert legacy.exists()
    monkeypatch.setattr(cache, "_PIP_AUDIT_LEGACY_INTERNAL_CACHE", legacy)

    _get_cache_dir(None, use_pip=False)
    assert not legacy.exists()


def test_caching_session_user_agent(cache_dir):
    with cache.caching_session(cache_dir) as session:
        request = session.prepare_request(requests.Request("GET", "https://example.com/"))
        assert request.headers["User-Agent"] == f"pip-audit/{__version__}"
        assert request.headers["Accept"] == "*/*"
        assert session.max_redirects == 5


@pytest.mark.parametrize(
    ("service_type", "response_body", "method"),
    [
        (PyPIService, b'{"vulnerabilities": []}', "GET"),
        (OsvService, b"{}", "POST"),
        (EcosystemsService, b"[]", "GET"),
    ],
)
def test_services_send_user_agent(service_type, response_body, method, cache_dir, monkeypatch):
    service = service_type(cache_dir=cache_dir)
    sent = []

    def send(request, **kwargs):
        sent.append(request)
        response = requests.Response()
        response.status_code = 200
        response._content = response_body
        return response

    monkeypatch.setattr(service.session, "send", send)
    dependency = ResolvedDependency("example", Version("1.0"))
    try:
        assert service.query(dependency) == (dependency, [])
    finally:
        service.session.close()
    assert len(sent) == 1
    assert sent[0].method == method
    assert sent[0].headers["User-Agent"] == f"pip-audit/{__version__}"
