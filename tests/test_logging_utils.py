from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aws_cli_mcp import logging_utils


def _settings(log_file: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        logging=SimpleNamespace(level="INFO", file=log_file),
    )


@patch("aws_cli_mcp.logging_utils.load_settings")
@patch("aws_cli_mcp.logging_utils.logging.basicConfig")
def test_configure_logging_stream_only(
    mock_basic_config: MagicMock,
    mock_load_settings: MagicMock,
) -> None:
    mock_load_settings.return_value = _settings(None)

    logging_utils.configure_logging()

    kwargs = mock_basic_config.call_args.kwargs
    assert kwargs["force"] is True
    assert kwargs["level"] == logging.INFO
    assert len(kwargs["handlers"]) == 1


@patch("aws_cli_mcp.logging_utils.load_settings")
@patch("aws_cli_mcp.logging_utils.logging.FileHandler", side_effect=OSError("permission denied"))
@patch("aws_cli_mcp.logging_utils._logger")
def test_configure_logging_file_handler_error(
    mock_logger: MagicMock,
    _mock_file_handler: MagicMock,
    mock_load_settings: MagicMock,
) -> None:
    mock_load_settings.return_value = _settings("./logs/app.log")

    logging_utils.configure_logging()

    mock_logger.warning.assert_called_once()


def test_get_logger_auto_configures(monkeypatch) -> None:
    monkeypatch.setattr(logging_utils, "_logging_configured", False)

    calls = {"count": 0}

    def fake_configure() -> None:
        calls["count"] += 1
        monkeypatch.setattr(logging_utils, "_logging_configured", True)

    monkeypatch.setattr(logging_utils, "configure_logging", fake_configure)

    logger = logging_utils.get_logger("test.logger")
    assert logger.name == "test.logger"
    assert calls["count"] == 1
