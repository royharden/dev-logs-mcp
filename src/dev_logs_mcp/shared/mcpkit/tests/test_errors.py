import pytest
from pydantic import ValidationError

from dev_logs_mcp.shared.mcpkit.errors import ErrorCode, ToolError
from dev_logs_mcp.shared.mcpkit.models import ToolEnvelope


def test_structured_error_roundtrip_and_no_success_evidence():
    error = ToolError(
        code=ErrorCode.PATH_FORBIDDEN, message="refused", hint="configure a safe source"
    )
    envelope = ToolEnvelope(ok=False, error=error)
    assert ToolEnvelope.model_validate_json(envelope.model_dump_json()) == envelope
    with pytest.raises(ValidationError):
        ToolEnvelope(ok=True, error=error)


def test_shared_models_are_strict_without_app_dependency():
    """Catch loose schema coercion after moving shared classes."""
    with pytest.raises(ValidationError):
        ToolError(code=ErrorCode.BUSY, message="wait", hint="retry", retryable="true")
