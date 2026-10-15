"""Application compatibility belongs outside the independently copied core suite."""

from dev_logs_mcp import contracts
from dev_logs_mcp.shared.mcpkit.errors import BoundaryModel, ErrorCode, ToolError
from dev_logs_mcp.shared.mcpkit.models import ToolEnvelope


def test_app_reexports_one_canonical_model_identity():
    """Catch duplicate schema classes without making the moved core import this app."""
    assert contracts.ToolError is ToolError
    assert contracts.ToolEnvelope is ToolEnvelope
    assert contracts.BoundaryModel is BoundaryModel
    assert contracts.ErrorCode is ErrorCode
