"""Unit tests for ToolRegistry."""

from core.registry import ToolMetadata, ToolRegistry


def test_tool_registry_discovers_nmap():
    registry = ToolRegistry()
    nmap = registry.get_tool("nmap")
    assert nmap is not None
    assert nmap.is_installed is True
    assert nmap.binary_path is not None
    assert nmap.version is not None
    assert "Nmap version" in nmap.version
    assert registry.is_available("nmap") is True


def test_tool_registry_handles_missing_tool():
    custom_tool = ToolMetadata(
        name="nonexistent_sec_tool_12345",
        display_name="Fake Tool",
        binary_name="nonexistent_sec_tool_12345",
        category="custom",
    )
    registry = ToolRegistry(tools=[custom_tool])
    tool = registry.get_tool("nonexistent_sec_tool_12345")
    assert tool is not None
    assert tool.is_installed is False
    assert tool.binary_path is None
    assert registry.is_available("nonexistent_sec_tool_12345") is False


def test_tool_registry_sqlmap_and_wafw00f_execution():
    """Verify sqlmap and wafw00f wrappers execute with code 0 without SyntaxError."""
    registry = ToolRegistry()
    sqlmap = registry.get_tool("sqlmap")
    assert sqlmap is not None
    assert sqlmap.is_installed is True
    ok, out, code = registry.test_tool("sqlmap")
    assert ok is True
    assert code == 0
    assert "SyntaxError" not in out
    assert "1.10" in out or "sqlmap" in out.lower()

    wafw00f = registry.get_tool("wafw00f")
    assert wafw00f is not None
    assert wafw00f.is_installed is True
    ok_w, out_w, code_w = registry.test_tool("wafw00f")
    assert ok_w is True
    assert code_w == 0
    assert "SyntaxError" not in out_w
    assert "WAFW00F" in out_w


def test_tool_registry_truthfully_reports_tool_availability():
    """Verify tools use valid low-impact probes and surface missing dependencies."""
    registry = ToolRegistry()
    
    # 1. John prints version/usage without arguments; do not pass its unsupported --help flag.
    john = registry.get_tool("john")
    assert john is not None
    assert john.is_installed is True
    assert john.version and "John the Ripper" in john.version
    ok_j, out_j, code_j = registry.test_tool("john")
    assert ok_j is True
    assert code_j == 0
    assert "John the Ripper" in out_j

    # 2. Nikto functions truthfully with -Version
    nikto = registry.get_tool("nikto")
    assert nikto is not None
    assert nikto.is_installed is True
    assert "Nikto" in nikto.version
    assert nikto.has_adapter is True
    assert nikto.has_gui is True
    assert nikto.has_parser is True
    ok_n, out_n, code_n = registry.test_tool("nikto")
    assert ok_n is True
    assert code_n == 0
    assert "Nikto" in out_n

    # 3. Verify _is_error_output correctly catches dependency errors
    assert registry._is_error_output("ERROR: Required module not found: XML::Writer") is True
    assert registry._is_error_output("Can't locate XML/Writer.pm in @INC") is True


