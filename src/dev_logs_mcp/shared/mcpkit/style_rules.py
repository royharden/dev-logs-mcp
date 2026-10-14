"""Portable description lint; no application or MCP transport dependency."""

SECTIONS = ("Use:", "Inputs:", "Returns:", "Bounds:", "Trust:", "Failures:")


def check_description(description: str) -> tuple[str, ...]:
    problems = []
    if type(description) is not str or not 1 <= len(description) <= 1400:
        return ("description length",)
    if any(ord(value) < 32 and value not in "\n\t" for value in description):
        problems.append("description control character")
    positions = [description.find(section) for section in SECTIONS]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        problems.append("description sections")
    if "untrusted" not in description.lower():
        problems.append("description trust")
    return tuple(problems)
