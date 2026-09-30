"""Conservative version checks; vendor-specific suffix ordering is unknown."""
import re


def compare_versions(left: str, right: str) -> int | None:
    if left == right:
        return 0
    if not all(re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", v) for v in (left, right)):
        return None
    a, b = [int(x) for x in left.split('.')], [int(x) for x in right.split('.')]
    size = max(len(a), len(b))
    a += [0] * (size - len(a))
    b += [0] * (size - len(b))
    return (a > b) - (a < b)


def match_version(row, detected: str | None) -> tuple[str, str]:
    metadata = row.match_criteria
    if metadata and metadata.get('vulnerable') is False:
        return 'excluded', 'NVD marks this CPE as an environmental prerequisite.'
    if not detected or detected in ('*', '-', 'unknown', 'Unknown'):
        return 'uncertain', 'No reliable software version was supplied or detected.'
    if not metadata:
        return 'uncertain', 'Legacy NVD record needs refresh to recover version boundaries.'
    if metadata.get('negated_context'):
        return 'uncertain', 'Negated NVD configuration requires verification.'
    unknown = False
    constrained = False
    if row.version and row.version not in ('*', '-'):
        constrained = True
        comparison = compare_versions(detected, row.version)
        if comparison is None:
            unknown = True
        elif comparison != 0:
            return 'excluded', 'Detected version differs from the affected version.'
    for field, allowed in (
        ('versionStartIncluding', (0, 1)), ('versionStartExcluding', (1,)),
        ('versionEndIncluding', (-1, 0)), ('versionEndExcluding', (-1,)),
    ):
        boundary = metadata.get(field)
        if boundary is None:
            continue
        constrained = True
        comparison = compare_versions(detected, boundary)
        if comparison is None:
            unknown = True
        elif comparison not in allowed:
            return 'excluded', 'Detected version is outside the affected range.'
    if metadata.get('vulnerable') is not True or metadata.get('context_required'):
        return 'uncertain', 'Additional NVD configuration conditions require verification.'
    if unknown or not constrained or row.version == '-':
        return 'uncertain', 'Version constraints are absent or require vendor-specific comparison.'
    return 'version_match', 'Version matches NVD criteria; applicability still requires confirmation.'
