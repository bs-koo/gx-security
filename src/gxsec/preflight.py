"""Bounded preparation signatures, separate from the full release inventory."""
import hashlib
import os
from pathlib import Path
import stat

from .models import content_hash
from .source import directory_exclusion_reason, exclusion_contract, is_reparse, reject_reparse_path
from .snapshot import _handle_path
from .execution import BudgetExceeded, checkpoint

SIGNATURE_NAMES = frozenset({
    'build.gradle', 'build.gradle.kts', 'pom.xml', 'SefApplication.java',
    'WebSecurityConfig.java', 'MethodSecurityConfig.java', 'JwtTokenProvider.java',
    'JwtAuthenticationFilter.java', 'MenuSecurityExpressionRoot.java',
    'MenuSecurityExpressionHandler.java', 'ApiResponse.java',
})
MAX_DISCOVERED = 50000
MAX_SIGNATURES = 512
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024


def inspect_inputs(source):
    """Metadata-only preparation; never substitutes for verified source inventory."""
    root = reject_reparse_path(source).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Source must be a directory')
    total = count = discovered = 0
    errors, exclusions, largest, candidates = [], [], [], []
    try:
        for directory, dirs, names in os.walk(root, followlinks=False,
                onerror=lambda exc: errors.append({'type': 'input_plan_unreadable'})):
            checkpoint()
            base = Path(directory)
            retained = []
            for name in sorted(dirs):
                path = base / name
                relative = path.relative_to(root).as_posix()
                reason = directory_exclusion_reason(relative)
                if not reason and is_reparse(path):
                    reason = 'reparse-entry'
                    errors.append({'type': 'reparse_entry', 'path': relative})
                if reason:
                    exclusions.append({'path': relative, 'reason': reason})
                else:
                    retained.append(name)
            dirs[:] = retained
            discovered += len(dirs) + len(names)
            if discovered > MAX_DISCOVERED:
                errors.append({'type': 'input_plan_discovery_limit'})
                break
            for name in sorted(names):
                checkpoint()
                if name == '.git':
                    continue
                path = base / name
                relative = path.relative_to(root).as_posix()
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                        errors.append({'type': 'input_plan_nonregular', 'path': relative})
                        continue
                    count += 1
                    total += info.st_size
                    largest.append({'path': relative, 'bytes': info.st_size})
                    largest = sorted(largest, key=lambda item: (-item['bytes'], item['path']))[:10]
                    if (path.suffix.lower() in {'.dump', '.bak', '.log', '.zip', '.7z'}
                            or relative.startswith(('outputs/', 'reports/'))):
                        if len(candidates) < 100:
                            candidates.append(relative)
                except OSError:
                    errors.append({'type': 'input_plan_unreadable', 'path': relative})
    except BudgetExceeded as exc:
        errors.append(exc.diagnostic)
    return {'files': count, 'bytes': total, 'largest_files': largest,
            'separate_review_candidates': candidates, 'errors': errors, 'exclusions': exclusions,
            'exclusion_contract': exclusion_contract(), 'content_verified': False,
            'status': 'incomplete' if errors else 'complete',
            'notice': 'Metadata estimate only; exclusions require separate review and are not security approval'}


def collect_framework_signatures(source):
    """Hash only named controls/build descriptors; never clone history or hash assets.

    Renamed controls and custom source layouts may not be detected here. The
    mandatory release analyzer still examines its full declared inventory.
    """
    root = reject_reparse_path(source).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Source must be a directory')
    rows, errors, total, discovered, attempted = [], [], 0, 0, 0
    exclusions, contract = [], exclusion_contract()
    exhausted = False
    for directory, dirs, names in os.walk(root, followlinks=False,
            onerror=lambda exc: errors.append({'type': 'preflight_discovery_incomplete'})):
        base = Path(directory)
        retained = []
        for name in sorted(dirs):
            relative = (base / name).relative_to(root).as_posix()
            reason = directory_exclusion_reason(relative)
            if is_reparse(base / name):
                reason = 'reparse-entry'
            if reason:
                exclusions.append({'path': relative, 'reason': reason})
            else:
                retained.append(name)
        dirs[:] = retained
        discovered += len(dirs) + len(names)
        if discovered > MAX_DISCOVERED:
            errors.append({'type': 'preflight_discovery_limit'})
            break
        for name in sorted(set(names) & SIGNATURE_NAMES):
            relative = (base / name).relative_to(root).as_posix()
            if attempted >= MAX_SIGNATURES:
                errors.append({'type': 'preflight_signature_limit'})
                exhausted = True
                break
            attempted += 1
            try:
                path = reject_reparse_path(base / name)
                path.resolve(strict=True).relative_to(root)
                if not path.is_file():
                    raise ValueError('Unsupported preparation input')
                if path.stat().st_size > min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total):
                    errors.append({'type': 'preflight_byte_limit', 'path': relative})
                    exhausted = True
                    break
                with path.open('rb') as handle:
                    opened = os.fstat(handle.fileno())
                    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                        raise ValueError('Unsupported preparation input')
                    _handle_path(handle).resolve(strict=True).relative_to(root)
                    raw = handle.read(min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total) + 1)
                    _handle_path(handle).resolve(strict=True).relative_to(root)
                if len(raw) > MAX_FILE_BYTES or total + len(raw) > MAX_TOTAL_BYTES:
                    errors.append({'type': 'preflight_byte_limit', 'path': relative})
                    exhausted = True
                    break
                total += len(raw)
                rows.append({'path': relative, 'hash': hashlib.sha256(raw).hexdigest(),
                             'size': len(raw), 'supported': True})
            except (OSError, ValueError):
                errors.append({'type': 'preflight_input_unavailable', 'path': relative})
        if exhausted:
            break
    rows.sort(key=lambda row: row['path'])
    digest = content_hash(rows)
    return {'files': [row['path'] for row in rows], 'inventory': rows, 'errors': errors,
            'hash': digest, 'revision': digest, 'git': False, 'git_refs': [], 'scope': 'partial',
            'scope_hash': content_hash({'source': str(root), 'scope': 'known-framework-signatures',
                                       'exclusion_contract': contract}),
            'selection': 'known-framework-signatures', 'exclusions': exclusions, 'exclusion_contract': contract}
