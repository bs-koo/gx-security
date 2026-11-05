#!/usr/bin/env python3
"""Run gx-security directly from a checkout without installing the package."""
import sys
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

_source = Path(__file__).resolve().parent / "src"
# Test runners may prepend the checkout ahead of src. Retain package semantics
# when this convenient executable is discovered as the gxsec import.
if __name__ == "gxsec":
    __path__ = [str(_source / "gxsec")]
    _spec = spec_from_file_location('_gxsec_checkout_metadata', _source / 'gxsec' / '__init__.py')
    _metadata = module_from_spec(_spec)
    _spec.loader.exec_module(_metadata)
    SCHEMA_VERSION = _metadata.SCHEMA_VERSION
    __version__ = _metadata.__version__
else:
    sys.path.insert(0, str(_source))

if __name__ == "__main__":
    from gxsec.cli import main
    raise SystemExit(main())
