"""Canonical import namespace matching the repository/common library ID."""
from mithril_interop.libraries import resolve_library, invoke_library
from mithril_link16 import link16
LIBRARY_ID = 'fund.mithril.lib.siso.link16'
def resolve(): return resolve_library(LIBRARY_ID)
def invoke(operation, arguments=None): return invoke_library(LIBRARY_ID, operation, arguments)
