# fund.mithril.lib.siso.link16

Independent specification plugin for Mithril JSON RPC v1. Plugin ID `fund.mithril.lib.siso.link16`.

Operations: link16-encode, link16-decode, link16-loopback, link16-send, link16-receive.

Install with `python -m pip install -e .`; discovery uses the `mithril.interop.plugins` entry-point group.

SISO 2021 DIS7, TSA0/MTI0, opaque 75-bit words. UDP simulation only; no RF or tactical field semantics.

[Detailed boundaries](https://github.com/mithril-lang/fund.mithril.lib.interop/blob/main/docs/design.md)

## Common library ID and imports

Repository, plugin and library ID: `fund.mithril.lib.siso.link16`. Python/Hy namespace: `fund.mithril.lib.siso.link16`. `.cljk` and `.kotoba` facades are under the matching `src/` namespace path; the packaged `.mith` Library binds this ID to `https://mithril.fund/lib/fund.mithril.lib.siso.link16` with its canonical graph digest.

See the [cross-language contract](https://github.com/mithril-lang/fund.mithril.lib.interop/blob/main/docs/language-adapters.md). Import resolution performs no automatic downloads or network effects.
