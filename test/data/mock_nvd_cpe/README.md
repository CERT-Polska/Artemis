# Mock NVD CPE dictionary

A stand-in for the NVD CPE 2.0 dictionary, pointed at by `CPE_NVD_DIR` in the test container so that
`artemis.cpe_tools.cpe_utils` answers lookups in the integration tests. Without it the tests run
against an empty directory in CI - every lookup returns `None`, and an assertion that an asset
carries a CPE passes without checking anything.

What is stored here are the raw feed chunks, not a ready-made index: the indices are built from them
by `_build_indices()` on first use, so that code is covered too.

Ten entries, copied verbatim from the real feed. Two of them are what the integration tests actually
assert on: `wordpress:wordpress`, which the wp_scanner reporter looks up by title, and
`rocklobster:contact_form_7`, which the wordpress_plugins one looks up by plugin slug. The rest are
here so that the lookups run against something more than a two-element map, and so that the shapes a
real feed has - several releases of one product, a deprecated name, a ref with a fragment - are
present rather than assumed away:

* `wordpress:wordpress` under three names - the product itself (a title without a version) and two
  releases, which the title index has to collapse onto the single `wordpress` key.
* `rocklobster:contact_form_7` and `automattic:akismet`, WordPress plugins whose refs point at
  `wordpress.org/plugins/<slug>/`, which is what the plugin slug index is keyed by. Akismet's ref
  carries a `#developers` fragment, which the slug has to be cut at.
* Two deprecated `ait-pro:bulletproof-security` names, superseded by ones carrying the `wordpress`
  target software and referencing `wordpress.org/plugins/bulletproof-security/` - the kind of entry
  `_iter_entries()` has to drop before it reaches the slug index.

Do not read that list as coverage. The behaviour of the index builder itself - version trimming,
per-product keying, deprecated filtering, the url index (which no reporter consults) - is asserted in
`test/unit/test_cpe_utils.py`, on fixtures written for exactly that. Every single entry here can be
deleted on its own and both integration tests still pass; what they need from this directory is that
the two lookups above resolve at all.
