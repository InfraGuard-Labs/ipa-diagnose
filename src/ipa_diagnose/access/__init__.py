"""`ipa-diagnose access USER HOST SERVICE`: does FreeIPA policy authorize USER to access HOST through SERVICE, and why?

The decision comes from FreeIPA's own HBAC evaluator (the ``hbactest`` API command, which uses the same libipa_hbac
library SSSD enforces with). ipa-diagnose only gathers the identity facts around it, explains the matched rule with a
small, bounded relationship index (``relations.py``), and never changes anything. See docs/access-diagnosis.md.
"""
