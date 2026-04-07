# GNAT Copilot review instructions

When reviewing PRs in this repository, prioritize:

1. **Connector compatibility**
   - Existing public methods should keep working unless the PR clearly introduces a versioned replacement.
   - Prefer adapter fallbacks over breaking renames.

2. **STIX safety**
   - Flag changes that alter object shape, required fields, relationship semantics, or timestamps.
   - Treat mapper changes as high-risk even if tests pass.

3. **Auth drift**
   - Highlight any changes to scopes, tokens, key names, permission expectations, or tenant assumptions.

4. **Testing quality**
   - Ask for fixture or golden-output coverage when a mapper or response translator changes.

5. **Maintenance bot expectations**
   - Bot-authored PRs should stay draft until a human reviewer is satisfied.
   - Prefer actionable comments that reference the concrete file and likely regression mode.

---

*Licensed under the Apache License, Version 2.0*
