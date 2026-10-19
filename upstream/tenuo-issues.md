# Draft Tenuo issues (not filed)

Product gaps found while building the AgentDojo adapter. Each is written to stand alone without mentioning the
experiment, so it can be filed publicly when we choose.

## 1. Constraints cannot match a null argument

Tool schemas often have optional arguments that arrive as `null` after validation (an unchanged recipient, no cc).
Closed-world checking requires the argument to be present and constrained, but no constraint accepts `null` alongside
other values:

```python
Exact(None)                                   # TypeError: 'None' is not an instance of 'str'
OneOf(["a"]).satisfies(None)                  # False
Subset(["a"]).satisfies(None)                 # False
AnyOf([OneOf(["a"]), Exact(None)])            # cannot be built
```

`Wildcard()` accepts `null` but accepts everything else too. Workaround today: map `null` to a sentinel before the
check and include the sentinel in `OneOf`, which means the checked value differs from the executed one.

Ask: a way to say "this value, or absent", e.g. `Exact(None)` / `Null()` usable inside `AnyOf`, or an
`optional=True` flag on a capability argument. The same gap made Hermes' optional `terminal` arguments
(`timeout`, `workdir`) impossible to constrain without denying calls that omit them.

## 2. Case-insensitive identifier matching

Email addresses, hostnames and user handles compare case-insensitively in the systems that consume them, but
`OneOf` and `Subset` are exact. An agent that writes `Alice@Example.com` is denied against
`alice@example.com`. Workaround: lowercase both sides outside Tenuo, which again separates the checked value from
the executed one.

Ask: a normalization option on `OneOf`/`Subset` (`casefold=True`), or documented guidance.

## 3. Authority that depends on data the agent reads (design discussion)

A common legitimate request names a source, not a value: "pay the bill in this file", "message the user who posted
the most". A warrant issued from the request cannot pin the payee or user, and the source document may itself be
attacker-controlled. Options worth documenting: approval for targets the issuer could not establish (Tenuo approval
gates already exist), and re-issuance after a trusted read. No code change proposed yet.
