# Contract pins

calve-extensions builds against the Calve Integration Contract (`calve-integration-contract`)
and tests against Calve's host (`calve-app`, `calve-testkit`) from a sibling `../calve-cli`
checkout. [`CONTRACT_PIN`](../CONTRACT_PIN) names the calve-cli commit those crates must match;
`cargo xtask check-contract` fails when the checkout differs from it, so a build never silently
uses another contract.

To move to a newer contract:

1. Check out the new calve-cli commit in `../calve-cli`.
2. Run `scripts/bump-contract.sh <commit>`: it rewrites the pin, then runs the contract check,
   the tests and the conformance suite.
3. Add a row below and commit the pin together with any module changes and new goldens.

| Pin | CIC | Change |
|---|---|---|
| see `CONTRACT_PIN` | 1.0 (pre-release) | Initial modules: classify with root `markers`, capture, relate, diff, detect, check_plan, describe |
