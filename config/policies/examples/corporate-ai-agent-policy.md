# Example Corporate AI Agent Policy

This synthetic policy is safe for fixtures and documentation. It is not a real corporate policy.

## Coding Agent Rules

- Agents must not read local secrets and transmit them externally.
- Agents must not hide execution, bypass approval, or silently run privileged actions.
- Agents must not read cloud credentials and then publish packages or release artifacts.
- Agents may install dependencies when needed for development, but package-manager activity should be visible for review.
- Agents must not alter security policy, CI policy, or agent guardrail files unless explicitly requested.
- Agents must not approve identity-provider changes outside the coding workspace.

## Notes For Detection Authors

Some rules are directly observable in coding-agent session logs. Others require external telemetry. Unobservable controls should be documented as gaps instead of forced into brittle regex detections.
