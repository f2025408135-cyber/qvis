## What this PR does

[One paragraph description]

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring
- [ ] Documentation
- [ ] New detection rule

## For new detection rules

- [ ] Rule ID assigned (QTT011+)
- [ ] Pure function — no side effects
- [ ] Uses `_cfg()` for all thresholds (quality gate G5)
- [ ] Evidence dict contains `rule_name` and `threshold_used` (G6)
- [ ] Added to Q-ATT&CK taxonomy table in docs/quantum-threat-taxonomy.md
- [ ] 8+ tests covering positive, negative, and edge cases

## Testing

- [ ] All existing tests pass
- [ ] New tests added for new code
- [ ] Coverage did not decrease

## Checklist

- [ ] Code follows existing patterns (structlog, type hints, docstrings)
- [ ] .env.example updated if new config vars added
- [ ] CHANGELOG.md updated
