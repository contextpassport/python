# Context Passport — Python Reference Implementation

A reference implementation of the [Context Passport](https://github.com/contextpassport/spec) v1.0 specification in Python.

**Specification:** https://github.com/contextpassport/spec
**License:** Apache-2.0

## Install

```bash
pip install context-passport
```

(Not yet on PyPI — install from source while v1.0 is in draft.)

```bash
pip install git+https://github.com/contextpassport/python.git
```

## Usage

```python
from context_passport import make_passport, verify_chain

# Root commit
root = make_passport(
    agent_id="agent-researcher-01",
    agent_name="Research Agent",
    payload={"input": "Analyze Q1 earnings", "output": {"summary": "APAC up 34%"}},
    role="researcher",
    provider="anthropic",
    model="claude-opus-4-6",
)

# Child commit
child = make_passport(
    agent_id="agent-writer-01",
    agent_name="Writer Agent",
    payload={"input": root["payload"]["output"], "output": "Draft prepared."},
    parent=root,
)

# Verify the chain
assert verify_chain([root, child])
```

## Conformance

This implementation targets **Core conformance** with the [Context Passport v1.0 conformance test suite](https://github.com/contextpassport/conformance-tests). Signed conformance is planned.

To run the conformance tests against this implementation:

```bash
git clone https://github.com/contextpassport/conformance-tests.git
cd conformance-tests
python runner/python/run.py --implementation context_passport
```

## Contributing

See [CONTRIBUTING.md](https://github.com/contextpassport/spec/blob/main/CONTRIBUTING.md) in the spec repository. Bug reports and pull requests welcome on this repo.

## Related repositories

- [contextpassport/spec](https://github.com/contextpassport/spec) — the specification
- [contextpassport/typescript](https://github.com/contextpassport/typescript) — TypeScript reference implementation
- [contextpassport/conformance-tests](https://github.com/contextpassport/conformance-tests) — conformance test suite
