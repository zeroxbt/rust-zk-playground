# rust-zk-playground

A Rust workspace of tiny, numbered crates, each isolating one zero-knowledge or modern cryptography concept. The goal is to learn by doing: keep every project minimal, runnable, and focused on one idea at a time.

## What this workspace is for
- Hands-on practice with ZK proofs and related cryptographic building blocks
- Clear separation of concepts: each folder (`01-…`, `02-…`, etc.) is its own crate
- A growing set of small examples that can later be composed into larger systems

## How I’m learning
- One concept per crate: constraints, witnesses, public vs private inputs, hash gadgets, commitments, Merkle proofs, basic Halo2 circuits, zkVM experiments, and more
- Prefer runnable mains over library scaffolding to see the full flow (define circuit → generate proof → verify)
- Minimal math, maximum code clarity: brief explanations alongside working Rust
- Incremental progression: start with trivial circuits (e.g., `x + 1 = 7`), then build up to arithmetic relations, hash preimages, commitments, and simple protocols
- Keep dependencies scoped to each crate; use the workspace only for organization and shared tooling