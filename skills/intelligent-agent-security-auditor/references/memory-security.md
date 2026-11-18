# Agent memory, RAG and vector stores (MODULE 07)

| Rule | Risk | Evidence |
|---|---|---|
| MEM-001 | memory shared across users/tenants (or scope unknown in a multi-user deployment) | manifest `scope`, vector-store collection without user/tenant filtering |
| MEM-002 | no TTL / retention | manifest `ttl` |
| MEM-003 | tool output / external content written to long-term memory without provenance | `write_sources`, `provenance_tracking` |
| MEM-004 | recalled memory injected into the system prompt | `injected_into: system_prompt`, interpolation of memory into instructions |
| MEM-005 | no deletion mechanism | `deletion_supported: false` |

Code detection covers common LangChain/LangGraph memory classes and vector stores (Chroma, FAISS,
PGVector, Pinecone, Qdrant, Weaviate, Milvus, LanceDB, Elasticsearch, MongoDB Atlas, OpenSearch,
Redis vector) and mem0. Scope from code is a heuristic (presence of `user_id`/`tenant_id`
partitioning); declare memory in the manifest for reliable evaluation.

## Controls

- **Partition** by user/tenant with server-side enforced filters (namespace per tenant, not a
  metadata filter the model can omit).
- **Provenance** on every write: source, trust level, timestamp; untrusted sources may store
  facts but never rules, preferences or instructions.
- **Placement**: recalled memory goes in a delimited data block, never in system instructions.
- **Retention & deletion**: TTL per data category; per-user and per-entry deletion (also needed
  to purge poisoned entries).
- **RAG ingestion**: scan documents for injection payloads (PI-003/PI-004) before indexing; keep
  source metadata to trace a poisoned chunk back to its document.

## Behavioral tests

ADV-MEM-001 (an email tries to persist a rule), ADV-MEM-002 (cross-user recall). Both run only in
the sandbox and back CTRL-MEM-B1.
