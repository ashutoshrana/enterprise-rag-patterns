# Repository maintenance

## Common Failure Patterns

| Symptom | Root cause | Fix |
|---|---|---|
| Unclassified retrieval results reached context | Missing metadata was treated as shared/public | Require complete private metadata or explicit trusted public classification; test model input with real stores |
| Callback enforcement failed with real SDK | Duck handler omitted callback attributes and raised before sanitizing | Implement callback protocol, inline execution, and sanitize before exceptions |
| Haystack pipeline failed to connect/run | Postponed annotations and decorated class super binding differed across SDKs | Resolve boundary annotations before registration and call parent implementation explicitly |
| Unauthorized duplicate-content passage reappears after filtering | DSPy rebuilt originals by content text alone | Compare complete normalized records and test identical text with different identities |

| Release appears successful without updated package | Reused version with skip-existing and no exact-tag gate | Use fresh versions, reject tag mismatch, test exact commit, validate distributions and clean wheel imports before upload |

| Standalone LlamaIndex adapter admits unclassified or disallowed-category nodes | Adapter duplicated identity checks without shared category policy | Reuse strict FERPAContextPolicy and exercise real sync/async query-engine prompts |
