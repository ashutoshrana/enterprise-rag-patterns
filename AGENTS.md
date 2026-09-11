# Repository maintenance

## Common Failure Patterns

| Symptom | Root cause | Fix |
|---|---|---|
| Unclassified retrieval results reached context | Missing metadata was treated as shared/public | Require complete private metadata or explicit trusted public classification; test model input with real stores |
| Callback enforcement failed with real SDK | Duck handler omitted callback attributes and raised before sanitizing | Implement callback protocol, inline execution, and sanitize before exceptions |
| Haystack pipeline failed to connect/run | Postponed annotations and decorated class super binding differed across SDKs | Resolve boundary annotations before registration and call parent implementation explicitly |
| Unauthorized duplicate-content passage reappears after filtering | DSPy rebuilt originals by content text alone | Compare complete normalized records and test identical text with different identities |
