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

| Retriever or filtered-document assertions miss leaks introduced during prompt assembly | Boundary tests stopped before the complete generator input and lacked a positive bypass control | Record real Haystack pipeline prompts against explicit fixture IDs/content and require unauthorized canaries in every bypass repetition; report source hashes and category-policy scope |

| Public Haystack constructor cannot be added to a pipeline | Only a private helper registered the component, and request scopes accepted malformed principals | Register lazily through a stable optional module, reject invalid principals at scope/run boundaries, and test store-to-model prompts plus fresh-process pipeline loading |
| Release workflow uses an advisory-affected or mutable publishing action | A dependency update in one repository left equivalent release workflows unchanged | Pin every publishing workflow to the verified patched action commit and validate each workflow before release |
| Optional SDK type checking differs between environments | A decorator is untyped without the SDK, while ignores become unused with newer typed SDKs | Type the factory subtype and decorator boundary explicitly, then check installed and absent SDK typing modes |

| Version validation fails despite updated source, or native SDK tests see stub modules | Editable distribution metadata retains its installed version, while unit tests install SDK stubs in the same process | Reinstall editable metadata after a version bump and run unit and native integration suites in separate processes |

| Published context examples fail against the public API or imply automatic orchestration | Design guidance introduced fields and behavior absent from the lightweight dataclasses | Use actual constructors, separate application responsibilities, and execute fenced documentation examples in a focused test |

| Installing the all extra fails before any package can run | The maf extra required a distribution absent from the registry while its adapter only had stub execution coverage | Retire the unavailable extra, exclude it from all, retain the legacy module and explicitly exclude native registration from support |

| A supported optional install automatically brings outstanding advisory findings | SDK transitive graphs contain unresolved vulnerabilities and no reviewed compatible clean graph | Remove affected extras from metadata and all, preserve adapter APIs as security quarantined, and require fresh per-extra/Python audits plus native tests before restoration |

| A release guard accepts incomplete artifacts or mismatched source-distribution identity | Validation iterated whatever artifacts happened to exist and checked only wheel metadata | Require one wheel and one sdist, stable source/tag identity and both metadata records; exercise missing, extra and mismatched archive fixtures |

| Python 3.10 optional installs select vulnerable dependencies while Python 3.12 scans clear | Fixed dependency releases require Python 3.11, so the resolver falls back to affected older versions | Keep core 3.10 support, add unconditional patched floors to affected extras, document 3.11 SDK contracts and treat 3.10 rejection as an excluded support cell |
