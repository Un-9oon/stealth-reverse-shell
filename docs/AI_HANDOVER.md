# ERS outcome assistant handover

## Fixed core idea

Keep the existing ERS Linux / ERS-W Windows framework as the controlled-lab experimental foundation. Add exactly one AI feature: a read-only classifier that predicts the outcome of a predeclared harmless task from sanitized operator observations. Begin with offline post-session analysis. Do not implement payload generation, command selection, autonomous actions, evasion changes, failure-root-cause analysis or PhantomGate functionality.

## Status and baseline

Code baseline: `20e0518de1bb31a866212e73b1882c4db5514772` in `Un-9oon/stealth-reverse-shell`. The new analytical pipeline, oracle fixtures, dataset and model are proposed. The current documentation change does not modify operational source files.

Before editing, inspect repository instructions, git status, actual code commit, listener record formats and applicable existing tests. Do not assume task correlation fields already exist. If observations are insufficient, document that limitation rather than fabricating labels or improving shell capabilities.

## Unit and labels

Evaluate one task episode within a session. A connection can contain multiple tasks. Use:

- `EXECUTION_COMPLETE`: independent endpoint completion and expected full output receipt verified.
- `OUTPUT_INCOMPLETE`: execution independently verified but expected output receipt demonstrably partial/absent.
- `EXECUTION_FAILED`: trusted fixture explicitly records failure, not merely missing output.
- `INCONCLUSIVE`: independent evidence does not establish another outcome.

Prediction status is separate: `PREDICTED`, `ABSTAINED`, `UNAVAILABLE`, `INVALID_INPUT`. A prediction is not ground truth. No output does not prove failure; connection establishment does not prove completion.

## Analysis architecture

```text
Existing approved lab run
  -> exported operator observations
  -> schema validator and metadata sanitizer
  -> correlated task windows
  -> explicit rules / trained classifier
  -> frozen prediction with evidence references
  -> read-only report

Separate endpoint fixture records
  -> reviewed oracle labels
  -> offline join with frozen predictions
  -> evaluation metrics
```

The assistant has no endpoint route, execution API, listener-control credentials or oracle read access. Oracle records become supervised targets or offline evaluation labels only. Never add privileged truth fields to inference features.

## Data contract

Input contains schema version, opaque run/session/task/window identifiers, ordered normalized events, timing and completeness metadata. IDs are grouping keys, not predictive features. Exclude raw commands, output, file contents, credentials, environment dumps, raw packet payloads, destination identifiers and fault/scenario labels.

Output contains schema/model version, task/window identity, predicted class, confidence or null, status, abstention reason and evidence-event IDs. Validate sizes, types, enums, probability range, task boundaries and referenced-event membership. Unknown fields are rejected.

## Models and evaluation

Implement explicit rules and majority baselines first; then train logistic regression and gradient-boosted trees. A complex sequence model is future work. Use identical allowed observations for all baselines. Fit preprocessing on training only; tune/calibrate on validation only.

Group all events/tasks from the same session and near-duplicate fixture run into the same split. Hold out machines and collection periods. Report Linux/Windows separately; cross-OS transfer requires a separate protocol. Record labels, class counts, reviewed disagreements, seeds, code/data/split/model hashes and exclusions.

Measure per-class precision/recall, macro-F1, false-success conclusions, incorrect success claims among all success predictions, uncertainty calibration, risk versus coverage, analysis latency and resource use. If identical observations correspond to different real outcomes, state the information limit and evaluate abstention. Do not force AI superiority when rules suffice.

## Proposed module boundaries

- `analysis/`: importer, validator, sanitizer, task windows, classifier client and read-only reporting.
- `ml/`: features, training, calibration and artifact provenance.
- `evaluation/`: group split audit, rules, metrics and leakage checks.
- `lab/`: synthetic benign fixtures, independent oracle records and reset verification.

Do not claim these paths already exist. Adapt naming to the inspected repository.

## Milestones

1. Reviewed baseline and one scoped synthetic fixture.
2. Sanitized schema, correlation audit and independently reviewed labels.
3. Rules baseline and evidence-linked report.
4. Pilot dataset and grouped training/validation.
5. Selected read-only classifier and explicit abstention/unavailable behavior.
6. Held-out evaluation, privacy/recovery checks and measured report updates.

## Required checks

Secret canaries absent before storage/export; interleaved tasks never mixed; no oracle leakage; invalid schema rejected; unavailable model never triggers agent actions; evidence references valid; committed analysis records recover; held-out groups and duplicates audited; report clearly separates predictions from truth.

This is a candidate research contribution, not confirmed global novelty. The original Word report is historical; use the revised PDF and Markdown with this handover. No trained accuracy or robustness result is established yet.
