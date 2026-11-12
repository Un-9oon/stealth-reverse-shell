# ERS AI session outcome report

Revision 2.0, prepared 22 October 2026. The original ERS framework remains the experimental foundation. The only proposed AI feature is read-only session/task outcome classification from sanitized observations.

## Contents

- `FYP_Report.pdf`: 35-page FYP design and methodology report.
- `FYP_Report.md`: editable text with linked SVG diagrams.
- `diagrams/`: 11 vector figures.
- `docs/AI_HANDOVER.md`: fixed scope, labels, milestones and implementation limits.
- `PROJECT_SPEC.json`: machine-readable scope and contracts.
- `reports/build_report.py`: self-contained generator for the PDF, Markdown and diagrams.

The report includes abstract, introduction, problem statement, proposed solution, literature review, candidate gap, existing-tools comparison, requirements, architecture, DFDs, use/misuse cases, activity/sequence/data diagrams, AI methodology, evaluation, market-value hypothesis, timeline, conclusion and future work. It contains 16 tables and 10 references.

## Regenerate

From the repository or package root:

```bash
python -m pip install -r reports/requirements.txt
python reports/build_report.py --output-dir .
```

Edit the generator's content blocks to keep the PDF and Markdown synchronized. Update the handover and specification when changing the design.

## Status

The new analysis modules, independent oracle fixtures, dataset, trained model and experiments are proposed. Original numerical stealth scores and unverified comparative rankings are not adopted as validated results. No runtime or model experiments were executed in this documentation revision.

The original `FYP_Report.docx` in the repository is a historical Word version and was not revised in this change. Use the revised PDF/Markdown and generator as the current report. No verified Word renderer was available locally; an unverified replacement DOCX is not supplied.

## Checks

The generated PDF was reopened, all pages rendered and visually reviewed, and figure links and SVG XML checked. Source rebuild consistency and specification syntax were verified. These documentation checks do not establish model performance or framework robustness.

Complete student, institution, supervisor, session and approval details before submission and apply the institution's actual format.
