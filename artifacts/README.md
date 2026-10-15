# Threat-hunting research evidence

Versioned outputs of the ATT&CK-grounded detection-engineering research. This is **evidence**, not raw telemetry or a collection of confirmed incidents.

| Stage | Folder | Interpretation |
| --- | --- | --- |
| Context | [`environment/`](environment/) | Platform applicability and telemetry readiness |
| Hypotheses | [`hypotheses/`](hypotheses/) | ATT&CK-grounded hunt proposals |
| Gate | [`eligibility/`](eligibility/) | Eligibility and rejection decisions |
| Plans | [`detection-plans/`](detection-plans/) | Observable, path and data-source requirements |
| Rules | [`sigma/`](sigma/) | 540 research Sigma rules and pySigma checks |
| Queries and execution | [`splunk/`](splunk/) | SPL, telemetry resolution, queue and runtime evidence |
| Findings | [`hunt-findings/`](hunt-findings/) | Validated candidate dispositions |
| Data support | [`telemetry/`](telemetry/) | Canonical and resolved telemetry summaries |
| Method support | [`research/`](research/) | Dataset selection/research metadata |

## Reading the results correctly

The recorded runtime batch executed **404** execution-ready hunts, of which **22** produced nonzero raw search results. Post-execution validation yielded **zero confirmed malicious hunt findings**. These figures are stage-scoped: Sigma validity is not SIEM availability; raw search hits are not validated positives; an ML probability is not an analyst verdict.

Consult the versioned manifests and stage-specific summaries before citing totals. For architecture and limitations, see [`docs/VALIDATION_AND_LIMITATIONS.md`](../docs/VALIDATION_AND_LIMITATIONS.md).
