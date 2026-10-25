# <Method>

<Describe the completed native API request and its filters.>
Measured source(s): `<full actual measured SHA(s)>`.
<Identify implementations when their measured source revisions differ.>
[Methodology](methodology.md), [reproducibility](reproducibility.md) and
[shared commands](README.md).

🟢 below baseline; 🔴 above baseline; ⚪ baseline/equal.

### Benchmark Results

Baseline: <Name the implementation used for this request.>

#### <Dataset name>

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | ... | ... | ... | ... | ... | ... |
| Maintained kvdb | ... | ... | ... | ... | ... | ... |
| PostgreSQL | ... | ... | ... | ... | ... | ... |
| SQLite | ... | ... | ... | ... | ... | ... |

<Use a separate table per dataset, with whole-number metrics and thousands
separators. Each ratio cell has only a colored dot and two-decimal number;
mark the baseline/equal cells ⚪ 1.00. Use the shared methodology for arithmetic.
Exclude smoke results. Keep measured source revisions above the tables.>

### Notes

<Keep short notes on native request semantics, comparison limits and material
measurement exceptions. Identify unavailable or unmatched implementations
without inventing metrics. Keep routine setup/timer policy, run labels/dates,
serial orders and profile paths in shared docs or evidence, not this report.>
