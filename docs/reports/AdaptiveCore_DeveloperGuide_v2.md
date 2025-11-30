# 🧬 Adaptive Core — Developer Guide (v2)

Author: DarekDGB  
AI Engineering Assistant: Angel  
License: MIT

---

## 1. Introduction

This guide shows developers **how to use the Adaptive Core** as an external module:  
how to initialize it, send events, load memory, and read immune responses.

---

## 2. Installation

Clone the repo:

```bash
git clone https://github.com/DarekDGB/DigiByte-Adaptive-Core
cd DigiByte-Adaptive-Core
```

Run tests:

```bash
pytest -q
```

---

## 3. Basic Usage

### Initialize the engine

```python
from adaptive_core.engine import AdaptiveCoreEngine

core = AdaptiveCoreEngine()
```

### Send events

```python
response = core.handle_event({
    "type": "wallet_behavior",
    "severity": 0.52,
    "metadata": {"address": "DGB123"}
})
```

### Read responses

```python
print(response.immune_score)
print(response.level)
```

---

## 4. Integrating with Wallet Layers

Wallets send:

- entropy drop signals  
- abnormal spending patterns  
- signature‑timing anomalies  

Example:

```python
core.handle_event({
    "type": "quantum_signature",
    "severity": 0.91,
})
```

---

## 5. Integrating with Node Layers

Sentinel, DQSN and ADN send:

- network anomalies  
- reorg depth signals  
- sudden hash‑rate deviation patterns  

---

## 6. Learning Reports

Developers can generate a full report:

```python
from adaptive_core.engine import AdaptiveCoreEngine

core = AdaptiveCoreEngine()
report = core.generate_learning_report()
print(report)
```

---

## 7. Best Practices

- Always run with fresh memory snapshots  
- Rotate long-term memory every 30 days  
- For testnet: enable verbose mode  
