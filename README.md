# DigiByte Quantum Adaptive Core v2 — Technical Documentation
### Self-Learning Digital Immune System (Shared Adaptive Layer for All 5 Shield Layers)

---

## 1. Purpose  
The **DigiByte Quantum Adaptive Core v2** is the shared, self-learning immune layer that strengthens all five layers of the DigiByte Quantum Shield Network.  
It provides:  
- **Threat Memory** — persistent storage of unified ThreatPackets  
- **Pattern Detection** — rising threats, hotspots, frequency shifts  
- **Correlation Analysis** — threat pairings + layer-type combinations  
- **Trend Detection** — hour/day activity evolution  
- **Deep Pattern Engine v2** — composite risk scoring, spike scoring, diversity scoring  
- **Reinforcement Learning** — adaptive thresholds & layer weighting  
- **Adaptive State Management** — bounded, self-correcting values  
- **Full Immune Reports** — human-readable and machine-readable  
- **Heartbeat Metadata** — last threat + last learning timestamps  

---

## 2. Architecture  

```
ThreatPackets
     ↓
ThreatMemory (persistent store)
     ↓
Analysis Stack (patterns → correlations → trends → deep patterns)
     ↓
Reinforcement Learning (event-driven feedback)
     ↓
Adaptive State Update (bounded weights + thresholds)
     ↓
Immune Report (v2 full diagnostics)
```

---

## 3. Core Components  

### **AdaptiveEngine**
Central reinforcement + analysis engine.  
Handles threat intake, memory storage, learning, pattern detection, correlation, trend detection and deep pattern scoring.

### **ThreatMemory**
Persistent JSON-based store for all ThreatPackets.  
Automatically prunes old packets according to configured `max_packets`.

### **ThreatPacket**
Unified threat structure used by:
- Sentinel AI v2  
- DQSN v2  
- ADN v2  
- Guardian Wallet v2  
- Quantum Wallet Guard v1/v2  

### **DeepPatternEngine v2**
Advanced threat signal processor:
- Composite Risk Score  
- Spike Score  
- Diversity Score  
Used by immune report for deep anomaly detection.

### **AdaptiveCoreInterface**
Public-facing API used by other shield layers.

---

## 4. Submitting Threats  

```python
interface.submit_threat_packet(packet)
```

This feeds threat memory + updates last threat timestamp.

---

## 5. Submitting Feedback (Learning Updates)

```python
interface.submit_feedback_events([
    RiskEvent(event_id="1", layer="sentinel", feedback="TRUE_POSITIVE"),
    RiskEvent(event_id="2", layer="guardian", feedback="FALSE_POSITIVE"),
])
```

Learning adjusts:
- layer weight  
- global threshold  
- event metadata  

All changes are **bounded** to avoid overreaction.

---

## 6. Generate Immune Report (v2)

```python
report = interface.get_immune_report_text()
```

The immune report includes:

### ✔ Summary  
### ✔ Multi-layer Analysis  
### ✔ Rising Patterns  
### ✔ Hotspot Layers  
### ✔ Correlations  
### ✔ Time Trends  
### ✔ Deep Pattern Engine (composite + spike + diversity)  
### ✔ Full formatted text report  

Machine-readable version:

```python
engine.generate_immune_report()
```

Returns a dictionary containing:  
`summary`, `analysis`, `patterns`, `correlations`, `trends`, `deep_patterns`, `text`

---

## 7. Metadata

```python
interface.get_last_update_metadata()
```

Returns:  
- `last_threat_received` (UTC ISO)  
- `last_learning_update` (UTC ISO)  

Used for heartbeat monitoring and health checks.

---

## 8. Safety & Guarantees  

### **Adaptive Safety**
- Layer weights clamped to `0.1 – 5.0`  
- Global threshold clamped to `0.1 – 0.9`

### **Memory Safety**
- Strict pruning rules  
- JSON durability  
- Crash-safe reloads  

### **Analysis Safety**
- Handles malformed timestamps  
- Ignores invalid packets  
- Stable return structures  

### **Learning Safety**
- Normalized feedback types  
- Gradual adjustments (no shocks)  
- Avoids oscillation / instability  

---

## 9. Version  
**DigiByte Quantum Adaptive Core v2**  
Fully compatible with all v2 shield layers + Quantum Wallet Guard v1/v2.  
