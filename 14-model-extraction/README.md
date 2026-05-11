# 14 — Model Extraction

## What is it?
Model extraction (model stealing) is an attack where an adversary queries
an ML model repeatedly to reconstruct its decision logic without direct access.

With enough queries, an attacker can:
- Create a near-identical copy of the model
- Bypass rate-limiting or paywalls
- Understand model internals for adversarial attacks

## How to run
Open in browser — no server needed:
  vulnerable.html
  fixed.html

## What to try (Vulnerable version)
1. A credit scoring model is available via "API"
2. Send individual queries — each returns exact scores
3. Click "Auto-Extract Model" — watch as the decision boundary is mapped
4. After ~20 queries, the attacker has enough to replicate the model
5. The "Extracted Model" panel shows the reconstructed logic

## The Fix
1. Rate limiting: max 10 queries per session
2. Output perturbation: add random noise to scores (hard to average out)
3. Query monitoring: detect systematic probing patterns
4. Round outputs: return "High/Medium/Low" instead of exact scores
