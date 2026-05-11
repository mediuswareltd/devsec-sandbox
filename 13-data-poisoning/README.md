# 13 — Data Poisoning

## What is it?
Data poisoning is an attack on machine learning models where an attacker
injects malicious training examples to corrupt the model's behavior.

Types:
- **Backdoor attacks**: Model works normally BUT gives wrong output for a specific trigger
- **Targeted attacks**: Make model misclassify a specific input
- **Availability attacks**: Degrade the model's overall accuracy

## How to run
Open in browser — no server needed:
  vulnerable.html
  fixed.html

## What to try (Vulnerable version)
1. The sentiment classifier starts trained on clean data
2. Add poisoned training examples using the "Inject Poisoned Data" section
3. Watch how the model's prediction for the word "excellent" changes
4. After enough poison, the model labels positive reviews as negative!

## The Fix
- Input validation: check for anomalous training samples
- Anomaly detection: flag examples that are statistical outliers
- Data provenance: track where training data came from
- Certified defenses: train with robustness guarantees
