# AI-Powered Network Intrusion Detection System

# Final Technical Performance Report

---

## 1. Executive Summary

The finalized system consists of a Random Forest base classifier, an LSTM sequence classifier, and a probability-stacking ensemble.

The finalized ensemble strategy is **probability_stacking** using **LogisticRegression** with C = **1.0** and class weighting = **balanced**.

The primary ensemble-selection metric was **macro_f1**.

The independent-test evaluation identified **Random Forest** as the strongest model under the primary Macro F1 criterion.

---

## 2. Final Ensemble Architecture

```text
Random Forest ───────┐
                     │ 15-class probabilities
                     ├──────────────┐
                     │              │
LSTM ────────────────┘ 15-class     │
                        probabilities
                                     ↓
                         30-dimensional meta-features
                                     ↓
                              Logistic Regression
                                   C = 1.0
                              class_weight=balanced
                                     ↓
                              Global 15-class output
```

---

## 3. Final Model Configuration

### Random Forest

- Model type: `RandomForestClassifier`
- Number of estimators: `100`
- Input features: `63`
- Output classes: `15`
- Class weighting: `balanced_subsample`
- Max features: `sqrt`
- Max depth: `None`
- Random state: `42`

### LSTM

- Sequence length: `5`
- Input features: `63`
- Output classes: `15`
- LSTM units: `64`
- Dropout: `0.2`
- Optimizer: `Adam`
- Learning rate: `0.001`
- Batch size: `256`
- Maximum epochs: `30`

### Final Ensemble

- Strategy: `probability_stacking`
- Meta-learner: `LogisticRegression`
- C: `1.0`
- Class weighting: `balanced`
- Probability features per base model: `15`
- Total stacking meta-features: `30`
- Global output classes: `15`

---

## 4. Dataset and Evaluation Configuration

- Training samples: **2,264,594**
- Independent-test observations: **566,149**
- Input features: **63**
- Output classes: **15**
- Sequence length: **5**
- Complete common evaluation sequences: **113,229**
- Used test observations: **566,145**
- Unused trailing observations: **4**

Common evaluation representations:

- Random Forest: `(113229, 63)`
- LSTM: `(113229, 5, 63)`
- Common target: `(113229,)`

---

## 5. Development-Stage Ensemble Selection

- Selected strategy: **probability_stacking**
- Meta-learner: **LogisticRegression**
- C: **1.0**
- Class weighting: **balanced**
- Selection Accuracy: **0.983143**
- Selection Macro F1: **0.701659**
- Selection Weighted F1: **0.989358**
- Independent test used for strategy selection: **False**

---

## 6. Independent-Test Performance

| Model | Accuracy | Macro Precision | Macro Recall | Macro F1 | Weighted Precision | Weighted Recall | Weighted F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.997174 | 0.793497 | 0.805317 | 0.786679 | 0.997234 | 0.997174 | 0.997187 |
| LSTM | 0.967376 | 0.496387 | 0.736063 | 0.559624 | 0.983661 | 0.967376 | 0.974189 |
| Final Ensemble | 0.976746 | 0.620924 | 0.772166 | 0.642411 | 0.996485 | 0.976746 | 0.986080 |

Primary independent-test metric: **Macro F1**
Independent-test winner: **Random Forest**

---

## 7. Model Comparison

- Ensemble vs Random Forest Accuracy difference: **-0.020428**
- Ensemble vs Random Forest Macro F1 difference: **-0.144268**
- Ensemble vs Random Forest Weighted F1 difference: **-0.011107**

- Ensemble vs LSTM Accuracy difference: **+0.009370**
- Ensemble vs LSTM Macro F1 difference: **+0.082787**
- Ensemble vs LSTM Weighted F1 difference: **+0.011891**

---

## 8. Error Analysis Findings

- Random Forest incorrect predictions: **320**
- LSTM incorrect predictions: **3,694**
- Final Ensemble incorrect predictions: **2,633**
- All three models agree: **108,775** (96.0664%)
- All three models disagree: **124** (0.1095%)
- RF correct → Ensemble wrong: **2,380**
- RF wrong → Ensemble correct: **67**
- LSTM-assisted successful RF corrections: **49**

---

## 9. Class-Level Findings

- Supported independent-test classes: **14**
- Ensemble F1 > RF F1: **1** supported classes
- Ensemble F1 < RF F1: **12** supported classes
- Ensemble F1 = RF F1: **1** supported classes
- Zero-support classes: **[np.int64(8)]**
- Low-support classes (support <= 5): **[np.int64(8), np.int64(9), np.int64(13)]**
- Largest Ensemble class-level error source: **Class 0** (2,558 errors)

---

## 10. Persisted Artifacts

### Model Artifacts

- `random_forest_handoff.joblib`
- `final_lstm_model.keras`
- `final_stacking_meta_learner.joblib`

### Configuration Artifacts

- `final_lstm_configuration.json`
- `final_ensemble_configuration.json`

### Evaluation and Reporting Artifacts

- `final_ensemble_performance.csv`
- `final_ensemble_classwise_results.csv`
- `final_ensemble_error_analysis.csv`
- `final_ensemble_confusion_matrix_rf.csv`
- `final_ensemble_confusion_matrix_lstm.csv`
- `final_ensemble_confusion_matrix.csv`
- `final_ensemble_performance_report.md`

---

## 11. Evaluation Limitations

- Zero-support independent-test class: **[np.int64(8)]**
- Low-support classes: **[np.int64(8), np.int64(9), np.int64(13)]**
- Very low-support class metrics require cautious interpretation.
- The Final Ensemble does not outperform Random Forest on the independent test.

---

## 12. Evaluation Integrity

- Independent-test data was reserved for final evaluation.
- The frozen ensemble configuration was preserved during testing.
- No model retraining was performed after independent-test evaluation.
- No threshold tuning was performed after independent-test evaluation.
- No ensemble re-selection was performed using independent-test results.

---

## 13. Final Conclusion

The finalized system combines Random Forest and LSTM probability outputs through a Logistic Regression stacking layer.

The independent-test evaluation identified **Random Forest** as the strongest measured model under the primary Macro F1 criterion.

The persisted Final Ensemble remains the development-selected probability-stacking architecture. Its measured test behavior, including class-level strengths, weaknesses, and limitations, is documented without modifying the finalized configuration.

---

## 14. Report Status

**Generated from validated Notebook 08 configuration, evaluation, error-analysis, and persistence results.**
