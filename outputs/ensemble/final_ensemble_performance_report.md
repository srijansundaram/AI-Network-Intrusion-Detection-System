# Final Random Forest + LSTM Ensemble Performance Report

## 1. Final Ensemble Configuration

- Strategy: probability_stacking
- Meta-learner: LogisticRegression
- Stacking C: 1.0
- Class weighting: balanced
- Primary selection metric: macro_f1
- Independent test used for ensemble selection: False

## 2. Dataset and Evaluation Configuration

- Input features: 63
- Global output classes: 15
- LSTM sequence length: 5
- Training samples: 2,264,594
- Independent-test observations: 566,149
- Common evaluation units: 113,229
- Used test observations: 566,145
- Excluded trailing observations: 4

## 3. Independent-Test Performance

| Model | Accuracy | Macro Precision | Macro Recall | Macro F1 | Weighted Precision | Weighted Recall | Weighted F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.997174 | 0.793497 | 0.805317 | 0.786679 | 0.997234 | 0.997174 | 0.997187 |
| LSTM | 0.967376 | 0.496387 | 0.736063 | 0.559624 | 0.983661 | 0.967376 | 0.974189 |
| Final Ensemble | 0.976746 | 0.620924 | 0.772166 | 0.642411 | 0.996485 | 0.976746 | 0.986080 |

Primary independent-test metric: Macro F1
Independent-test Macro F1 winner: Random Forest

## 4. Error Analysis Findings

- Random Forest incorrect predictions: 320
- LSTM incorrect predictions: 3,694
- Final Ensemble incorrect predictions: 2,633
- All three models agree on 108,775 (96.0664%) evaluation units.
- RF correct → Ensemble wrong: 2,380
- RF wrong → Ensemble correct: 67
- LSTM-assisted successful RF corrections: 49
- Largest Ensemble class-level error source: Class 0 (2,558 errors).

## 5. Evaluation Limitations

- Zero-support independent-test class: [np.int64(8)]
- Low-support classes (support <= 5): [np.int64(8), np.int64(9), np.int64(13)]
- Very low-support class metrics require cautious interpretation.
- Independent-test results were used for final evaluation only.
- No model or ensemble configuration was modified after observing independent-test results.

## 6. Persisted Artifacts

- final_stacking_meta_learner.joblib
- final_ensemble_configuration.json
- final_ensemble_performance.csv
- final_ensemble_classwise_results.csv
- final_ensemble_error_analysis.csv
- final_ensemble_confusion_matrix_rf.csv
- final_ensemble_confusion_matrix_lstm.csv
- final_ensemble_confusion_matrix.csv
