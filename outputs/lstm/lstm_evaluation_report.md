
# Final LSTM Model Evaluation Report

## Model
- Model type: LSTM
- Sequence length: 5
- Input features: 63
- Output classes: 15
- Architecture: LSTM(64) → Dropout → Dense(15)
- Optimizer: Adam
- Learning rate: 3.125000148429535e-05
- Loss function: sparse_categorical_crossentropy
- Trainable parameters: 33,743

## Independent Test Performance
- Test sequences: 113,229
- Test loss: 0.098224
- Test accuracy: 0.967376
- Test accuracy: 96.7376%

## Persistence Validation
The persisted LSTM model was loaded independently without retraining.

- Persisted model loaded successfully.
- Input shape verified: (None, 5, 63)
- Output shape verified: (None, 15)
- Test sequences reconstructed successfully.
- Prediction probabilities generated successfully.
- Predicted classes remained within the valid range 0–14.
- Prediction probability vectors were finite and normalized.
- Load-and-predict accuracy: 96.7376%
- Documented test accuracy: 96.7376%
- Absolute difference: approximately 2.56 × 10^-8

## Error Analysis
- Total test samples analyzed: 113,229
- Total false positives: 3,694
- Total false negatives: 3,694
- Classes analyzed: 15
- Classes with test support: 14
- Classes predicted: 13
- Minority classes (support ≤ 100): 6
- Largest individual confusion: True class 0 → Predicted class 1, with 1,258 samples.
- Highest false-positive count: Class 1, with 1,258 false positives.
- Highest false-negative count: Class 0, with 3,551 false negatives.
- Highest FNR among classes with at least 100 test samples: Class 6, approximately 0.0577.
- Lowest precision among classes with at least 100 test samples: Class 11, approximately 0.4707.

## Final Assessment
The final LSTM model satisfies the modelling and evaluation requirements of the project issue.

The trained model, evaluation evidence, configuration, model summary, and preprocessing dependencies have been preserved for downstream integration.

The model is ready for version-controlled handoff and backend integration. Future inference should use the persisted model together with the established 63-feature representation, feature metadata, StandardScaler, and sequence length of 5.

**Status: LSTM model training, evaluation, persistence, validation, and handoff preparation complete.**
