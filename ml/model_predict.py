# ml/model_predict.py
import joblib
import os

# Load model and vectorizer
MODEL_PATH = "models/vuln_model.pkl"
VEC_PATH = "models/vectorizer.pkl"

def load_model():
    if not (os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH)):
        raise FileNotFoundError("Model or vectorizer not found. Train first using model_train.py.")
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VEC_PATH)
    return model, vectorizer


def predict_vulnerability(description):
    model, vectorizer = load_model()
    desc_vector = vectorizer.transform([description])
    prediction = model.predict(desc_vector)[0]
    probabilities = model.predict_proba(desc_vector)[0]
    severity_score = {
        "LOW": probabilities[0],
        "MEDIUM": probabilities[1],
        "HIGH": probabilities[2],
        "CRITICAL": probabilities[3] if len(probabilities) > 3 else 0.0
    }
    return {
        "description": description,
        "predicted_severity": prediction,
        "confidence": round(max(probabilities) * 100, 2)
    }


if __name__ == "__main__":
    sample = "Cross-site scripting vulnerability in Apache HTTP Server allows remote attackers to inject arbitrary web script."
    result = predict_vulnerability(sample)
    print(f"\n🔍 Description: {result['description']}")
    print(f" Predicted Severity: {result['predicted_severity']}")
    print(f" Confidence: {result['confidence']}%\n")
