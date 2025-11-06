# ml/model_train.py
import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

def train_model():
    dataset_path = os.path.join("dataset", "cleaned_vuln_data.csv")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(" Clean dataset not found! Run preprocess.py first.")

    print(" Loading dataset for training...")
    df = pd.read_csv(dataset_path).dropna()

    X = df["description"]
    y = df["severity"]

    print(" Vectorizing text descriptions...")
    vectorizer = TfidfVectorizer(max_features=3000, stop_words="english")
    X_vec = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

    print(" Training Logistic Regression model...")
    model = LogisticRegression(max_iter=300)
    model.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f" Model Accuracy: {acc*100:.2f}%")
    print("\nDetailed Report:\n", classification_report(y_test, y_pred))

    # Save trained model & vectorizer
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/vuln_model.pkl")
    joblib.dump(vectorizer, "models/vectorizer.pkl")

    print("\n Model and vectorizer saved successfully in models/ folder.")

if __name__ == "__main__":
    train_model()
