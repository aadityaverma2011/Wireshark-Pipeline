from flask import Flask, request, jsonify
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

app = Flask(__name__)

@app.route('/train', methods=['POST'])
def train_model():
    if 'file' not in request.files:
        print("[ERROR] No file part in request")
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if file.filename == '':
        print("[ERROR] No selected file")
        return jsonify({'error': 'No selected file'}), 400

    try:
        print("[INFO] Reading CSV file...")
        df = pd.read_csv(file)
        print("[DEBUG] Columns in uploaded CSV:", list(df.columns)) 
        selected_features = ['Rate', 'Unique Source Ports', 'Entropy Difference', 'Source Port Entropy', 'Total Flows']

        target = 'attack_type'

        print("[INFO] Validating required columns...")
        if not all(col in df.columns for col in selected_features + [target]):
            print("[ERROR] Missing required columns in the CSV file")
            return jsonify({'error': 'Missing required columns in the CSV file'}), 400

        print("[INFO] Preparing training and test datasets...")
        X = df[selected_features]
        y = df[target]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        print("[INFO] Training Random Forest model...")
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)

        print("[INFO] Making predictions...")
        y_pred = rf_model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)

        model_path = os.path.join(os.getcwd(), 'new.pkl')
        joblib.dump(rf_model, model_path)
        print(f"[INFO] Model saved to {model_path}")
        print(f"[INFO] Accuracy: {accuracy:.4f}")
        print("[INFO] Training complete.")

        return jsonify({
            'message': 'Model trained and saved successfully',
            'accuracy': round(accuracy, 4),
            'classification_report': report
        })

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("[INFO] Starting Flask server on port 5000...")
    app.run(debug=True, port=5000)
