import pandas as pd
import random
import os

# Load the CSV
df = pd.read_csv("flow_features.csv")

# Possible labels
labels = ["Normal", "Benign", "Attack"]

# Assign a random label to each row
df["attack_type"] = [random.choice(labels) for _ in range(len(df))]

# Save it
output_path = os.path.join(os.getcwd(), "flow_features_labeled.csv")
df.to_csv(output_path, index=False)

print(f"✔️ Labeled CSV saved at: {output_path}")
