"""
IDS - Model Training & Evaluation (CICIDS2017 Multi-class)
===========================================================
3 mo hinh: KNN, Random Forest, SVM
7 lop: BENIGN, DoS, DDoS, PortScan, Brute Force, Bot, Web Attack
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.neighbors    import KNeighborsClassifier
from sklearn.ensemble     import RandomForestClassifier
from sklearn.svm          import LinearSVC
from sklearn.calibration  import CalibratedClassifierCV
from sklearn.metrics      import (accuracy_score, precision_score,
                                  recall_score, f1_score,
                                  confusion_matrix, classification_report)

# -- Duong dan --
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
CHART_DIR = os.path.join(BASE_DIR, "static", "charts")
os.makedirs(CHART_DIR, exist_ok=True)

# Load label names
_le = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))
LABEL_NAMES = list(_le.classes_)

COLORS = {
    "KNN"           : "#6C63FF",
    "Random Forest" : "#00C9A7",
    "SVM (Linear)"  : "#FF6584",
}


def load_data():
    print("Loading preprocessed data...")
    X_train = np.load(os.path.join(MODEL_DIR, "X_train.npy"))
    X_test  = np.load(os.path.join(MODEL_DIR, "X_test.npy"))
    y_train = np.load(os.path.join(MODEL_DIR, "y_train.npy"))
    y_test  = np.load(os.path.join(MODEL_DIR, "y_test.npy"))
    print(f"  Train: {X_train.shape} | Test: {X_test.shape}")
    print(f"  Classes: {LABEL_NAMES}")
    return X_train, X_test, y_train, y_test


def evaluate(y_true, y_pred, model_name):
    return {
        "model"    : model_name,
        "accuracy" : round(accuracy_score(y_true, y_pred) * 100, 2),
        "precision": round(precision_score(y_true, y_pred, average='weighted',
                                           zero_division=0) * 100, 2),
        "recall"   : round(recall_score(y_true, y_pred, average='weighted',
                                        zero_division=0) * 100, 2),
        "f1"       : round(f1_score(y_true, y_pred, average='weighted',
                                    zero_division=0) * 100, 2),
    }


def plot_confusion_matrix(y_true, y_pred, model_name, filepath):
    cm = confusion_matrix(y_true, y_pred)
    n_classes = len(LABEL_NAMES)
    fig, ax = plt.subplots(figsize=(max(8, n_classes + 2), max(7, n_classes + 1)))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')

    sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlGn',
                xticklabels=LABEL_NAMES, yticklabels=LABEL_NAMES,
                linewidths=0.5, linecolor='#0f3460',
                ax=ax, cbar_kws={'shrink': 0.8})

    ax.set_xlabel('Predicted', color='white', fontsize=12)
    ax.set_ylabel('Actual', color='white', fontsize=12)
    ax.set_title(f'Confusion Matrix - {model_name}', color='white',
                 fontsize=13, pad=15)
    ax.tick_params(colors='white', labelsize=9)
    plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
    for spine in ax.spines.values():
        spine.set_edgecolor('#0f3460')

    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved: {os.path.basename(filepath)}")


def plot_comparison(results, filepath):
    metrics = ['accuracy', 'precision', 'recall', 'f1']
    x       = np.arange(len(metrics))
    width   = 0.22

    fig, ax = plt.subplots(figsize=(11, 6))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')

    for i, r in enumerate(results):
        vals  = [r[m] for m in metrics]
        color = list(COLORS.values())[i]
        bars  = ax.bar(x + i * width, vals, width, label=r['model'],
                       color=color, alpha=0.85, edgecolor='white', linewidth=0.5)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    f'{val:.1f}%', ha='center', va='bottom',
                    color='white', fontsize=8, fontweight='bold')

    ax.set_xticks(x + width)
    ax.set_xticklabels(['Accuracy', 'Precision', 'Recall', 'F1-Score'],
                        color='white', fontsize=12)
    min_val = min(r[m] for r in results for m in metrics)
    ax.set_ylim(max(0, min_val - 10), 102)
    ax.set_ylabel('Score (%)', color='white', fontsize=12)
    ax.set_title('Model Comparison - CICIDS2017 Multi-class',
                 color='white', fontsize=14, pad=15)
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#444')
    ax.spines['left'].set_color('#444')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.grid(True, color='#333', linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    ax.legend(facecolor='#0f3460', edgecolor='#6C63FF', labelcolor='white',
              fontsize=10, loc='lower right')

    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved: {os.path.basename(filepath)}")


def train_and_evaluate():
    print("=" * 65)
    print("  IDS - Model Training (CICIDS2017 Multi-class)")
    print("=" * 65)

    X_train, X_test, y_train, y_test = load_data()
    all_results    = []
    trained_models = {}

    # -- 1. KNN --
    print("\n[1/3] Training KNN (k=5)...")
    t0  = time.time()
    knn = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
    knn.fit(X_train, y_train)
    elapsed = time.time() - t0
    y_pred  = knn.predict(X_test)
    res     = evaluate(y_test, y_pred, "KNN")
    res["train_time"] = round(elapsed, 2)
    all_results.append(res)
    trained_models["KNN"] = knn
    print(f"  [OK] Done in {elapsed:.1f}s | Accuracy: {res['accuracy']}%")
    plot_confusion_matrix(y_test, y_pred, "KNN",
                          os.path.join(CHART_DIR, "cm_knn.png"))
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES,
                                zero_division=0))

    # -- 2. Random Forest --
    print("[2/3] Training Random Forest (100 trees)...")
    t0  = time.time()
    rf  = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)
    elapsed = time.time() - t0
    y_pred  = rf.predict(X_test)
    res     = evaluate(y_test, y_pred, "Random Forest")
    res["train_time"] = round(elapsed, 2)
    all_results.append(res)
    trained_models["Random Forest"] = rf
    print(f"  [OK] Done in {elapsed:.1f}s | Accuracy: {res['accuracy']}%")
    plot_confusion_matrix(y_test, y_pred, "Random Forest",
                          os.path.join(CHART_DIR, "cm_rf.png"))
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES,
                                zero_division=0))

    # -- 3. SVM --
    print("[3/3] Training SVM (LinearSVC)...")
    t0  = time.time()
    svc = CalibratedClassifierCV(LinearSVC(max_iter=3000, random_state=42), cv=3)
    svc.fit(X_train, y_train)
    elapsed = time.time() - t0
    y_pred  = svc.predict(X_test)
    res     = evaluate(y_test, y_pred, "SVM (Linear)")
    res["train_time"] = round(elapsed, 2)
    all_results.append(res)
    trained_models["SVM (Linear)"] = svc
    print(f"  [OK] Done in {elapsed:.1f}s | Accuracy: {res['accuracy']}%")
    plot_confusion_matrix(y_test, y_pred, "SVM (Linear)",
                          os.path.join(CHART_DIR, "cm_svm.png"))
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES,
                                zero_division=0))

    # -- Save --
    print("\nSaving models...")
    for name, model in trained_models.items():
        fname = name.lower().replace(" ", "_").replace("(", "").replace(")", "") + ".pkl"
        joblib.dump(model, os.path.join(MODEL_DIR, fname))
        print(f"  Saved: {fname}")

    print("\nGenerating comparison chart...")
    plot_comparison(all_results, os.path.join(CHART_DIR, "comparison.png"))

    results_path = os.path.join(MODEL_DIR, "results.json")
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"  Saved: results.json")

    # Summary
    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    print(f"{'Model':<20} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Time':>10}")
    print("-" * 72)
    for r in all_results:
        print(f"{r['model']:<20} {r['accuracy']:>9.2f}% {r['precision']:>9.2f}% "
              f"{r['recall']:>9.2f}% {r['f1']:>9.2f}% {r['train_time']:>9.1f}s")
    best = max(all_results, key=lambda x: x['f1'])
    print(f"\n[BEST] {best['model']} (F1 = {best['f1']}%)")

    return all_results


if __name__ == "__main__":
    if not os.path.exists(os.path.join(MODEL_DIR, "X_train.npy")):
        print("Preprocessed data not found. Running preprocess.py first...")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import preprocess
        preprocess.preprocess()
        print()

    train_and_evaluate()
