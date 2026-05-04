"""
IDS - Model Training & Evaluation (CICIDS2017 Multi-class) v2
=============================================================
Models : KNN (k=15, distance), Random Forest (RandomizedSearchCV), SVM (LinearSVC)
Classes: BENIGN, DoS, DDoS, PortScan, Brute Force, Bot, Web Attack
Fixes  :
  - Module-level joblib.load chuyển vào load_data() (tránh crash khi import)
  - Load X_val / y_val (đã tạo ở preprocess nhưng chưa được dùng)
  - KNN: k=15, weights='distance', ball_tree, subsample 200k nếu SMOTE set quá lớn
  - RF : n_estimators=300, class_weight='balanced', RandomizedSearchCV (n_iter=10, cv=3)
  - SVM: C=0.5, max_iter=5000
  - Metrics: thêm F1-Macro (quan trọng với IDS - phát hiện class nhỏ), AUC-ROC (OvR)
  - Val evaluation + overfit gap (Val F1 - Test F1) in ra cho mỗi model
  - classification_report digits=4
  - Best model được đánh dấu trong results.json
"""

# -*- coding: utf-8 -*-
import os
import sys

# FIX: Force stdout utf-8 tren Windows (cp1252 khong encode duoc tieng Viet)
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import json
import time
import joblib
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.neighbors       import KNeighborsClassifier
from sklearn.ensemble        import RandomForestClassifier
from sklearn.svm             import LinearSVC
from sklearn.calibration     import CalibratedClassifierCV
from sklearn.model_selection import RandomizedSearchCV
from sklearn.preprocessing   import label_binarize
from sklearn.metrics         import (accuracy_score, precision_score,
                                     recall_score, f1_score,
                                     confusion_matrix, classification_report,
                                     roc_auc_score)

# -- Đường dẫn --
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
CHART_DIR = os.path.join(BASE_DIR, "static", "charts")
os.makedirs(CHART_DIR, exist_ok=True)

# FIX: KHÔNG load ở module level — sẽ gây crash nếu chưa preprocess
LABEL_NAMES  = None
RANDOM_STATE = 42

COLORS = {
    "KNN"          : "#6C63FF",
    "Random Forest": "#00C9A7",
    "SVM (Linear)" : "#FF6584",
}


# ===========================================================================
def load_data():
    """Load preprocessed train / val / test data và label names."""
    global LABEL_NAMES

    # FIX: Load label_encoder TRONG HÀM thay vì module level
    le_path = os.path.join(MODEL_DIR, "label_encoder.pkl")
    if not os.path.exists(le_path):
        raise FileNotFoundError(
            "label_encoder.pkl not found — hãy chạy preprocess.py trước!"
        )
    le = joblib.load(le_path)
    LABEL_NAMES = list(le.classes_)

    print("Loading preprocessed data...")
    X_train = np.load(os.path.join(MODEL_DIR, "X_train.npy"))
    X_val   = np.load(os.path.join(MODEL_DIR, "X_val.npy"))   # FIX: load val
    X_test  = np.load(os.path.join(MODEL_DIR, "X_test.npy"))
    y_train = np.load(os.path.join(MODEL_DIR, "y_train.npy"))
    y_val   = np.load(os.path.join(MODEL_DIR, "y_val.npy"))   # FIX: load val
    y_test  = np.load(os.path.join(MODEL_DIR, "y_test.npy"))

    print(f"  Train : {X_train.shape} | Val: {X_val.shape} | Test: {X_test.shape}")
    print(f"  Classes ({len(LABEL_NAMES)}): {LABEL_NAMES}")
    return X_train, X_val, X_test, y_train, y_val, y_test


# ===========================================================================
def evaluate(y_true, y_pred, model_name, y_prob=None):
    """
    Tính đầy đủ metrics:
      - Accuracy, Precision/Recall/F1 weighted
      - F1 Macro  (QUAN TRỌNG cho IDS — phát hiện class nhỏ bị bỏ qua)
      - AUC-ROC OvR (nếu có y_prob)
    """
    n_classes = len(LABEL_NAMES) if LABEL_NAMES else None
    result = {
        "model"       : model_name,
        "accuracy"    : round(accuracy_score(y_true, y_pred) * 100, 2),
        "precision_w" : round(precision_score(y_true, y_pred, average='weighted',
                                              zero_division=0) * 100, 2),
        "recall_w"    : round(recall_score(y_true, y_pred, average='weighted',
                                           zero_division=0) * 100, 2),
        "f1_weighted" : round(f1_score(y_true, y_pred, average='weighted',
                                       zero_division=0) * 100, 2),
        # THÊM: Macro F1
        "f1_macro"    : round(f1_score(y_true, y_pred, average='macro',
                                       zero_division=0) * 100, 2),
    }
    # THÊM: AUC-ROC (One-vs-Rest, weighted)
    if y_prob is not None and n_classes is not None:
        try:
            y_bin = label_binarize(y_true, classes=list(range(n_classes)))
            auc   = roc_auc_score(y_bin, y_prob, average='weighted',
                                  multi_class='ovr')
            result["auc_roc"] = round(auc * 100, 2)
        except Exception:
            result["auc_roc"] = None
    return result


def _print_split_metrics(split_name, metrics):
    auc_str = f"  AUC={metrics['auc_roc']}%" if metrics.get("auc_roc") else ""
    print(f"  [{split_name:4s}] Acc={metrics['accuracy']}%  "
          f"F1-W={metrics['f1_weighted']}%  "
          f"F1-Macro={metrics['f1_macro']}%{auc_str}")


def evaluate_split(model, X, y, split_name, model_name):
    """Evaluate model trên 1 split, trả về (metrics_dict, y_pred)."""
    y_pred = model.predict(X)
    y_prob = model.predict_proba(X) if hasattr(model, "predict_proba") else None
    metrics = evaluate(y, y_pred, model_name, y_prob=y_prob)
    _print_split_metrics(split_name, metrics)
    return metrics, y_pred


# ===========================================================================
def plot_confusion_matrix(y_true, y_pred, model_name, filepath):
    cm = confusion_matrix(y_true, y_pred)
    n  = len(LABEL_NAMES)
    fig, ax = plt.subplots(figsize=(max(8, n + 2), max(7, n + 1)))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')

    sns.heatmap(cm, annot=True, fmt='d', cmap='RdYlGn',
                xticklabels=LABEL_NAMES, yticklabels=LABEL_NAMES,
                linewidths=0.5, linecolor='#0f3460',
                ax=ax, cbar_kws={'shrink': 0.8})

    ax.set_xlabel('Predicted', color='white', fontsize=12)
    ax.set_ylabel('Actual',    color='white', fontsize=12)
    ax.set_title(f'Confusion Matrix — {model_name}', color='white',
                 fontsize=13, pad=15)
    ax.tick_params(colors='white', labelsize=9)
    plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
    for sp in ax.spines.values():
        sp.set_edgecolor('#0f3460')

    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved: {os.path.basename(filepath)}")


def plot_comparison(results, filepath):
    metrics_keys   = ['accuracy', 'f1_weighted', 'f1_macro']
    metrics_labels = ['Accuracy', 'F1 Weighted', 'F1 Macro']
    x     = np.arange(len(metrics_keys))
    width = 0.22

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')

    for i, r in enumerate(results):
        vals  = [r.get(m, 0) for m in metrics_keys]
        color = list(COLORS.values())[i % len(COLORS)]
        bars  = ax.bar(x + i * width, vals, width, label=r['model'],
                       color=color, alpha=0.85, edgecolor='white', linewidth=0.5)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.3,
                    f'{val:.1f}%', ha='center', va='bottom',
                    color='white', fontsize=8, fontweight='bold')

    all_vals = [r.get(m, 0) for r in results for m in metrics_keys]
    ax.set_xticks(x + width)
    ax.set_xticklabels(metrics_labels, color='white', fontsize=12)
    ax.set_ylim(max(0, min(all_vals) - 10), 102)
    ax.set_ylabel('Score (%)', color='white', fontsize=12)
    ax.set_title('Model Comparison — CICIDS2017 Multi-class',
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


# ===========================================================================
def train_and_evaluate():
    print("=" * 70)
    print("  IDS — Model Training v2 (CICIDS2017 Multi-class)")
    print("=" * 70)

    X_train, X_val, X_test, y_train, y_val, y_test = load_data()
    all_results    = []
    trained_models = {}

    # -----------------------------------------------------------------------
    # 1. KNN
    # FIX: k=15, weights='distance', ball_tree, subsample nếu SMOTE set lớn
    # -----------------------------------------------------------------------
    print("\n[1/3] Training KNN (k=15, distance-weighted, ball_tree)...")
    t0 = time.time()

    MAX_KNN = 200_000
    MAX_RF  = 500_000   # subsample cho RF (tránh OOM với 8.7M SMOTE rows)
    MAX_SVM = 300_000   # subsample cho SVM
    if len(X_train) > MAX_KNN:
        print(f"  KNN: subsampling {MAX_KNN:,} / {len(X_train):,} "
              f"(SMOTE set too large for KNN)")
        rng_knn  = np.random.default_rng(RANDOM_STATE)
        knn_idx  = rng_knn.choice(len(X_train), MAX_KNN, replace=False)
        X_knn, y_knn = X_train[knn_idx], y_train[knn_idx]
    else:
        X_knn, y_knn = X_train, y_train

    knn = KNeighborsClassifier(
        n_neighbors=15,          # FIX: 15 thay vì 5 — ổn định hơn trên dataset lớn
        weights='distance',      # FIX: giảm noise từ neighbors xa
        algorithm='ball_tree',   # FIX: nhanh hơn brute force
        n_jobs=-1
    )
    knn.fit(X_knn, y_knn)
    elapsed = time.time() - t0
    trained_models["KNN"] = knn
    print(f"  [OK] Trained in {elapsed:.1f}s")

    val_res,  _       = evaluate_split(knn, X_val,  y_val,  "VAL",  "KNN")
    test_res, y_pred  = evaluate_split(knn, X_test, y_test, "TEST", "KNN")
    gap = val_res['f1_macro'] - test_res['f1_macro']
    print(f"  Overfit gap (Val-Test F1-Macro): {gap:+.2f}%")
    test_res["train_time"]    = round(elapsed, 2)
    test_res["val_f1_macro"]  = val_res["f1_macro"]
    all_results.append(test_res)

    plot_confusion_matrix(y_test, y_pred, "KNN",
                          os.path.join(CHART_DIR, "cm_knn.png"))
    # FIX: digits=4 để thấy rõ class nhỏ
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES,
                                zero_division=0, digits=4))

    # -----------------------------------------------------------------------
    # 2. Random Forest
    # FIX: subsample 500k để tránh OOM khi CV fork subprocess với 8.7M rows
    # -----------------------------------------------------------------------
    print("[2/3] Training Random Forest (RandomizedSearchCV)...")
    t0 = time.time()

    if len(X_train) > MAX_RF:
        print(f"  RF: subsampling {MAX_RF:,} / {len(X_train):,} (avoid OOM in CV)")
        rng_rf  = np.random.default_rng(RANDOM_STATE)
        rf_idx  = rng_rf.choice(len(X_train), MAX_RF, replace=False)
        X_rf, y_rf = X_train[rf_idx], y_train[rf_idx]
    else:
        X_rf, y_rf = X_train, y_train

    param_dist = {
        "n_estimators"     : [200, 300, 500],
        "max_depth"        : [None, 20, 30],
        "min_samples_split": [2, 5],
        "max_features"     : ["sqrt", "log2"],
    }
    rf_base   = RandomForestClassifier(
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight='balanced'
    )
    rf_search = RandomizedSearchCV(
        rf_base,
        param_distributions=param_dist,
        n_iter=10,
        cv=3,
        scoring='f1_weighted',
        n_jobs=1,          # FIX: n_jobs=1 in CV to avoid subprocess OOM
        random_state=RANDOM_STATE,
        verbose=1
    )
    rf_search.fit(X_rf, y_rf)
    rf = rf_search.best_estimator_
    elapsed = time.time() - t0
    print(f"  Best params: {rf_search.best_params_}")
    trained_models["Random Forest"] = rf
    print(f"  [OK] Trained in {elapsed:.1f}s")

    val_res,  _       = evaluate_split(rf, X_val,  y_val,  "VAL",  "Random Forest")
    test_res, y_pred  = evaluate_split(rf, X_test, y_test, "TEST", "Random Forest")
    gap = val_res['f1_macro'] - test_res['f1_macro']
    print(f"  Overfit gap (Val-Test F1-Macro): {gap:+.2f}%")
    test_res["train_time"]    = round(elapsed, 2)
    test_res["val_f1_macro"]  = val_res["f1_macro"]
    test_res["best_params"]   = str(rf_search.best_params_)
    all_results.append(test_res)

    plot_confusion_matrix(y_test, y_pred, "Random Forest",
                          os.path.join(CHART_DIR, "cm_rf.png"))
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES,
                                zero_division=0, digits=4))

    # -----------------------------------------------------------------------
    # 3. SVM (LinearSVC)
    # FIX: subsample 300k để tránh OOM; CalibratedClassifierCV → predict_proba OK
    # -----------------------------------------------------------------------
    print("[3/3] Training SVM (LinearSVC, C=0.5, max_iter=5000)...")
    t0  = time.time()

    if len(X_train) > MAX_SVM:
        print(f"  SVM: subsampling {MAX_SVM:,} / {len(X_train):,} (avoid OOM)")
        rng_svm  = np.random.default_rng(RANDOM_STATE + 1)
        svm_idx  = rng_svm.choice(len(X_train), MAX_SVM, replace=False)
        X_svm, y_svm = X_train[svm_idx], y_train[svm_idx]
    else:
        X_svm, y_svm = X_train, y_train

    svc = CalibratedClassifierCV(
        LinearSVC(C=0.5, max_iter=5000, random_state=RANDOM_STATE),
        cv=3
    )
    svc.fit(X_svm, y_svm)
    elapsed = time.time() - t0
    trained_models["SVM (Linear)"] = svc
    print(f"  [OK] Trained in {elapsed:.1f}s")

    val_res,  _       = evaluate_split(svc, X_val,  y_val,  "VAL",  "SVM (Linear)")
    test_res, y_pred  = evaluate_split(svc, X_test, y_test, "TEST", "SVM (Linear)")
    gap = val_res['f1_macro'] - test_res['f1_macro']
    print(f"  Overfit gap (Val-Test F1-Macro): {gap:+.2f}%")
    test_res["train_time"]   = round(elapsed, 2)
    test_res["val_f1_macro"] = val_res["f1_macro"]
    all_results.append(test_res)

    plot_confusion_matrix(y_test, y_pred, "SVM (Linear)",
                          os.path.join(CHART_DIR, "cm_svm.png"))
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES,
                                zero_division=0, digits=4))

    # -----------------------------------------------------------------------
    # Save models
    # -----------------------------------------------------------------------
    print("\nSaving models...")
    for name, model in trained_models.items():
        fname = (name.lower()
                 .replace(" ", "_")
                 .replace("(", "")
                 .replace(")", "") + ".pkl")
        joblib.dump(model, os.path.join(MODEL_DIR, fname))
        print(f"  Saved: {fname}")

    print("\nGenerating comparison chart...")
    plot_comparison(all_results, os.path.join(CHART_DIR, "comparison.png"))

    # FIX: Đánh dấu best model theo F1-Macro (phù hợp IDS hơn F1-weighted)
    best = max(all_results, key=lambda x: x['f1_macro'])
    for r in all_results:
        r['is_best'] = (r['model'] == best['model'])

    results_path = os.path.join(MODEL_DIR, "results.json")
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"  Saved: results.json (best model marked)")

    # Summary
    print("\n" + "=" * 84)
    print("  SUMMARY")
    print("=" * 84)
    print(f"{'Model':<20} {'Accuracy':>10} {'F1-W':>8} {'F1-Macro':>10}"
          f" {'AUC-ROC':>8} {'Val-F1M':>9} {'Time':>7}")
    print("-" * 84)
    for r in all_results:
        star = " ⭐" if r.get('is_best') else ""
        auc  = f"{r['auc_roc']:>7.2f}%" if r.get('auc_roc') else "    N/A "
        print(f"{r['model']:<20} {r['accuracy']:>9.2f}% {r['f1_weighted']:>7.2f}%"
              f" {r['f1_macro']:>9.2f}% {auc} {r.get('val_f1_macro', 0):>8.2f}%"
              f" {r['train_time']:>6.1f}s{star}")
    print(f"\n[BEST] {best['model']} — F1-Macro = {best['f1_macro']}%")

    return all_results


# ===========================================================================
if __name__ == "__main__":
    if not os.path.exists(os.path.join(MODEL_DIR, "X_train.npy")):
        print("Preprocessed data not found -> running preprocess.py first...")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import preprocess
        preprocess.preprocess()
        print()

    train_and_evaluate()
