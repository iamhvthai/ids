"""
IDS - CICIDS2017 Multi-class Preprocessing Pipeline (v8 - CRITICAL FIXES)
=========================================================
COMPLETE PIPELINE WITH ALL CRITICAL FIXES:
  1. Load & concat CSV (float32 optimization)
  2. EDA - Data overview
  3. Handle Inf/NaN (fillna median)
  4. Drop duplicates
  5. Remove identifiers
  6. Encode Destination Port (binning + raw + 8 specific ports + port_mod_1000)
  7. Feature Interactions (flow_pkt_ratio, flow_byte_ratio)
  8. Map labels → 7 classes
  9. Remove tiny classes
  10. Encode labels
  11. Train/Val/Test split (70/15/15, stratified)
  12. Variance Threshold (keep binary, remove low-var continuous)
  13. RF Importance (for correlation smart drop)
  14. Correlation filter (smart drop by importance with tolerance, stratified sample)
  15. Feature Selection (RF + MI, balanced, normalized, MI scaled with MinMaxScaler)
  16. Leakage Detection (check for label correlation > 0.9 and MI > 0.5)
  17. Power Transform (continuous only, Yeo-Johnson, BEFORE SMOTE)
  18. StandardScaler (BEFORE SMOTE for proper distance)
  19. SMOTE (sampling_strategy='not majority', TRAIN only)
  20. Shuffle (after SMOTE to prevent order bias)
  21. Outlier Clipping (clip to [-5, 5] for stability)
  22. Retrain RF + Permutation Importance (VAL - CRITICAL FIX, n_repeats=10)
  23. Final data preparation (no double scaling)
  24. Sanity checks
  25. Save all artifacts
  26. Post-preprocessing EDA
"""

import os
import glob
import json
import time
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder, PowerTransformer, MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.feature_selection import mutual_info_classif, VarianceThreshold
from imblearn.over_sampling import SMOTE
from datetime import datetime


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder để handle numpy int64/float64."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

# Random seed for reproducibility
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)
rng = np.random.default_rng(RANDOM_STATE)

# -- Paths --
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR  = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
CHART_DIR = os.path.join(BASE_DIR, "static", "charts")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

# -- Config --
ID_COLUMNS = ['Flow ID', 'Source IP', 'Destination IP', 'Src IP', 'Dst IP', 'Timestamp']
CORR_THRESHOLD = 0.95
CORR_IMP_TOLERANCE = 1e-4  # Tolerance for importance comparison (fix bias)
TOP_N_FEATURES = 40  # Will be dynamic if FEATURE_IMP_THRESHOLD is set
FEATURE_IMP_THRESHOLD = None  # If None, use TOP_N_FEATURES; if set, use dynamic
MIN_CLASS_SIZE = 30
SMOTE_K_NEIGHBORS = 5
SMOTE_SAMPLING_STRATEGY = 'not majority'  # Better for multi-class (fix)
CORR_SAMPLE_SIZE = 10000
USE_SCALER = True  # False for RF/XGBoost, True for SVM/KNN
USE_FLOAT32 = True
TRAIN_VAL_TEST_SPLIT = (0.7, 0.15, 0.15)
PERM_IMP_REPEATS = 10  # Reduced from 20 (cost optimization)
LOG_FILE = os.path.join(MODEL_DIR, "preprocessing_log.json")
FEATURE_IMPORTANCE_FILE = os.path.join(MODEL_DIR, "feature_importance.json")

# Label mapping
LABEL_MAP = {
    'BENIGN': 'BENIGN',
    'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS', 'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS',
    'DDoS': 'DDoS',
    'PortScan': 'PortScan',
    'FTP-Patator': 'Brute Force', 'SSH-Patator': 'Brute Force',
    'Web Attack \x96 Brute Force': 'Web Attack', 'Web Attack \x96 XSS': 'Web Attack', 'Web Attack \x96 Sql Injection': 'Web Attack',
    'Web Attack \u2013 Brute Force': 'Web Attack', 'Web Attack \u2013 XSS': 'Web Attack', 'Web Attack \u2013 Sql Injection': 'Web Attack',
    'Web Attack - Brute Force': 'Web Attack', 'Web Attack - XSS': 'Web Attack', 'Web Attack - Sql Injection': 'Web Attack',
    'Bot': 'Bot',
}


def preprocess():
    print("=" * 90)
    print("  IDS - CICIDS2017 Multi-class Preprocessing (v6 - LOGIC FIXES + ENHANCEMENTS)")
    print("=" * 90)
    
    start_time = time.time()
    log_data = {
        "version": "v8",
        "timestamp": datetime.now().isoformat(),
        "config": {
            "CORR_THRESHOLD": CORR_THRESHOLD,
            "TOP_N_FEATURES": TOP_N_FEATURES,
            "SMOTE_SAMPLING_STRATEGY": SMOTE_SAMPLING_STRATEGY,
            "USE_SCALER": USE_SCALER,
            "RANDOM_STATE": RANDOM_STATE,
        },
        "rows_dropped": {},
        "features_removed": {},
        "class_distribution": {},
        "step_times": {},
        "pipeline_steps": []
    }

    # == 1. Load & concat CSV ==
    step_start = time.time()
    print("\n[1/17] Loading all CSV files...")
    csv_files = sorted(glob.glob(os.path.join(DATA_DIR, "**", "*.csv"), recursive=True))
    if not csv_files:  # fallback: thư mục gốc data/
        csv_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))
    dfs = []
    for f in csv_files:
        name = os.path.basename(f)
        df_tmp = pd.read_csv(f, encoding='utf-8', low_memory=False)
        df_tmp.columns = df_tmp.columns.str.strip()
        if USE_FLOAT32:
            numeric_cols = df_tmp.select_dtypes(include=[np.number]).columns
            df_tmp[numeric_cols] = df_tmp[numeric_cols].astype(np.float32)
        print(f"       {name[:50]:<50} rows={len(df_tmp):>9,}")
        dfs.append(df_tmp)
    df = pd.concat(dfs, ignore_index=True)
    del dfs
    initial_rows = len(df)
    print(f"       TOTAL: {len(df):,} rows | {df.shape[1]} columns")
    log_data["step_times"]["load"] = time.time() - step_start

    # == 2. EDA ==
    step_start = time.time()
    print("\n[2/17] EDA - Data Overview...")
    print(f"       Shape: {df.shape} | Memory: {df.memory_usage(deep=True).sum() / 1024**2:.1f} MB")
    print(f"       Missing: {df.isnull().sum().sum():,} | Duplicates: {df.duplicated().sum():,}")
    _plot_data_info(df, os.path.join(CHART_DIR, "01_data_overview.txt"))
    log_data["step_times"]["eda"] = time.time() - step_start

    # == 3. Handle Inf/NaN ==
    step_start = time.time()
    print("\n[3/17] Handling Inf/NaN (fillna median)...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    medians = df[numeric_cols].median()
    for col in numeric_cols:
        if df[col].isnull().sum() > 0:
            df[col] = df[col].fillna(medians[col])  # FIX: Copy-on-Write (pandas 2+)
    # Safety net: fill bất kỳ NaN còn lại bằng 0
    remaining_nan = df.isnull().sum().sum()
    if remaining_nan > 0:
        df.fillna(0, inplace=True)
    print(f"       Remaining NaN: {df.isnull().sum().sum()}")
    log_data["step_times"]["handle_nan"] = time.time() - step_start

    # == 4. Drop duplicates ==
    step_start = time.time()
    print("\n[4/17] Dropping exact duplicates...")
    before = len(df)
    df.drop_duplicates(inplace=True)
    dropped = before - len(df)
    log_data["rows_dropped"]["duplicates"] = dropped
    print(f"       Removed {dropped:,} -> {len(df):,} remain")
    log_data["step_times"]["dedup"] = time.time() - step_start

    # == 5. Remove identifiers ==
    step_start = time.time()
    print("\n[5/17] Removing identifier columns...")
    found_id = [c for c in ID_COLUMNS if c in df.columns]
    if found_id:
        df.drop(columns=found_id, inplace=True)
        print(f"       Dropped: {found_id}")
    print(f"       Columns: {df.shape[1]}")
    log_data["step_times"]["remove_id"] = time.time() - step_start

    # == 6. Encode Destination Port ==
    step_start = time.time()
    print("\n[6/17] Encoding Destination Port (binning + raw + features + mod)...")
    if 'Destination Port' in df.columns:
        df['Destination Port_Raw'] = df['Destination Port'].copy()
        df['Destination Port'] = pd.cut(df['Destination Port'],
                                        bins=[0, 1024, 49151, 65535],
                                        labels=[0, 1, 2],
                                        include_lowest=True).astype(np.int8)
        # Feature engineering - specific ports
        df['is_http'] = (df['Destination Port_Raw'] == 80).astype(np.int8)
        df['is_https'] = (df['Destination Port_Raw'] == 443).astype(np.int8)
        df['is_ftp'] = (df['Destination Port_Raw'] == 21).astype(np.int8)
        df['is_ssh'] = (df['Destination Port_Raw'] == 22).astype(np.int8)
        df['is_dns'] = (df['Destination Port_Raw'] == 53).astype(np.int8)
        df['is_smtp'] = (df['Destination Port_Raw'] == 25).astype(np.int8)
        df['is_telnet'] = (df['Destination Port_Raw'] == 23).astype(np.int8)
        df['is_rdp'] = (df['Destination Port_Raw'] == 3389).astype(np.int8)
        # Port modulo for PortScan detection (random ports)
        df['port_mod_1000'] = (df['Destination Port_Raw'] % 1000).astype(np.int16)
        print(f"       Port binned + raw + 8 specific ports + port_mod_1000 added")
    print(f"       Columns: {df.shape[1]}")
    log_data["step_times"]["port_encoding"] = time.time() - step_start

    # == 6.5 Feature Interactions (lightweight, high-value) ==
    step_start = time.time()
    print("\n[6.5/17] Adding feature interactions (flow ratios)...")
    interaction_features = []
    # Flow packet ratio (helps detect DoS/DDoS)
    if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
        df['flow_pkt_ratio'] = (df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)).astype(np.float32)
        interaction_features.append('flow_pkt_ratio')
    # Flow byte ratio (helps detect data exfiltration)
    if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
        df['flow_byte_ratio'] = (df['Total Length of Fwd Packets'] / (df['Total Length of Bwd Packets'] + 1)).astype(np.float32)
        interaction_features.append('flow_byte_ratio')
    if interaction_features:
        print(f"       Added {len(interaction_features)} interaction features: {interaction_features}")
    log_data["step_times"]["feature_interactions"] = time.time() - step_start

    # == 7. Map labels ==
    step_start = time.time()
    print("\n[7/17] Mapping 15 labels -> 7 classes...")
    df['Label'] = df['Label'].str.strip()
    df['Label'] = df['Label'].map(LABEL_MAP)
    unknown = df['Label'].isna().sum()
    if unknown > 0:
        df.dropna(subset=['Label'], inplace=True)
        log_data["rows_dropped"]["unmapped_labels"] = unknown
    print(f"       Class distribution:")
    for lbl, cnt in df['Label'].value_counts().items():
        pct = cnt / len(df) * 100
        print(f"         {lbl:<20}: {cnt:>9,} ({pct:>5.1f}%)")
    log_data["step_times"]["label_map"] = time.time() - step_start

    # == 8. Remove tiny classes ==
    step_start = time.time()
    print(f"\n[8/17] Removing tiny classes (< {MIN_CLASS_SIZE})...")
    class_counts = df['Label'].value_counts()
    small_classes = class_counts[class_counts < MIN_CLASS_SIZE].index.tolist()
    if small_classes:
        df = df[~df['Label'].isin(small_classes)]
        print(f"       Removed: {small_classes}")
    print(f"       Total: {len(df):,}")
    log_data["step_times"]["remove_tiny"] = time.time() - step_start

    # == 9. Encode labels ==
    step_start = time.time()
    print("\n[9/17] Encoding labels...")
    le = LabelEncoder()
    df['Label'] = le.fit_transform(df['Label'])
    print(f"       Classes: {list(le.classes_)}")
    log_data["step_times"]["encode_labels"] = time.time() - step_start

    # == 10. Train/Val/Test split ==
    step_start = time.time()
    print("\n[10/17] Train/Val/Test split (70/15/15, stratified)...")
    feature_cols = [c for c in df.columns if c != 'Label']
    X = df[feature_cols].values
    y = df['Label'].values
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=RANDOM_STATE, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=RANDOM_STATE, stratify=y_temp
    )
    print(f"       Train: {X_train.shape[0]:,} | Val: {X_val.shape[0]:,} | Test: {X_test.shape[0]:,}")
    log_data["rows_dropped"]["train_val_test"] = {
        "train": int(X_train.shape[0]), "val": int(X_val.shape[0]), "test": int(X_test.shape[0])
    }
    log_data["step_times"]["split"] = time.time() - step_start

    # == 11. Variance Threshold (keep binary features) ==
    step_start = time.time()
    print(f"\n[11/17] Variance Threshold (remove near-zero variance, keep binary)...")
    # Identify binary features (port features, is_http, etc.)
    binary_features = set()
    for i, col in enumerate(feature_cols):
        if col.startswith('is_') or col == 'Destination Port':
            binary_features.add(i)
    
    # Apply variance threshold only to continuous features
    continuous_idx = [i for i in range(len(feature_cols)) if i not in binary_features]
    vt = None
    all_kept_idx = None
    if continuous_idx:
        X_continuous = X_train[:, continuous_idx]
        vt = VarianceThreshold(threshold=0.01)
        X_continuous_filtered = vt.fit_transform(X_continuous)
        kept_continuous_idx = [continuous_idx[i] for i in vt.get_support(indices=True)]
        removed_low_var = [feature_cols[i] for i in continuous_idx if i not in kept_continuous_idx]
        
        # Reconstruct X with binary + filtered continuous
        all_kept_idx = sorted(list(binary_features) + kept_continuous_idx)
        X_train = X_train[:, all_kept_idx]
        X_val = X_val[:, all_kept_idx]
        X_test = X_test[:, all_kept_idx]
        feature_cols = [feature_cols[i] for i in all_kept_idx]
        
        if removed_low_var:
            log_data["features_removed"]["low_variance"] = removed_low_var
            print(f"       Removed {len(removed_low_var)} low-variance continuous features")
            print(f"       Kept all {len(binary_features)} binary features")
    else:
        all_kept_idx = list(range(len(feature_cols)))
    print(f"       Features: {len(feature_cols)}")
    log_data["step_times"]["variance_threshold"] = time.time() - step_start

    # == 12. RF Importance (for correlation smart drop) ==
    step_start = time.time()
    print(f"\n[12/17] Computing RF importance (for correlation smart drop)...")
    rf_temp = RandomForestClassifier(n_estimators=50, max_depth=10, n_jobs=-1, 
                                     random_state=RANDOM_STATE, class_weight='balanced')
    rf_temp.fit(X_train, y_train)
    temp_rf_imp = rf_temp.feature_importances_
    print(f"       RF importance computed")
    log_data["step_times"]["rf_temp"] = time.time() - step_start

    # == 13. Correlation filter (TRAIN only, smart drop based on importance) ==
    step_start = time.time()
    print(f"\n[13/17] Correlation filter (threshold={CORR_THRESHOLD}, smart drop by importance)...")
    train_sample_size = min(CORR_SAMPLE_SIZE, len(X_train))
    # Stratified sample to preserve class distribution
    train_indices = []
    for class_label in np.unique(y_train):
        class_idx = np.where(y_train == class_label)[0]
        class_sample_size = int(train_sample_size * len(class_idx) / len(y_train))
        train_indices.extend(rng.choice(class_idx, size=min(class_sample_size, len(class_idx)), replace=False))
    train_indices = np.array(train_indices)
    
    df_train_sample = pd.DataFrame(X_train[train_indices], columns=feature_cols)
    corr_abs = df_train_sample.corr().abs()
    upper = corr_abs.where(np.triu(np.ones(corr_abs.shape), k=1).astype(bool))
    
    # Smart drop: drop feature with LOWER importance (with tolerance)
    drop_corr = set()
    for i in range(len(feature_cols)):
        for j in range(i+1, len(feature_cols)):
            if upper.iloc[i, j] > CORR_THRESHOLD:
                # Add tolerance: if importance similar, drop higher index (fallback)
                imp_diff = abs(temp_rf_imp[i] - temp_rf_imp[j])
                if imp_diff < CORR_IMP_TOLERANCE:
                    # Importance too similar, drop higher index (fallback)
                    drop_corr.add(j)
                else:
                    # Drop feature with lower importance
                    drop_corr.add(i if temp_rf_imp[i] < temp_rf_imp[j] else j)
    
    if drop_corr:
        keep_cols = [feature_cols[i] for i in range(len(feature_cols)) if i not in drop_corr]
        col_idx = [i for i in range(len(feature_cols)) if i not in drop_corr]
        X_train = X_train[:, col_idx]
        X_val = X_val[:, col_idx]
        X_test = X_test[:, col_idx]
        removed_corr = [feature_cols[i] for i in drop_corr]
        log_data["features_removed"]["correlation"] = removed_corr
        feature_cols = keep_cols
        print(f"       Dropped {len(drop_corr)} correlated features (kept higher importance)")
    print(f"       Features: {len(feature_cols)}")
    _plot_correlation(corr_abs, os.path.join(CHART_DIR, "02_correlation_matrix.png"))
    log_data["step_times"]["correlation"] = time.time() - step_start

    # == 14. Feature Selection: RF + MI (TRAIN only, balanced, normalized) ==
    step_start = time.time()
    print(f"\n[14/17] Feature Selection (RF + MI, balanced, normalized, TRAIN only)...")
    rf_sel = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, 
                                    random_state=RANDOM_STATE, class_weight='balanced')
    rf_sel.fit(X_train, y_train)
    rf_imp = rf_sel.feature_importances_
    
    # Scale X_train for MI using MinMaxScaler (better for MI than StandardScaler)
    scaler_mi = MinMaxScaler()
    X_train_scaled_mi = scaler_mi.fit_transform(X_train)
    print("Start MI...")
    mi_imp = mutual_info_classif(X_train_scaled_mi, y_train, random_state=RANDOM_STATE)
    print("Done MI")
    # Normalize both to [0, 1]
    rf_imp_norm = rf_imp / (rf_imp.sum() + 1e-10)
    mi_imp_norm = mi_imp / (mi_imp.sum() + 1e-10)
    combined_imp = 0.5 * rf_imp_norm + 0.5 * mi_imp_norm
    
    # == LEAKAGE DETECTION (ALL features, TRƯỚC feature selection) ==
    # FIX: check toàn bộ features trước khi lọc, không chỉ top N
    print(f"\n       [LEAKAGE CHECK] Scanning ALL {len(feature_cols)} features for label leakage...")
    leakage_idx = set()
    leakage_features = []
    suspicious_features = []

    for idx in range(len(feature_cols)):
        feat_name = feature_cols[idx]
        corr = np.abs(np.corrcoef(X_train[:, idx], y_train)[0, 1])
        mi_score = mi_imp[idx]

        # Name-based leakage check (highest priority)
        if any(keyword in feat_name.lower() for keyword in ['label', 'attack', 'class', 'target']):
            leakage_idx.add(idx)
            leakage_features.append((feat_name, float(corr), float(mi_score)))
            print(f"         🔴 NAME-BASED LEAKAGE: {feat_name}")
        # Critical: high Pearson correlation with label
        elif corr > 0.9:
            leakage_idx.add(idx)
            leakage_features.append((feat_name, float(corr), float(mi_score)))
            print(f"         🔴 CRITICAL LEAKAGE: {feat_name} (corr={corr:.4f}, MI={mi_score:.4f})")
        # Warning: high MI (potential indirect leakage)
        elif mi_score > 0.5:
            suspicious_features.append((feat_name, float(corr), float(mi_score)))
            print(f"         ⚠️  SUSPICIOUS: {feat_name} (corr={corr:.4f}, MI={mi_score:.4f})")

    if not leakage_features and not suspicious_features:
        print(f"         ✓ No obvious leakage detected")

    # Loại leaky features khỏi selection pool bằng cách push xuống đáy ranking
    combined_imp_clean = combined_imp.copy()
    if leakage_idx:
        for idx in leakage_idx:
            combined_imp_clean[idx] = -1.0
        print(f"         → Excluded {len(leakage_idx)} leaky features from selection pool")

    log_data["leakage_check"] = {
        "critical_leakage": leakage_features,
        "suspicious_features": suspicious_features,
        "total_critical": len(leakage_features),
        "total_suspicious": len(suspicious_features)
    }

    # Dynamic feature selection trên CLEANED pool (leaky features đã bị loại)
    if FEATURE_IMP_THRESHOLD is not None:
        sorted_idx = np.where(combined_imp_clean > FEATURE_IMP_THRESHOLD)[0]
        sorted_idx = sorted_idx[np.argsort(combined_imp_clean[sorted_idx])[::-1]]
        print(f"       Dynamic feature selection (threshold={FEATURE_IMP_THRESHOLD}): {len(sorted_idx)} features")
    else:
        sorted_idx = np.argsort(combined_imp_clean)[::-1][:TOP_N_FEATURES]
        print(f"       Fixed feature selection (TOP_N={TOP_N_FEATURES}): {len(sorted_idx)} features")

    top_features = [feature_cols[i] for i in sorted_idx]
    top_rf_imp = rf_imp[sorted_idx]
    top_mi_imp = mi_imp[sorted_idx]
    top_combined_imp = combined_imp_clean[sorted_idx]

    print(f"       Top features (RF + MI combined, normalized):")
    for rank, (f, rf, mi, comb) in enumerate(zip(top_features[:10], top_rf_imp[:10], top_mi_imp[:10], top_combined_imp[:10]), 1):
        print(f"         {rank:2d}. {f:<45} RF={rf:.4f} MI={mi:.4f} Comb={comb:.4f}")

    X_train = X_train[:, sorted_idx]
    X_val = X_val[:, sorted_idx]
    X_test = X_test[:, sorted_idx]
    feature_cols = top_features
    
    # Save feature importance
    feature_imp_data = {
        "features": top_features,
        "rf_importance": [float(x) for x in top_rf_imp],
        "mi_importance": [float(x) for x in top_mi_imp],
        "combined_importance": [float(x) for x in top_combined_imp]
    }
    with open(FEATURE_IMPORTANCE_FILE, 'w') as f:
        json.dump(feature_imp_data, f, indent=2)
    
    log_data["step_times"]["feature_selection"] = time.time() - step_start

    # == 15. Power Transform (handle skewed features - BEFORE SMOTE, skip binary) ==
    step_start = time.time()
    print(f"\n[15/17] Power Transform (continuous only, BEFORE SMOTE)...")
    # Identify binary features
    binary_idx = [i for i, f in enumerate(feature_cols) if f.startswith('is_') or f == 'port_mod_1000']
    continuous_idx = [i for i in range(len(feature_cols)) if i not in binary_idx]

    pt = None  # FIX: khởi tạo trước để tránh NameError khi save
    if continuous_idx:
        pt = PowerTransformer(method='yeo-johnson')
        X_train_continuous = pt.fit_transform(X_train[:, continuous_idx])
        X_val_continuous = pt.transform(X_val[:, continuous_idx])
        X_test_continuous = pt.transform(X_test[:, continuous_idx])
        
        # Reconstruct with binary + transformed continuous
        X_train_new = np.zeros_like(X_train)
        X_val_new = np.zeros_like(X_val)
        X_test_new = np.zeros_like(X_test)
        
        X_train_new[:, binary_idx] = X_train[:, binary_idx]
        X_train_new[:, continuous_idx] = X_train_continuous
        X_val_new[:, binary_idx] = X_val[:, binary_idx]
        X_val_new[:, continuous_idx] = X_val_continuous
        X_test_new[:, binary_idx] = X_test[:, binary_idx]
        X_test_new[:, continuous_idx] = X_test_continuous
        
        X_train = X_train_new
        X_val = X_val_new
        X_test = X_test_new
        print(f"       Power transform applied to {len(continuous_idx)} continuous features")
        print(f"       Kept {len(binary_idx)} binary features unchanged")
    log_data["step_times"]["power_transform"] = time.time() - step_start

    # == 16. StandardScaler (BEFORE SMOTE for proper distance) ==
    step_start = time.time()
    print(f"\n[16/19] StandardScaler (BEFORE SMOTE for proper distance)...")
    scaler_smote = StandardScaler()
    X_train = scaler_smote.fit_transform(X_train)
    X_val = scaler_smote.transform(X_val)
    X_test = scaler_smote.transform(X_test)
    print(f"       StandardScaler applied (for SMOTE distance)")
    log_data["step_times"]["scaler_smote"] = time.time() - step_start

    # == 17. SMOTE (TRAIN only, sampling_strategy='not majority') ==
    step_start = time.time()
    print(f"\n[17/19] SMOTE (sampling_strategy={SMOTE_SAMPLING_STRATEGY}, TRAIN only)...")
    print(f"       Before: {len(X_train)}")
    smote = SMOTE(k_neighbors=SMOTE_K_NEIGHBORS, sampling_strategy=SMOTE_SAMPLING_STRATEGY, random_state=RANDOM_STATE)
    X_train, y_train = smote.fit_resample(X_train, y_train)
    print(f"       After: {len(X_train)}")
    unique, counts = np.unique(y_train, return_counts=True)
    for lbl_idx, cnt in zip(unique, counts):
        print(f"         {le.classes_[lbl_idx]:<20}: {cnt:>9,}")
    
    # Log class imbalance ratio after SMOTE
    imbalance_ratio = counts.max() / counts.min()
    print(f"       Imbalance ratio after SMOTE: {imbalance_ratio:.2f}x")
    log_data["smote_imbalance_ratio"] = float(imbalance_ratio)
    log_data["step_times"]["smote"] = time.time() - step_start

    # == 17.5 Shuffle after SMOTE ==
    step_start = time.time()
    print(f"\n[17.5/19] Shuffling after SMOTE...")
    from sklearn.utils import shuffle as sklearn_shuffle
    X_train, y_train = sklearn_shuffle(X_train, y_train, random_state=RANDOM_STATE)
    print(f"       Shuffled training data")
    log_data["step_times"]["shuffle"] = time.time() - step_start

    # == 18. Outlier Clipping (AFTER SMOTE for proper distance) ==
    step_start = time.time()
    print(f"\n[18/19] Outlier clipping (clip to [-5, 5] for stability)...")
    X_train = np.clip(X_train, -5, 5)
    X_val = np.clip(X_val, -5, 5)
    X_test = np.clip(X_test, -5, 5)
    print(f"       Clipped outliers to [-5, 5] range")
    log_data["step_times"]["outlier_clipping"] = time.time() - step_start

    # == 19. Retrain RF + Permutation Importance (VAL - CRITICAL FIX) ==
    step_start = time.time()
    print(f"\n[19/19] Retrain RF + Permutation Importance (VAL set - CRITICAL FIX)...")
    rf_final = RandomForestClassifier(n_estimators=100, max_depth=None, n_jobs=-1, random_state=RANDOM_STATE)
    rf_final.fit(X_train, y_train)
    
    # CRITICAL FIX: Permutation importance on VAL, not TRAIN
    perm_imp = permutation_importance(rf_final, X_val, y_val, n_repeats=PERM_IMP_REPEATS, 
                                      random_state=RANDOM_STATE, n_jobs=-1)
    perm_importances = perm_imp.importances_mean
    final_rf_imp = rf_final.feature_importances_
    
    print(f"       ✓ Permutation importance evaluated on VALIDATION set (n_repeats={PERM_IMP_REPEATS})")
    print(f"       Top 10 differences (RF vs Permutation on VAL):")
    diff = np.abs(final_rf_imp - perm_importances)
    top_diff_idx = np.argsort(diff)[::-1][:10]
    for rank, idx in enumerate(top_diff_idx, 1):
        print(f"         {rank:2d}. {top_features[idx]:<45} RF={final_rf_imp[idx]:.4f} Perm={perm_importances[idx]:.4f}")
    _plot_feature_importance_comparison(top_features, final_rf_imp, perm_importances,
                                        os.path.join(CHART_DIR, "03_feature_importance.png"))
    log_data["step_times"]["retrain_rf"] = time.time() - step_start

    # == FINAL SCALING (optional, based on model type) ==
    step_start = time.time()
    print(f"\n[FINAL] Final data preparation (USE_SCALER={USE_SCALER})...")
    if USE_SCALER:
        # For SVM/KNN: data already scaled before SMOTE, just ensure float32
        X_train_scaled = X_train.astype(np.float32)
        X_val_scaled = X_val.astype(np.float32)
        X_test_scaled = X_test.astype(np.float32)
        scaler_final = scaler_smote  # Use the pre-SMOTE scaler
        print(f"        Using pre-SMOTE StandardScaler (already applied)")
        print(f"        Train: mean={X_train_scaled.mean():.4f} std={X_train_scaled.std():.4f}")
        print(f"        Val:   mean={X_val_scaled.mean():.4f} std={X_val_scaled.std():.4f}")
        print(f"        Test:  mean={X_test_scaled.mean():.4f} std={X_test_scaled.std():.4f}")
    else:
        # For tree-based models: use data as-is (already scaled before SMOTE)
        X_train_scaled = X_train.astype(np.float32)
        X_val_scaled = X_val.astype(np.float32)
        X_test_scaled = X_test.astype(np.float32)
        scaler_final = None
        print(f"        No scaling (for tree-based models)")
    log_data["step_times"]["final_scaling"] = time.time() - step_start

    # == SANITY CHECKS ==
    print(f"\n[SANITY CHECKS]")
    assert not np.isnan(X_train_scaled).any(), "NaN found in X_train!"
    assert not np.isinf(X_train_scaled).any(), "Inf found in X_train!"
    assert not np.isnan(X_val_scaled).any(), "NaN found in X_val!"
    assert not np.isinf(X_val_scaled).any(), "Inf found in X_val!"
    assert not np.isnan(X_test_scaled).any(), "NaN found in X_test!"
    assert not np.isinf(X_test_scaled).any(), "Inf found in X_test!"
    assert X_train_scaled.shape[1] == len(feature_cols), "Feature count mismatch!"
    print(f"       ✓ All sanity checks passed")

    # == SAVE ==
    print(f"\n[SAVE] Saving artifacts...")
    np.save(os.path.join(MODEL_DIR, "X_train.npy"), X_train_scaled)
    np.save(os.path.join(MODEL_DIR, "X_val.npy"), X_val_scaled)
    np.save(os.path.join(MODEL_DIR, "X_test.npy"), X_test_scaled)
    np.save(os.path.join(MODEL_DIR, "y_train.npy"), y_train)
    np.save(os.path.join(MODEL_DIR, "y_val.npy"), y_val)
    np.save(os.path.join(MODEL_DIR, "y_test.npy"), y_test)
    joblib.dump(scaler_smote, os.path.join(MODEL_DIR, "scaler_before_smote.pkl"))
    if pt is not None:  # FIX: guard tránh NameError khi không có continuous features
        joblib.dump(pt, os.path.join(MODEL_DIR, "power_transformer.pkl"))
    joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.pkl"))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_names.pkl"))
    
    # CRITICAL: Save SMOTE model for reproducibility
    joblib.dump(smote, os.path.join(MODEL_DIR, "smote.pkl"))
    print(f"       ✓ Saved: smote.pkl")
    
    # CRITICAL: Save VarianceThreshold and feature indices for inference
    if vt is not None:
        joblib.dump(vt, os.path.join(MODEL_DIR, "variance_selector.pkl"))
        print(f"       ✓ Saved: variance_selector.pkl")
    if all_kept_idx is not None:
        np.save(os.path.join(MODEL_DIR, "feature_indices_after_variance.npy"), np.array(all_kept_idx))
        print(f"       ✓ Saved: feature_indices_after_variance.npy")
    
    # Save StratifiedKFold for cross-validation in training
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    joblib.dump(skf, os.path.join(MODEL_DIR, "stratified_kfold.pkl"))
    print(f"       ✓ Saved: stratified_kfold.pkl")
    
    # Save pipeline order for reproducibility
    pipeline_order = [
        "load_csv",
        "eda",
        "handle_nan",
        "drop_duplicates",
        "remove_identifiers",
        "encode_port",
        "feature_interactions",
        "map_labels",
        "remove_tiny_classes",
        "encode_labels",
        "train_val_test_split",
        "variance_threshold",
        "rf_importance",
        "correlation_filter",
        "feature_selection",
        "power_transform",
        "scaler_before_smote",
        "smote",           # FIX: SMOTE chạy TRƯỚC outlier_clipping trong code thực tế
        "shuffle",
        "outlier_clipping",
        "retrain_rf",
        "final_scaler"
    ]
    log_data["pipeline_order"] = pipeline_order
    
    print(f"       ✓ Saved: X_train.npy, X_val.npy, X_test.npy")
    print(f"       ✓ Saved: y_train.npy, y_val.npy, y_test.npy")
    print(f"       ✓ Saved: scaler.pkl, power_transformer.pkl, label_encoder.pkl, feature_names.pkl")

    # == POST-EDA ==
    print(f"\n[POST-EDA] Generating charts...")
    _plot_class_distribution(y_train, y_val, y_test, le, os.path.join(CHART_DIR, "04_class_distribution.png"))
    _plot_feature_distributions(X_train_scaled, feature_cols, os.path.join(CHART_DIR, "05_feature_distributions.png"))

    # == LOGGING ==
    log_data["pipeline_steps"] = [
        f"Initial rows: {initial_rows:,}",
        f"Final rows: {len(X_train) + len(X_val) + len(X_test):,}",
        f"Features: {len(feature_cols)} (from {len(feature_cols) + len(log_data['features_removed'].get('correlation', []))})",
        f"Train/Val/Test: {len(X_train):,} / {len(X_val):,} / {len(X_test):,}",
        f"SMOTE: Yes (sampling_strategy={SMOTE_SAMPLING_STRATEGY})",
        f"Power Transform: Yes (Yeo-Johnson)",
        f"StandardScaler: {USE_SCALER}",
        f"Total time: {time.time() - start_time:.1f}s"
    ]
    with open(LOG_FILE, 'w') as f:
        json.dump(log_data, f, indent=2, cls=NumpyEncoder)
    print(f"       Saved: preprocessing_log.json")

    print(f"\n{'=' * 90}")
    print(f"  [DONE] Preprocessing complete!")
    print(f"  Train: {X_train_scaled.shape[0]:,} | Val: {X_val_scaled.shape[0]:,} | Test: {X_test_scaled.shape[0]:,}")
    print(f"  Features: {len(feature_cols)} | Classes: {len(le.classes_)}")
    print(f"  Total time: {time.time() - start_time:.1f}s")
    print(f"{'=' * 90}")

    # Return appropriate scaler based on USE_SCALER
    scaler_to_return = scaler_final if USE_SCALER else scaler_smote
    return X_train_scaled, X_val_scaled, X_test_scaled, y_train, y_val, y_test, scaler_to_return, le, feature_cols


# =========================================================================
def _plot_data_info(df, filepath):
    """Save data overview to text file"""
    with open(filepath, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("DATA OVERVIEW\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Shape: {df.shape}\n")
        f.write(f"Memory: {df.memory_usage(deep=True).sum() / 1024**2:.1f} MB\n\n")
        f.write("Data Types:\n")
        f.write(str(df.dtypes) + "\n\n")
        f.write("Descriptive Statistics:\n")
        f.write(str(df.describe()) + "\n\n")
        f.write("Missing Values:\n")
        f.write(str(df.isnull().sum()) + "\n")
    print(f"       Saved: {os.path.basename(filepath)}")


def _plot_feature_importance_comparison(features, rf_imp, perm_imp, filepath):
    """Plot RF vs Permutation importance"""
    n = len(features)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, max(6, n * 0.35)))
    
    for ax, importances, title in [(ax1, rf_imp, "RF Importance"),
                                    (ax2, perm_imp, "Permutation Importance (VAL)")]:
        fig.patch.set_facecolor('#1a1a2e')
        ax.set_facecolor('#16213e')
        colors = plt.cm.RdYlGn(np.linspace(0.3, 1.0, n))
        bars = ax.barh(range(n), importances[::-1], color=colors, edgecolor='#ffffff22', height=0.7)
        ax.set_yticks(range(n))
        ax.set_yticklabels(features[::-1], color='white', fontsize=8)
        ax.set_xlabel('Importance Score', color='white', fontsize=10)
        ax.set_title(title, color='white', fontsize=12, pad=15)
        ax.tick_params(colors='white')
        for s in ['top', 'right']: ax.spines[s].set_visible(False)
        for s in ['bottom', 'left']: ax.spines[s].set_color('#444')
        ax.xaxis.grid(True, color='#333', linestyle='--', alpha=0.6)
        ax.set_axisbelow(True)
        for bar, val in zip(bars, importances[::-1]):
            ax.text(val + 0.001, bar.get_y() + bar.get_height()/2, f'{val:.4f}',
                    va='center', color='white', fontsize=7)
    
    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"       Saved: {os.path.basename(filepath)}")


def _plot_correlation(corr_matrix, filepath):
    """Plot correlation heatmap"""
    n = min(30, corr_matrix.shape[0])
    sample = corr_matrix.iloc[:n, :n]
    mask = np.triu(np.ones_like(sample, dtype=bool))
    fig, ax = plt.subplots(figsize=(14, 12))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')
    sns.heatmap(sample, mask=mask, cmap='coolwarm', center=0, vmin=-1, vmax=1, ax=ax,
                linewidths=0.2, linecolor='#ffffff11', cbar_kws={'shrink': 0.7})
    ax.set_title('Feature Correlation Matrix', color='white', fontsize=13, pad=15)
    ax.tick_params(colors='white', labelsize=7)
    plt.tight_layout()
    plt.savefig(filepath, dpi=100, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"       Saved: {os.path.basename(filepath)}")


def _plot_class_distribution(y_train, y_val, y_test, le, filepath):
    """Plot class distribution across train/val/test"""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.patch.set_facecolor('#1a1a2e')
    
    for ax, y, title in [(axes[0], y_train, "Train"), (axes[1], y_val, "Validation"), (axes[2], y_test, "Test")]:
        ax.set_facecolor('#16213e')
        unique, counts = np.unique(y, return_counts=True)
        labels = [le.classes_[i] for i in unique]
        colors = plt.cm.Set3(np.linspace(0, 1, len(unique)))
        bars = ax.bar(labels, counts, color=colors, edgecolor='white', linewidth=1.5)
        ax.set_title(title, color='white', fontsize=12, pad=10)
        ax.set_ylabel('Count', color='white', fontsize=10)
        ax.tick_params(colors='white')
        for spine in ax.spines.values(): spine.set_color('#444')
        plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height, f'{int(height)}',
                    ha='center', va='bottom', color='white', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"       Saved: {os.path.basename(filepath)}")


def _plot_feature_distributions(X_train, feature_cols, filepath):
    """Plot histogram of top 12 features"""
    n_features = min(12, len(feature_cols))
    fig, axes = plt.subplots(3, 4, figsize=(16, 10))
    fig.patch.set_facecolor('#1a1a2e')
    axes = axes.flatten()
    
    for idx in range(n_features):
        ax = axes[idx]
        ax.set_facecolor('#16213e')
        ax.hist(X_train[:, idx], bins=30, color='#00C9A7', alpha=0.7, edgecolor='white')
        ax.set_title(feature_cols[idx], color='white', fontsize=9)
        ax.tick_params(colors='white', labelsize=7)
        for spine in ax.spines.values(): spine.set_color('#444')
    
    for idx in range(n_features, len(axes)):
        axes[idx].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"       Saved: {os.path.basename(filepath)}")


if __name__ == "__main__":
    preprocess()
