"""
IDS - CICIDS2017 Multi-class Preprocessing Pipeline
====================================================
Gop tat ca 8 file CSV cua CICIDS2017 thanh 1 dataset multi-class.

15 nhan goc duoc nhom thanh 7 lop chinh:
  BENIGN, DoS, PortScan, DDoS, Brute Force, Bot, Web Attack

Pipeline:
  1. Load & concat tat ca file CSV
  2. Xu ly Inf/NaN
  3. Drop duplicates
  4. Xoa cot dinh danh + lab-bias
  5. Nhom nhan -> 7 lop chinh
  6. Xu ly class imbalance (undersample BENIGN)
  7. Encode nhan
  8. Train/Test split (stratified)
  9. Correlation filter (tren train)
  10. RF Feature Selection -> Top N (tren train)
  11. Drop duplicates lan 2 (post-reduction)
  12. StandardScaler (fit train only)
"""

import os
import glob
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier

# -- Duong dan --
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR  = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
CHART_DIR = os.path.join(BASE_DIR, "static", "charts")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

# -- Cau hinh --
# Cot dinh danh he thong (xoa neu ton tai)
ID_COLUMNS = ['Flow ID', 'Source IP', 'Destination IP', 'Src IP', 'Dst IP', 'Timestamp']
# Cot lab-bias
DROP_COLUMNS = ['Destination Port']
CORR_THRESHOLD = 0.95
TOP_N_FEATURES = 25
BENIGN_SAMPLE  = 50000    # Undersample BENIGN de can bang
MIN_CLASS_SIZE = 30       # Nhan co < 30 mau se bi loai

# Nhom 15 nhan -> 7 lop chinh
LABEL_MAP = {
    'BENIGN':                       'BENIGN',
    # DoS family
    'DoS Hulk':                     'DoS',
    'DoS GoldenEye':                'DoS',
    'DoS slowloris':                'DoS',
    'DoS Slowhttptest':             'DoS',
    # DDoS rieng
    'DDoS':                         'DDoS',
    # Scan
    'PortScan':                     'PortScan',
    # Brute Force
    'FTP-Patator':                  'Brute Force',
    'SSH-Patator':                  'Brute Force',
    # Web Attack (ky tu ngan cach co the la \x96, \u2013 hoac -)
    'Web Attack \x96 Brute Force':  'Web Attack',
    'Web Attack \x96 XSS':          'Web Attack',
    'Web Attack \x96 Sql Injection':'Web Attack',
    'Web Attack \u2013 Brute Force': 'Web Attack',
    'Web Attack \u2013 XSS':         'Web Attack',
    'Web Attack \u2013 Sql Injection':'Web Attack',
    'Web Attack - Brute Force':     'Web Attack',
    'Web Attack - XSS':             'Web Attack',
    'Web Attack - Sql Injection':   'Web Attack',
    # Bot
    'Bot':                          'Bot',
}
# Nhan bi loai vi qua it mau: Infiltration (36), Heartbleed (11)


def preprocess():
    print("=" * 65)
    print("  IDS - CICIDS2017 Multi-class Preprocessing")
    print("=" * 65)

    # == 1. Load & concat tat ca CSV ==
    print("\n[1/12] Loading all CSV files...")
    csv_files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))
    print(f"       Found {len(csv_files)} files")

    dfs = []
    for f in csv_files:
        name = os.path.basename(f)
        df_tmp = pd.read_csv(f, encoding='utf-8', low_memory=False)
        df_tmp.columns = df_tmp.columns.str.strip()
        print(f"       {name[:50]:<50} rows={len(df_tmp):>9,}")
        dfs.append(df_tmp)

    df = pd.concat(dfs, ignore_index=True)
    del dfs  # free memory
    print(f"       TOTAL: {len(df):,} rows  |  {df.shape[1]} columns")

    # == 2. Inf -> NaN -> Drop NaN ==
    print("\n[2/12] Handling Inf/NaN...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    print(f"       Removed {before - len(df):,} rows -> {len(df):,} remain")

    # == 3. Drop exact duplicates ==
    print("\n[3/12] Dropping exact duplicates...")
    before = len(df)
    df.drop_duplicates(inplace=True)
    print(f"       Removed {before - len(df):,} -> {len(df):,} remain")

    # == 4a. Xoa cot dinh danh he thong (Flow ID, IP, Timestamp) ==
    print("\n[4/12] Removing identifier & lab-bias columns...")
    found_id = [c for c in ID_COLUMNS if c in df.columns]
    if found_id:
        df.drop(columns=found_id, inplace=True)
        print(f"       Dropped identifiers: {found_id}")
    else:
        print("       No identifier columns found (already clean)")

    # == 4b. Xoa lab-bias columns ==
    found_bias = [c for c in DROP_COLUMNS if c in df.columns]
    if found_bias:
        df.drop(columns=found_bias, inplace=True)
        print(f"       Dropped lab-bias: {found_bias}")
    print(f"       Columns remaining: {df.shape[1]}")

    # == 5. Nhom nhan -> 7 lop ==
    print("\n[5/12] Mapping 15 labels -> 7 classes...")
    df['Label'] = df['Label'].str.strip()
    df['Label'] = df['Label'].map(LABEL_MAP)
    unknown = df['Label'].isna().sum()
    if unknown > 0:
        print(f"       Dropping {unknown:,} rows with unmapped labels")
        df.dropna(subset=['Label'], inplace=True)

    print(f"       Class distribution:")
    for lbl, cnt in df['Label'].value_counts().items():
        print(f"         {lbl:<20}: {cnt:>9,}")

    # == 6. Loai cac lop qua nho ==
    print(f"\n[6/12] Removing tiny classes...")
    class_counts = df['Label'].value_counts()
    small_classes = class_counts[class_counts < MIN_CLASS_SIZE].index.tolist()
    if small_classes:
        print(f"       Removing tiny classes (< {MIN_CLASS_SIZE} samples): {small_classes}")
        df = df[~df['Label'].isin(small_classes)]

    print(f"       Distribution before split:")
    for lbl, cnt in df['Label'].value_counts().items():
        print(f"         {lbl:<20}: {cnt:>9,}")
    print(f"       Total: {len(df):,}")

    # == 7. Encode nhan ==
    print("\n[7/12] Encoding labels...")
    le = LabelEncoder()
    df['Label'] = le.fit_transform(df['Label'])
    label_map = dict(zip(le.classes_, le.transform(le.classes_)))
    print(f"       Mapping: {label_map}")

    # == 8. Train/Test split ==
    print("\n[8/12] Train/Test split (80/20, stratified)...")
    feature_cols = [c for c in df.columns if c != 'Label']
    X = df[feature_cols].values
    y = df['Label'].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"       Train: {X_train.shape[0]:,}  |  Test: {X_test.shape[0]:,}")

    # == 8b. Xu ly class imbalance (chi tren Train) ==
    print(f"\n[8b/12] Balancing classes (undersample BENIGN to {BENIGN_SAMPLE:,} on Train only)...")
    df_train_tmp = pd.DataFrame(X_train, columns=feature_cols)
    df_train_tmp['__y__'] = y_train
    
    benign_label_encoded = le.transform(['BENIGN'])[0]
    benign_mask = df_train_tmp['__y__'] == benign_label_encoded
    n_benign = benign_mask.sum()
    if n_benign > BENIGN_SAMPLE:
        benign_df = df_train_tmp[benign_mask].sample(n=BENIGN_SAMPLE, random_state=42)
        others_df = df_train_tmp[~benign_mask]
        df_train_tmp = pd.concat([benign_df, others_df], ignore_index=True)
        print(f"       BENIGN on Train: {n_benign:,} -> {BENIGN_SAMPLE:,}")
    
    X_train = df_train_tmp.drop(columns=['__y__']).values
    y_train = df_train_tmp['__y__'].values
    print(f"       Final Train size: {len(X_train):,}")

    # == 9. Correlation filter (tren train) ==
    print(f"\n[9/12] Correlation filter (threshold={CORR_THRESHOLD})...")
    df_train = pd.DataFrame(X_train, columns=feature_cols)
    corr_abs = df_train.corr().abs()
    upper = corr_abs.where(np.triu(np.ones(corr_abs.shape), k=1).astype(bool))
    drop_corr = [col for col in upper.columns if any(upper[col] > CORR_THRESHOLD)]
    if drop_corr:
        print(f"       Dropping {len(drop_corr)} correlated columns")
        keep_cols = [c for c in feature_cols if c not in drop_corr]
        col_idx = [feature_cols.index(c) for c in keep_cols]
        X_train = X_train[:, col_idx]
        X_test  = X_test[:, col_idx]
        feature_cols = keep_cols
    print(f"       Features remaining: {len(feature_cols)}")
    _plot_correlation(corr_abs, os.path.join(CHART_DIR, "correlation_matrix.png"))

    # == 10. RF Feature Selection ==
    print(f"\n[10/12] RF Importance -> top {TOP_N_FEATURES}...")
    rf_sel = RandomForestClassifier(n_estimators=100, max_depth=15,
                                    n_jobs=-1, random_state=42)
    rf_sel.fit(X_train, y_train)
    importances = rf_sel.feature_importances_
    sorted_idx  = np.argsort(importances)[::-1][:TOP_N_FEATURES]
    top_features    = [feature_cols[i] for i in sorted_idx]
    top_importances = importances[sorted_idx]

    print(f"       Top {TOP_N_FEATURES} features:")
    for rank, (f, imp) in enumerate(zip(top_features, top_importances), 1):
        print(f"         {rank:2d}. {f:<45} {imp:.4f}")

    X_train = X_train[:, sorted_idx]
    X_test  = X_test[:, sorted_idx]
    feature_cols = top_features
    _plot_feature_importance(top_features, top_importances,
                             os.path.join(CHART_DIR, "feature_importance.png"))

    # == 11. Drop duplicates lan 2 (post-reduction) TRÊN TRAIN ONLY ==
    print(f"\n[11/12] Post-reduction dedup (Train only)...")
    df_tr = pd.DataFrame(X_train, columns=feature_cols)
    df_tr['__y__'] = y_train
    before_tr = len(df_tr)
    df_tr.drop_duplicates(inplace=True)
    X_train = df_tr.drop(columns=['__y__']).values
    y_train = df_tr['__y__'].values
    print(f"       Train: {before_tr:,} -> {len(X_train):,}")

    # KHÔNG CHẠM VÀO X_test, y_test Ở ĐÂY!
    print(f"       Test:  Giữ nguyên {len(X_test):,} rows")

    # == 12. StandardScaler ==
    print(f"\n[12/12] StandardScaler (fit on train only)...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)
    print(f"        Train mean={X_train.mean():.4f} std={X_train.std():.4f}")
    print(f"        Test  mean={X_test.mean():.4f}  std={X_test.std():.4f}")

    # == Save ==
    print("\n[SAVE] Saving artifacts...")
    np.save(os.path.join(MODEL_DIR, "X_train.npy"), X_train)
    np.save(os.path.join(MODEL_DIR, "X_test.npy"),  X_test)
    np.save(os.path.join(MODEL_DIR, "y_train.npy"), y_train)
    np.save(os.path.join(MODEL_DIR, "y_test.npy"),  y_test)
    joblib.dump(scaler,       os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(le,           os.path.join(MODEL_DIR, "label_encoder.pkl"))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_names.pkl"))

    print(f"\n{'=' * 65}")
    print(f"  [DONE] Preprocessing complete!")
    print(f"  Train: {X_train.shape[0]:,}  |  Test: {X_test.shape[0]:,}")
    print(f"  Features: {len(feature_cols)}  |  Classes: {len(le.classes_)}")
    print(f"  Classes: {list(le.classes_)}")
    print(f"{'=' * 65}")

    return X_train, X_test, y_train, y_test, scaler, le, feature_cols


# =========================================================================
def _plot_feature_importance(features, importances, filepath):
    n = len(features)
    fig, ax = plt.subplots(figsize=(10, max(6, n * 0.4)))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')
    colors = plt.cm.RdYlGn(np.linspace(0.3, 1.0, n))
    bars = ax.barh(range(n), importances[::-1],
                   color=colors, edgecolor='#ffffff22', height=0.7)
    ax.set_yticks(range(n))
    ax.set_yticklabels(features[::-1], color='white', fontsize=9)
    ax.set_xlabel('Importance Score', color='white', fontsize=11)
    ax.set_title(f'Top {n} Features - RF Importance',
                 color='white', fontsize=13, pad=15)
    ax.tick_params(colors='white')
    for s in ['top', 'right']: ax.spines[s].set_visible(False)
    for s in ['bottom', 'left']: ax.spines[s].set_color('#444')
    ax.xaxis.grid(True, color='#333', linestyle='--', alpha=0.6)
    ax.set_axisbelow(True)
    for bar, val in zip(bars, importances[::-1]):
        ax.text(val + 0.001, bar.get_y() + bar.get_height()/2,
                f'{val:.4f}', va='center', color='white', fontsize=8)
    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"       Chart saved: {os.path.basename(filepath)}")


def _plot_correlation(corr_matrix, filepath):
    n = min(30, corr_matrix.shape[0])
    sample = corr_matrix.iloc[:n, :n]
    mask = np.triu(np.ones_like(sample, dtype=bool))
    fig, ax = plt.subplots(figsize=(14, 12))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#16213e')
    sns.heatmap(sample, mask=mask, cmap='coolwarm', center=0,
                vmin=-1, vmax=1, ax=ax, square=False,
                linewidths=0.2, linecolor='#ffffff11',
                cbar_kws={'shrink': 0.7})
    ax.set_title('Feature Correlation Matrix', color='white', fontsize=13, pad=15)
    ax.tick_params(colors='white', labelsize=7)
    plt.tight_layout()
    plt.savefig(filepath, dpi=100, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"       Chart saved: {os.path.basename(filepath)}")


if __name__ == "__main__":
    preprocess()
