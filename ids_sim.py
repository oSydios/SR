import pandas as pd
import numpy as np
import joblib
import sys
import os

# --- 1. CONFIGURAÇÕES & ARTEFATOS ---

MODEL_FILE = "/home/auser/Downloads/decision_tree_model.pkl"
MIN_MAX_FILE = "/home/auser/Downloads/feature_min_max.csv"
ORDER_FILE = "/home/auser/Downloads/feature_order.pkl"


# Rename_Map
RENAME_MAP = {
    'Tot Fwd Pkts': 'Total Fwd Packets', 'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets', 'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max', 'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean', 'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max', 'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean', 'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Pkt Len Min': 'Min Packet Length', 'Pkt Len Max': 'Max Packet Length',
    'Pkt Len Mean': 'Packet Length Mean', 'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance', 'Pkt Size Avg': 'Average Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size', 'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Flow Byts/s': 'Flow Bytes/s', 'Flow Pkts/s': 'Flow Packets/s',
    'Fwd IAT Tot': 'Fwd IAT Total', 'Bwd IAT Tot': 'Bwd IAT Total',
    'Fwd Pkts/s': 'Fwd Packets/s', 'Bwd Pkts/s': 'Bwd Packets/s',
    'FIN Flag Cnt': 'FIN Flag Count', 'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count', 'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count', 'URG Flag Cnt': 'URG Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count', 'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length', 'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes', 'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes', 'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward', 'Fwd Seg Size Min': 'min_seg_size_forward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk', 'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate', 'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk', 'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Dst Port': 'Destination Port',
}

# Mapeamento de output (do inteiro para o nome da classe)
LABEL_MAPPING = {
    0: 'Dos Hulk',
    1: 'DoS slowloris ',       
    2: 'DoS Slowhttptest',
    3: 'DoS GoldenEye',
    4: 'Heartbleed',
    5: 'Benign',           
}
# --- FIM CONFIGURAÇÕES ---

def load_artifacts():
    """Carrega o modelo, min/max e a ordem das features."""
    try:
        dt_model = joblib.load(MODEL_FILE)
        min_max_df = pd.read_csv(MIN_MAX_FILE)
        feature_order = joblib.load(ORDER_FILE)
        numeric_features = min_max_df['feature'].tolist()
        return dt_model, min_max_df, feature_order, numeric_features
    except FileNotFoundError as e:
        print(f"ERRO: Não foi possível encontrar o ficheiro necessário: {e.filename}")
        print("Certifique-se de que os ficheiros .pkl e .csv estão no caminho correto.")
        sys.exit(1)

def preprocess_cic_flows(csv_path, feature_order, numeric_features, min_max_df):
    """Lê, renomeia, trata valores, normaliza e ordena os dados."""
    print(f"\n[*] A carregar e pré-processar dados de {csv_path}...")
    
    # 1. Leitura e Limpeza Inicial
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"ERRO ao ler CSV: {e}")
        sys.exit(1)

    df.columns = df.columns.str.strip() # Remove espaços em branco
    df.rename(columns=RENAME_MAP, inplace=True) # Aplica o RENAME_MAP

    # Guarda colunas originais úteis para o relatório
    report_cols = [col for col in ['Flow ID', 'Source IP', 'Destination IP', 'Dst Port'] if col in df.columns]

    # 2. Inserir Colunas em Falta (Garante as 78 features)
    missing_in_df = list(set(feature_order) - set(df.columns))
    if missing_in_df:
        print(f"--> Inserir {len(missing_in_df)} feature(s) em falta com valor 0.")
        for col in missing_in_df:
            df[col] = 0

    # 3. Filtragem e Reordenação Final
    try:
        # Cria o DataFrame X com exatamente a ordem e o número de colunas corretas (78)
        X_new = df[feature_order].copy()
    except KeyError as e:
        print(f"\nERRO: A feature crítica {e} não pôde ser encontrada/renomeada.")
        sys.exit(1)

    # 4. Tratamento de Valores Infinitos/NaN (Importante para dados CICFlowMeter)
    X_new.replace([np.inf, -np.inf, np.nan], 0, inplace=True)

    # 5. Min-Max Scaling
    min_max_dict = min_max_df.set_index('feature').to_dict()
    
    for feature in numeric_features:
        if feature in X_new.columns:
            min_val = min_max_dict['min'][feature]
            max_val = min_max_dict['max'][feature]
            denominator = (max_val - min_val)
            
            if denominator != 0:
                # Normaliza e limita (clip) para os valores vistos no treino (0 a 1)
                X_new.loc[:, feature] = (X_new[feature] - min_val) / denominator
                X_new.loc[:, feature] = X_new[feature].clip(0, 1) 
            else:
                X_new.loc[:, feature] = 0
    
    return X_new.values, df[report_cols].copy() # Retorna o array pronto para o modelo e as colunas para o relatório

def main():
    """Função principal para executar o pipeline de IDS."""
    
    if len(sys.argv) != 2:
        sys.exit(1)
    
    csv_path = sys.argv[1] # Caminho do CSV passado pelo full_ids_run.sh
    
    # --- A. Carregar Artefatos ---
    dt_model, min_max_df, feature_order, numeric_features = load_artifacts()
    
    # --- B. Pré-processar Dados ---
    X_new_array, report_df = preprocess_cic_flows(csv_path, feature_order, numeric_features, min_max_df)
    
    # --- C. Previsão ---
    print("\n[*] Previsões...")
    predictions = dt_model.predict(X_new_array)
    
    # --- D. Apresentar Resultados ---
    report_df['Predicted_Label'] = predictions
    report_df['Predicted_Label'] = report_df['Predicted_Label'].map(LABEL_MAPPING)

    print("\n--- RELATÓRIO DE DETEÇÃO DE INTRUSÃO (Decision Tree) ---")
    
    # Contagem de resultados
    summary = report_df['Predicted_Label'].value_counts()
    print(summary)

    num_ataque = summary.get('Dos Hulk', 0) + summary.get('DoS slowloris', 0) + summary.get('Heartbleed', 0) + summary.get('DoS Slowhttptest', 0) + summary.get('DoS GoldenEye', 0)

    if num_ataque > 0:
            print("\n[!!!] ALERTA: ATAQUE(S) DETETADO(S)! [!!!]")
            ataque_flows = report_df[report_df['Predicted_Label'] != 'Benign']
            
            print("\nPrimeiros 5 Flows de Ataque:")
            print(ataque_flows.head())
    else:
        print("\n[+] Nenhum ataque detetado (todos os flows são Benignos).")
        
    print("\nClassificação concluída.")
 
if __name__ == "__main__":
    main()
