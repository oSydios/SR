#!/bin/bash

# =======================================================
# CONFIGURAÇÕES 
# =======================================================

INTERFACE="eth0"                            
PCAP_FILE="/tmp/ataque_capturado_teste.pcap" 
OUTPUT_DIR="/home/auser/"
CFM_BIN_DIR="/home/auser/Downloads/CICFlowMeter-4.0/bin"
INPUT_FOLDER="/tmp/"
IDS_SCRIPT="/home/auser/ids_sim.py"

VENV_PYTHON="/home/auser/ids_venv/bin/python3"

PCAP_FILENAME=$(basename $PCAP_FILE)
CSV_FILE="${OUTPUT_DIR}${PCAP_FILENAME}_Flow.csv"
# =======================================================

echo "--- 1. INICIO DA CAPTURA COM TSHARK ---"
sudo tshark -i $INTERFACE  -w $PCAP_FILE 

if [ $? -ne 0 ]; then
    echo "ERRO: Captura com Tshark falhou. Verifique se a interface '$INTERFACE' existe."
    exit 1
fi
echo "Captura encerrada com sucesso."

# --------------------------------------------------------------------------------

echo "--- 2. PROCESSANDO PCAP (CICFlowMeter) ---"
(
    cd $CFM_BIN_DIR && \
    sudo ./cfm $INPUT_FOLDER $OUTPUT_DIR
                                                                   
)
if [ $? -ne 0 ]; then
    echo "ERRO: O processamento CICFlowMeter falhou. Verifique as permissões ou caminhos."
    exit 1
fi
echo "Geração de features concluída com sucesso."

# --------------------------------------------------------------------------------

echo "--- 3. CLASSIFICAÇÃO DOS FLOWS (IDS Python) ---"

# 2. Verificar se o ficheiro CSV foi criado
if [ ! -f "$CSV_FILE" ]; then
    echo "ERRO: Ficheiro CSV de flows não encontrado: $CSV_FILE"
    echo "Verifique se o CICFlowMeter nomeou o ficheiro corretamente."
    exit 1
fi


$VENV_PYTHON $IDS_SCRIPT "$CSV_FILE"

if [ $? -ne 0 ]; then
    echo "ERRO: A classificação IDS Python falhou. Verifique o ambiente virtual ou o código."
    exit 1
fi

echo "--- CLASSIFICAÇÃO COMPLETA ---"
