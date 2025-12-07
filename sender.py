import sys
from scapy.all import PcapReader, sendp
import time

# --- Configurações que deve alterar ---

INTERFACE_NAME = "Ethernet 2" 
PCAP_FILE = r"C:\Users\pc\Downloads\Wednesday-workingHours.pcap" 
# NOVO: Limite de pacotes a enviar (ex: 50.000 pacotes para um teste rápido)
PACKET_LIMIT = 50000 
# ----------------------------------------

def stream_and_send(interface, pcap_file, limit):
    packets_sent = 0
    start_time = time.time()
    
    try:
        print(f"[*] A iniciar leitura do ficheiro PCAP grande (Limite: {limit} pacotes)")
        
        reader = PcapReader(pcap_file)
        print(f"[*] A enviar pacotes via streaming na interface: {interface}...")

        for packet in reader:
            if packets_sent >= limit: # Verifica o limite antes de enviar
                break 

            sendp(packet, iface=interface, count=1, verbose=0)
            packets_sent += 1
            
            # Mostra o progresso a cada 1000 pacotes
            if packets_sent % 1000 == 0:
                print(f"\r[*] Pacotes enviados: {packets_sent}", end='')
        
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n[+] Replay concluído.")
        print(f"[+] Total de pacotes enviados: {packets_sent}")
        print(f"[+] Duração: {duration:.2f} segundos")

    except Exception as e:
        print(f"\n[!] Erro: {e}")
        sys.exit(1)

if __name__ == "__main__":
    stream_and_send(INTERFACE_NAME, PCAP_FILE, PACKET_LIMIT)


