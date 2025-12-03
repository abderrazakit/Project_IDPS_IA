import pandas as pd
import joblib
import time
import os
import numpy as np
from subprocess import run, PIPE, STDOUT
import logging
import warnings

# --- 1. SUPPRESSION DES WARNINGS (COSMÉTIQUE) ---
# On ignore les avertissements de sklearn concernant les noms de features manquants
warnings.filterwarnings("ignore", category=UserWarning)

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# --- CHEMINS CRITIQUES ---
LOG_DIR = '/home/kali/IDPS_IA_Project/Data_Acquisition/zeek_logs'
FLOW_LOG = os.path.join(LOG_DIR, 'flowmeter.log')
CONN_LOG = os.path.join(LOG_DIR, 'conn.log')

MODEL_DIR = '/home/kali/IDPS_IA_Project/Model_Deployment/trained_models'
MODEL_PATH = os.path.join(MODEL_DIR, 'lgbm_model_filtered_sampled.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'min_max_scaler_filtered.pkl')
ENCODER_PATH = os.path.join(MODEL_DIR, 'label_encoder_filtered.pkl')

BLOCKED_IPS = set()
UID_TO_IP_CACHE = {} 
LAST_READ_POSITION = 0

# --- FEATURES & LABELS ---
FEATURES_FOR_MODEL = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

LABELS_DECODER = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest', 
    'DoS slowloris', 'FTP-Patator', 'PortScan', 'SSH-Patator', 'Web Attack  Brute Force'
]

# --- FONCTIONS ---

def load_artifacts():
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        encoder = joblib.load(ENCODER_PATH)
        logging.info("✅ Artefacts ML chargés avec succès.")
        return model, scaler, encoder
    except Exception as e:
        logging.error(f"❌ Erreur chargement artefacts: {e}")
        exit(1)

def update_ip_cache():
    """Lit conn.log pour associer UID Zeek -> IP Source."""
    try:
        if not os.path.exists(CONN_LOG): return
        
        # On lit les 500 dernières lignes pour être sûr d'avoir l'IP
        with open(CONN_LOG, 'r') as f:
            f.seek(0, 2)
            f_size = f.tell()
            # Lire les derniers 50KB (augmenté pour être sûr)
            f.seek(max(f_size - 50000, 0)) 
            lines = f.readlines()
            
            count_new = 0
            for line in lines:
                if line.startswith('#'): continue
                parts = line.split('\t')
                
                # Format standard conn.log: ts, uid, id.orig_h ...
                # Index 1 = UID, Index 2 = Source IP
                if len(parts) > 4:
                    uid = parts[1]
                    src_ip = parts[2]
                    UID_TO_IP_CACHE[uid] = src_ip
                    count_new += 1
            
            # Décommentez pour déboguer si "IP_Inconnue" persiste
            # logging.info(f"Cache IP mis à jour : {len(UID_TO_IP_CACHE)} entrées en mémoire.")

    except Exception as e:
        logging.error(f"Erreur lecture conn.log: {e}")

def apply_block_rule(ip_address):
    # Protection: ne jamais bloquer localhost ou des IPs invalides
    if ip_address in ["127.0.0.1", "::1", "IP_Inconnue"]: return

    if ip_address not in BLOCKED_IPS:
        try:
            run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
            BLOCKED_IPS.add(ip_address)
            logging.critical(f"⛔ ACTION: IP {ip_address} BLOQUÉE via iptables")
        except Exception as e:
            logging.error(f"Echec blocage: {e}")

def process_flow_line(line, scaler, model):
    parts = line.strip().split('\t')
    if len(parts) < 10: return None, None
    
    uid = parts[0]
    
    # 1. Extraction brute
    raw_vals = []
    for p in parts[1:]:
        try:
            val = float(p) if p not in ['-', ''] else 0.0
            raw_vals.append(val)
        except ValueError:
            raw_vals.append(0.0)
            
    # 2. Adaptation Scaler (69 features)
    scaler_needs = getattr(scaler, 'n_features_in_', 69)
    current_len = len(raw_vals)
    
    if current_len > scaler_needs:
        raw_vals = raw_vals[:scaler_needs]
    elif current_len < scaler_needs:
        raw_vals += [0.0] * (scaler_needs - current_len)
        
    # 3. Normalisation
    try:
        X = np.array([raw_vals])
        X_scaled = scaler.transform(X)
        
        # 4. Adaptation Modèle (68 features)
        model_needs = getattr(model, 'n_features_in_', 68)
        if X_scaled.shape[1] > model_needs:
            X_final = X_scaled[:, :model_needs]
        else:
            X_final = X_scaled
            
    except Exception as e:
        return None, None
    
    # Récupération IP via le cache
    src_ip = UID_TO_IP_CACHE.get(uid, "IP_Inconnue")
    
    return X_final, src_ip

def run_loop(model, scaler, encoder):
    global LAST_READ_POSITION
    
    while not os.path.exists(FLOW_LOG):
        logging.info(f"⏳ En attente de {FLOW_LOG}...")
        time.sleep(2)
    
    logging.info(f"👁️  Surveillance active de {FLOW_LOG}")
        
    with open(FLOW_LOG, 'r') as f:
        f.seek(0, 2)
        LAST_READ_POSITION = f.tell()
        
    while True:
        try:
            # On met à jour le cache IP AVANT de traiter les logs
            update_ip_cache()
            
            with open(FLOW_LOG, 'r') as f:
                f.seek(LAST_READ_POSITION)
                lines = f.readlines()
                LAST_READ_POSITION = f.tell()
            
            if not lines:
                time.sleep(0.5)
                continue
                
            for line in lines:
                if line.startswith('#'): continue
                
                features, src_ip = process_flow_line(line, scaler, model)
                if features is None: continue
                
                # INFERENCE
                pred_idx = model.predict(features)[0]
                
                try:
                    pred_label = encoder.inverse_transform([pred_idx])[0]
                except:
                    pred_label = "Unknown"

                # AFFICHAGE DU RÉSULTAT
                if pred_label != 'BENIGN':
                    logging.critical(f"🚨 ALERTE: {pred_label} détecté depuis {src_ip}")
                    apply_block_rule(src_ip)
                else:
                    # On n'affiche que si l'IP est connue pour valider le fix
                    if src_ip != "IP_Inconnue":
                        logging.info(f"✅ Trafic Normal (Source: {src_ip})")
                    else:
                        # Si IP inconnue, on l'affiche quand même pour info (mode debug)
                        logging.info(f"✅ Trafic Normal (IP Inconnue - ID: {line.split()[0]})")
                    
        except Exception as e:
            logging.error(f"Erreur boucle: {e}")
            time.sleep(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERREUR: Lancez avec sudo !")
        exit(1)
        
    model, scaler, encoder = load_artifacts()
    run_loop(model, scaler, encoder)
