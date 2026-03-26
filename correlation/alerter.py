import json
import os
import logging
from datetime import datetime, timezone
from colorama import Fore, Style, init
from config import ALERT_OUTPUT_PATH

init(autoreset= True)
logger = logging.getLogger(__name__)

class Alerter:
    def __init__(self):
        os.makedirs(os.path.dirname(ALERT_OUTPUT_PATH), exist_ok = True)
    
    def process(self, detections):
        if not detections:
            print(Fore.GREEN + '[+] No attack chains detected in this run.')
            return

        for detection in detections:
            self._print_alert(detection)
            self._save_alert(detection)

    def _print_alert(self, d):
        print()
        print(Fore.RED + '=' * 65)
        print(Fore.RED + f'  CRITICAL ALERT — ATTACK CHAIN DETECTED')
        print(Fore.RED + '=' * 65)
        print(Fore.YELLOW + f'  Chain:    {d["chain"]}')
        print(Fore.YELLOW + f'  Actor:    {d["actor"]}')
        print(Fore.YELLOW + f'  Source IP: {d["source_ip"]}')
        print(Fore.CYAN  + f'  MITRE:    {" · ".join(d["mitre_ttps"])}')
        print()
        print(Fore.WHITE + '  Timeline:')
        tl = d['timeline']
        print(f'    Recon started:   {tl["recon_start"]}')
        print(f'    Priv esc at:     {tl["privesc_time"]}')
        print(f'    Exfil at:        {tl["exfil_time"]}')
        print()
        print(Fore.WHITE + '  Evidence:')
        ev = d['evidence']
        print(f'    Recon calls:     {ev["recon_calls"]}')
        print(f'    Roles assumed:   {ev["roles_assumed"]}')
        print(f'    Buckets hit:     {ev["buckets_accessed"]}')
        print(Fore.RED + '=' * 65)
        print()

    def _save_alert(self, detection):
        alerts = []
        if os.path.exists(ALERT_OUTPUT_PATH):
            with open(ALERT_OUTPUT_PATH) as f:
                try:
                    alerts = json.load(f)
                except:
                    alerts = []
        alerts.append(detection)
        with open(ALERT_OUTPUT_PATH, 'w') as f:
            json.dump(alerts, f, indent=2, default=str)
        print(Fore.GREEN + f'  Alert saved to {ALERT_OUTPUT_PATH}')
