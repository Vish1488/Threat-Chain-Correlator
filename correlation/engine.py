import sqlite3
import logging
import os
from datetime import datetime, timedelta, timezone
from config import (
    DB_PATH, CORRELATION_WINDOW_MINUTES, MIN_RECON_CALLS,
    RECON_API_CALLS, PRIVESC_API_CALLS, EXFIL_API_CALLS
)

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self._init_db()
    
    def _init_db(self):
        #creates events table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                timestamp TEXT,
                api_call TEXT,
                service TEXT,
                actor TEXT,
                source_ip TEXT,
                region TEXT,
                bucket_name TEXT,
                role_assumed TEXT,
                processed INTEGER DEFAULT 0

            )
        ''')
        self.conn.commit()
    
    def ingest(self, events):
        #store the events in the table
        inserted = 0
        for ev in events:
            try:
                bucket = self._extract_bucket(ev)
                role = self._extract_role(ev)
                self.conn.execute('''
                    INSERT OR IGNORE INTO events
                    (event_id, timestamp, api_call, service, actor, source_ip, region, bucket_name, role_assumed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ev['event_id'],
                    ev['timestamp'].isoformat(),
                    ev['api_call'],
                    ev['service'],
                    ev['actor'],
                    ev['source_ip'],
                    ev['region'],
                    bucket,
                    role
                ))
                inserted +=1
            except Exception as e:
                logger.debug(f'Failed to insert event: {e}')
        self.conn.commit()
        logger.info(f'ingested {inserted} new events into the sqlite table')


    def detect_chains(self):
        """This is the core logic of the correlation engine, for each unique IP+actor/user combo, 
            it will check if all 3 detection stages occured within the designated time (for now 15 mins)
            returns lists of chain detections"""
        
        detections = []
        window_start = (
            datetime.now(timezone.utc) - timedelta(minutes=CORRELATION_WINDOW_MINUTES)).isoformat()

        #get all actors active in the window
        actors = self.conn.execute('''
            SELECT DISTINCT actor, source_ip FROM events
            WHERE timestamp > ? AND processed = 0
        ''', (window_start,)).fetchall()

        for actor, source_ip in actors:
            detection = self._check_chain_for_actor(
                actor, source_ip, window_start
            )
            if detection:
                detections.append(detection)
                self._mark_processed(actor, window_start)
        return detections

    def _check_chain_for_actor(self, actor, source_ip, window_start):
        #checks if a specific actor completed all 3 stages of the attack chain
        #returns detection dictionary or none
        recon_calls = self._get_events_for_actor(actor, RECON_API_CALLS, window_start)
        privesc_calls = self._get_events_for_actor(actor, PRIVESC_API_CALLS, window_start)
        assumed_actor = None
        #Once the attacker is able to escalate to a privilleged role, the attacker user/role will change
        if privesc_calls:
            role_name = privesc_calls[0].get('role_assumed', '')
            if role_name:
                assumed_actor = f'assumed-role/{role_name}'

        
        exfil_calls = []
        if assumed_actor:
            exfil_calls = self._get_events_for_actor(
            assumed_actor, EXFIL_API_CALLS, window_start
        )

        #all three stages should be present
        if (len(recon_calls)>=MIN_RECON_CALLS and len(privesc_calls)>=1 and len(exfil_calls)>=1):

            #logic to check the time order of the calls: - recon -> privillege esc -> exfil
            first_recon = min(e['timestamp'] for e in recon_calls)
            first_privesc = min(e['timestamp'] for e in privesc_calls)
            first_exfil = min(e['timestamp'] for e in exfil_calls)

            if first_recon <= first_privesc <= first_exfil:
                return {
                    'chain': 'IAM_RECON_PRIVESC_S3_EXFIL',
                    'severity': 'CRITICAL',
                    'actor': actor,
                    'assumed_role': assumed_actor,
                    'source_ip': source_ip,
                    'mitre_ttps': ['T1580','T1548','T1530'],
                    'timeline': {
                        'recon_start': first_recon,
                        'privesc_time': first_privesc,
                        'exfil_time': first_exfil
                    },
                    'evidence': {
                        'recon_calls': [e['api_call'] for e in recon_calls],
                        'roles_assumed': list(set(
                            e.get('role_assumed', '') for e in  privesc_calls 
                        )),
                        'buckets_accessed': list(set(
                            e.get('bucket_name', '') for e in  exfil_calls
                        )),
                    },
                    'detected_at': datetime.now(timezone.utc).isoformat()
                }
        return None
    
    def _get_events_for_actor(self, actor, api_calls, window_start):
        placeholders = ','.join('?' * len(api_calls))
        rows = self.conn.execute(f'''
            SELECT api_call, timestamp, source_ip, bucket_name, role_assumed
            FROM events
            WHERE actor = ?
            AND api_call IN ({placeholders})
            AND timestamp > ?
            ORDER BY timestamp ASC 
        ''', [actor]+list(api_calls) + [window_start]).fetchall()

        return [
            {'api_call': r[0], 'timestamp':r[1],
             'source_ip': r[2], 'bucket_name': r[3],
             'role_assumed': r[4]}
             for r in rows
        ]

    def _mark_processed(self, actor, window_start):
        self.conn.execute(
            'UPDATE events SET processed=1 WHERE actor=? AND timestamp>?',
            (actor, window_start)
        )
        self.conn.commit()
    
    def _extract_bucket(self, ev):
        params = ev.get('request_params', {}) or {}
        return params.get('bucketName', '')

    def _extract_role(self, ev):
        params = ev.get('request_params', {}) or {}
        role_arn = params.get('roleArn', '')
        if role_arn:
            return role_arn.split('/')[-1]
        return ''