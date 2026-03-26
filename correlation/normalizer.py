from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class EventNormalizer:
    def normalize(self, raw_events):
        #cleans/normalises the raw event logs we got from cloudtrail to actually utilise the data
        normalized = []
        for event in raw_events:
            try:
                normalized_event = self._normalize_single(event)
                if normalized_event:
                    normalized.append(normalized_event)
            except Exception as e:
                logger.debug(f'could not normalize event: {e}')
                continue
        return normalized

    def _normalize_single(self, event):
        # function to normalize a single event log and append in the final dictionary
        #extracting the actor identity who made the call
        identity = event.get('userIdentity',{})
        actor = self._extract_actor(identity)

        #extract the API call
        api_call = event.get('eventName', '')
        service = event.get('eventSource', '').replace('.amazonaws.com', '')

        #extract source IP
        source_ip = event.get('sourceIPAddress', 'unknown')

        #extract TimeStamp
        event_time_str = event.get('eventTime', '')
        event_time = datetime.fromisoformat (
            event_time_str.replace('Z', '+00:00')
        ) if event_time_str else None

        if not api_call or not event_time:
            return None
        
        #extract Resource Info
        resources = event.get('resources', [])
        request_params = event.get('requestParameters',{}) or {}

        return {
            'event_id': event.get('eventID', ''),
            'timestamp': event_time,
            'api_call': api_call,
            'service': service,
            'actor': actor,
            'source_ip': source_ip,
            'region': event.get('awsRegion', ''),
            'resources': resources,
            'request_params': request_params,
            'user_agent': event.get('userAgent', ''),
            'error_code': event.get('errorCode', None),
            'raw': event
        }
    def _extract_actor(self, identity):
        #extracting the actor identifier from useridentity
        id_type = identity.get('type', '')
        if id_type == 'IAMUser':
            return identity.get('userName', 'unknown-iam-user')
        elif id_type == 'AssumedRole':
            arn = identity.get('arn', '')
            # arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION
            parts = arn.split('/')
            return f'assumed-role/{parts[1]}' if len(parts) > 1 else arn

        elif id_type =='Root':
            return 'ROOT'
        else:
            return identity.get('arn', identity.get('principalId', 'unknown'))
