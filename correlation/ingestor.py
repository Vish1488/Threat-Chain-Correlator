import boto3
import json
import logging
from datetime import datetime, timedelta, timezone
from config import AWS_REGION, CLOUDTRAIL_LOG_GROUP

logger = logging.getLogger(__name__)

class CloudTrailIngestor:
    def __init__(self):
        self.client = boto3.client('logs',region_name=AWS_REGION)
        self.log_group = CLOUDTRAIL_LOG_GROUP
    
    def fetch_events(self,minutes_back = 20):
        #fetch events from cloudtrail from 20 mins back
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes_back)

        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)

        events = []
        try:
            paginator = self.client.get_paginator('filter_log_events')
            pages = paginator.paginate(
                logGroupName = self.log_group,
                startTime = start_ms,
                endTime = end_ms
            )
            for page in pages:
                for event in page.get('events',[]):
                    try:
                        record = json.loads(event['message'])
                        #
                        if 'Records' in record:
                            events.extend(record['Records'])
                        else:
                            events.append(record)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f'Error fetching CloudTrail events: {e}')
            raise

        logger.info(f'Fetched {len(events)} CloudTrail events')
        return events

