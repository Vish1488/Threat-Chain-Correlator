import logging 
import sys
from correlation.ingestor import CloudTrailIngestor
from correlation.normalizer import EventNormalizer
from correlation.engine import CorrelationEngine
from correlation.alerter import Alerter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('main')

def run():
    logger.info('AWS Threat Chain Corelation starting...')
    ingestor = CloudTrailIngestor()
    normalizer = EventNormalizer()
    engine = CorrelationEngine()
    alerter = Alerter()

    #first, fetch the raw logs from cloudtrail
    logger.info('Fetching Cloudtrail events...')
    raw_events = ingestor.fetch_events(minutes_back=60)

    if not raw_events:
        logger.warning('No events fetched. Check cloudtrail config')
        sys.exit(0)
    
    #second, normalize the logs
    logger.info('Normalizing the logs')
    normalized = normalizer.normalize(raw_events)
    logger.info(f'Normalized {len(normalized)} events')

    #third, store the cleaned events in sqlite db
    engine.ingest(normalized)

    #next, run the threat chain detection logic
    logger.info('Running chain correlation....')
    detections = engine.detect_chains()
    logger.info(f'Found {len(detections)} attack chains')

    #lastly, generate an alert based on the detection
    alerter.process(detections)

if __name__ == '__main__':
    try:
        run()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()