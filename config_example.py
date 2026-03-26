AWS_REGION = 'ap-south-1'
CLOUDTRAIL_LOG_GROUP = 'aws-cloudtrail-logs-group-name'

ATTACKER_IAM_USER = 'compromised-dev-user'
PRIVILEGED_ROLE_NAME = 'your-privileged-role'
TARGET_BUCKET = 'target-bucket-name'
ACCOUNT_ID = '12-digit-account-ID'

CORRELATION_WINDOW_MINUTES = 15
MIN_RECON_CALLS = 3
DB_PATH = 'db/events.db'
ALERT_OUTPUT_PATH = 'output/alerts.json'

RECON_API_CALLS = [
    'ListUsers', 'ListRoles', 'ListPolicies',
    'ListGroups', 'ListAttachedRolePolicies',
    'GetAccountAuthorizationDetails', 'ListAccessKeys'
]

PRIVESC_API_CALLS = ['AssumeRole', 'AssumeRoleWithWebIdentity']

EXFIL_API_CALLS = ['GetObject', 'ListObjects', 'ListObjectsV2',
                   'GetObjectAcl', 'HeadObject']
