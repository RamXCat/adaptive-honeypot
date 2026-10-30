from enum import Enum

class ArtifactCategory(str, Enum):
    AWS_CREDENTIALS          = "aws_credentials"
    SSH_PRIVATE_KEY          = "ssh_private_key"
    APP_CONFIG_FILE          = "app_config_file"
    DATABASE_CREDENTIALS     = "database_credentials"
    DECOY_DIRECTORY          = "decoy_directory"
    VULNERABLE_SERVICE_BANNER = "vulnerable_service_banner"
    MALWARE_C2_INFRASTRUCTURE = "malware_c2_infrastructure"
