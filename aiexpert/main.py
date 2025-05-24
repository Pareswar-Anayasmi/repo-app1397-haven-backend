import os
from dotenv import load_dotenv
import logging

env_path = os.environ.get('ENV_PATH') or ".env"
load_dotenv(env_path, override=True)

from .utils.configurations import DEFAULT_LOG_LEVEL, LOGGING_AZURE_MONITOR

log = logging.getLogger(__name__)

logging.basicConfig(
    level=DEFAULT_LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)


# save all env variables with suffix _LOG_LEVEL to variable logger_log_levels
logger_log_levels = {key: value for key, value in os.environ.items() if key.endswith("_LOG_LEVEL")}

# set log levels for all loggers
for key, value in logger_log_levels.items():
    # set logger name to variable "logger_name" 
    logger_name = key.replace("_LOG_LEVEL", "").lower().replace("__", ".")
    if logger_name != "default":
        logging.getLogger(logger_name).setLevel(value)
        log.info(f"Setting log level for {logger_name} to {value}")


# log all env variables
log.debug("Environment variables:")
for key, value in os.environ.items():

    if any(substring in key.lower() for substring in ["password", "secret", "token", "key", "connection_string"]):
        log.debug(f"{key}=********")
    else:
        log.debug(f"{key}={value}")

import time
if hasattr(time, 'tzset'):
    time.tzset()
else:
    log.warning("IMPORTANT: tzset() is not supported on this system.")

if LOGGING_AZURE_MONITOR:
    log.info("Enabling Azure Monitor for logging")
    from .azure import azure_monitor_logging

from .server import app

