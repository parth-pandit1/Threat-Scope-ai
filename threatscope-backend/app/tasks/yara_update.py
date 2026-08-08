"""
Scheduled task to update YARA rules weekly.
"""
import logging
from app.analysis.yara_manager import update_rules

logger = logging.getLogger(__name__)

def update_yara_rules_task():
    """
    Scheduled task to pull the latest Yara rules,
    recompile them, and update the atomic yarc file.
    """
    logger.info("Starting scheduled yara rules update...")
    try:
        update_rules()
        logger.info("Finished scheduled yara rules update.")
    except Exception as e:
        logger.error(f"Error in scheduled yara rules update: {e}")
