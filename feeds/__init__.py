"""
feeds/__init__.py - Feed registry
All feed classes are registered here. The monitoring module iterates this registry.
"""
from feeds.malwarebazaar import MalwareBazaarFeed
from feeds.urlhaus       import URLHausFeed
from feeds.threatfox     import ThreatFoxFeed
from feeds.openphish     import OpenPhishFeed
from feeds.otx_feed      import OTXFeed
from feeds.feodo         import FeodoFeed
from feeds.abuseipdb_feed import AbuseIPDBFeed
from feeds.cisa_kev      import CISAKevFeed
from feeds.circl_cve     import CIRCLCVEFeed

# Registry: (feed_instance, interval_seconds)
# Interval is also stored in config.py for reference
import config

ALL_FEEDS = [
    (MalwareBazaarFeed(),  config.INTERVAL_MALWAREBAZAAR),
    (URLHausFeed(),        config.INTERVAL_URLHAUS),
    (ThreatFoxFeed(),      config.INTERVAL_THREATFOX),
    (OpenPhishFeed(),      config.INTERVAL_OPENPHISH),
    (OTXFeed(),            config.INTERVAL_OTX),
    (FeodoFeed(),          config.INTERVAL_FEODO),
    (AbuseIPDBFeed(),      config.INTERVAL_ABUSEIPDB),
    (CISAKevFeed(),        config.INTERVAL_CISA_KEV),
    (CIRCLCVEFeed(),       config.INTERVAL_CIRCL_CVE),
]

__all__ = ["ALL_FEEDS"]
