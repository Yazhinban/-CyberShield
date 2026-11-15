from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DATABASE_URL = f"sqlite:///{(DATA_DIR / 'cybershield.db').as_posix()}"
APP_NAME = "CyberShield"
RISK_LEVELS = ((4, "Low"), (9, "Medium"), (16, "High"), (25, "Critical"))
LIKELIHOOD_LABELS = {1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely", 5: "Almost Certain"}
IMPACT_LABELS = {1: "Negligible", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Severe"}
ASSET_TYPES = ["Server", "Database", "Website", "Network Device", "Endpoint", "Cloud Infrastructure", "Application", "Other"]
THREAT_CATEGORIES = ["Malware", "Ransomware", "Phishing", "Insider Threat", "Unauthorized Access", "Data Breach", "Denial of Service", "Social Engineering", "Network Attacks", "Physical Threats", "Other"]
VULNERABILITY_CATEGORIES = ["Access Control", "Configuration", "Software/Patching", "Data Protection", "Network Security", "Human Factors", "Other"]
RISK_STATUSES = ["Identified", "Under Assessment", "Treatment Planned", "In Progress", "Resolved", "Accepted"]
TREATMENT_STRATEGIES = ["Risk Avoidance", "Risk Mitigation", "Risk Transfer", "Risk Acceptance"]
