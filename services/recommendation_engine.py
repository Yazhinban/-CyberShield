RULES = {
    "weak password": ["Enforce a strong password policy", "Enable multi-factor authentication", "Configure account lockout and suspicious login alerts"],
    "outdated": ["Apply supported security patches", "Establish a patch management schedule", "Track software versions and end-of-life dates"],
    "phishing": ["Provide targeted security awareness training", "Enable email filtering and attachment scanning", "Establish a simple incident reporting process"],
    "firewall": ["Review and minimize exposed services", "Document firewall rule owners and expiry dates", "Monitor network access logs"],
    "privilege": ["Apply least privilege", "Review privileged accounts quarterly", "Log and alert on administrative actions"],
    "encrypt": ["Encrypt sensitive data at rest and in transit", "Protect and rotate encryption keys", "Verify backups can be restored"],
    "ransomware": ["Maintain isolated, tested backups", "Patch exposed systems promptly", "Prepare and rehearse incident response procedures"],
    "mfa": ["Enable MFA for remote and privileged access", "Remove stale accounts", "Review authentication logs for unusual activity"],
}
def recommend(threat: str, vulnerability: str, category: str = "") -> list[str]:
    text = f"{threat} {vulnerability} {category}".lower()
    matched = []
    for key, items in RULES.items():
        if key in text: matched.extend(items)
    return list(dict.fromkeys(matched)) or ["Confirm ownership and scope of the exposure", "Apply defense-in-depth controls appropriate to this asset", "Monitor for exploitation and review this risk after treatment"]
