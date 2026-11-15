import pandas as pd
from services.risk_engine import classify

def risk_rows(risks):
    return [{"Risk ID": f"RSK-{r.id:04d}", "Asset": r.asset.name, "Threat": r.threat.name, "Vulnerability": r.vulnerability.name,
             "Likelihood": r.likelihood, "Impact": r.impact, "Score": r.inherent_score, "Level": classify(r.inherent_score),
             "Residual Score": r.residual_score, "Owner": r.owner, "Status": r.status, "Date Identified": r.identified_at.strftime("%Y-%m-%d")} for r in risks]

def risk_dataframe(risks): return pd.DataFrame(risk_rows(risks))
