# CyberShield

CyberShield is a local, web-based cybersecurity risk assessment and treatment portal for the 21CSC308T Security Risk Management Principles academic project. It provides a persistent SQLite asset and risk register, transparent 5×5 scoring, treatment tracking, analytics, CSV export, and PDF reports. Mitigation suggestions are generated with a deterministic rule-based engine; no external AI service or vulnerability scanner is used.

## Run on Windows

1. Install Python 3.10 or later and open PowerShell in this folder.
2. (Recommended) Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies and launch:

   ```powershell
   python -m pip install -r requirements.txt
   streamlit run app.py
   ```

The database is created automatically at `data/cybershield.db` on first launch. `python -m database.init_db` can also initialize it separately. The database file is persistent; back up the `data` directory to preserve records.

## Workflow

Register an asset, a threat, and a vulnerability associated with the asset. Create a risk assessment by selecting all three and assigning likelihood and impact (1–5). Inherent risk is likelihood × impact: 1–4 Low, 5–9 Medium, 10–16 High, and 17–25 Critical. The treatment page records a strategy, actions, owner, deadline, expected outcomes, and a separately stored residual likelihood and impact. Risk resolution is always an explicit status change.

Use **Settings → Load sample demonstration data** for fictional presentation records. Those records are marked as demo data and can be removed from the same page. CSV exports are available in the risk register and report page. The PDF includes organization name, date, summary counts, risk register, and treatment plans.

## Modules

Dashboard · Asset Management · Threat Management · Vulnerability Assessment · Risk Assessment · Risk Register · Risk Treatment · Reports & Analytics · Settings.

## Tests

Run `python -m unittest discover -s tests`. Tests use an isolated in-memory SQLite database and do not touch the local application database.

## Scope and security notes

This is a single-user local academic application, not a hosted multi-user system. It records vulnerabilities provided by the user and does not scan systems. Database access uses SQLAlchemy parameterized operations. Do not store secrets or highly sensitive production data in this demonstration application.
