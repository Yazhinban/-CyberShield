import unittest
from datetime import date
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from database.db import Base
from database.models import Asset, Threat, Vulnerability, Risk, RiskTreatment, AssessmentHistory
from services.risk_engine import assess
from services.recommendation_engine import recommend
from utils.pdf_generator import make_pdf

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session=sessionmaker(self.engine,expire_on_commit=False)
    def tearDown(self): self.engine.dispose()

    def test_assess_treat_reassess_and_report(self):
        with self.Session() as s:
            asset=Asset(name="Student Records",asset_type="Database",owner="IT")
            threat=Threat(name="Unauthorized Data Access",category="Unauthorized Access")
            s.add_all([asset,threat]); s.flush()
            vuln=Vulnerability(name="Weak Password Policy",asset_id=asset.id,category="Access Control")
            s.add(vuln); s.flush()
            initial=assess(4,5)
            risk=Risk(asset_id=asset.id,threat_id=threat.id,vulnerability_id=vuln.id,likelihood=4,impact=5,residual_likelihood=4,residual_impact=5,owner="IT",status="Treatment Planned",explanation=initial["explanation"])
            s.add(risk); s.flush()
            risk.history.append(AssessmentHistory(likelihood=4,impact=5,notes="Initial assessment"))
            risk.treatment=RiskTreatment(strategy="Risk Mitigation",activities="Enable MFA",owner="IT",deadline=date.today(),implementation_status="In Progress")
            risk.residual_likelihood=2; risk.residual_impact=4
            risk.history.append(AssessmentHistory(likelihood=2,impact=4,residual=True,notes="MFA enabled"))
            s.commit()
            self.assertEqual((risk.inherent_score,risk.residual_score),(20,8))
            self.assertIn("Enable multi-factor authentication",recommend(threat.name,vuln.name)[1])
            pdf=make_pdf("Example Organization",[asset],[risk],[risk.treatment])
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertEqual(len(s.scalars(select(AssessmentHistory)).all()),2)

if __name__=="__main__": unittest.main()
