import unittest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from database.db import Base
from database import models  # ensures model registration

class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session=sessionmaker(self.engine,expire_on_commit=False)
    def tearDown(self): self.engine.dispose()
    def test_relations_persist_and_foreign_keys_are_structured(self):
        from database.models import Asset, Threat, Vulnerability, Risk, RiskTreatment
        with self.Session() as s:
            a=Asset(name="Demo",asset_type="Server"); t=Threat(name="Phishing",category="Phishing"); s.add_all([a,t]); s.flush()
            v=Vulnerability(name="Weak MFA",asset_id=a.id,category="Access Control"); s.add(v); s.flush()
            r=Risk(asset_id=a.id,threat_id=t.id,vulnerability_id=v.id,likelihood=4,impact=5,residual_likelihood=2,residual_impact=3); s.add(r); s.flush()
            r.treatment=RiskTreatment(strategy="Risk Mitigation",activities="Enable MFA")
            s.commit(); rid=r.id
        with self.Session() as s:
            r=s.get(Risk,rid)
            self.assertEqual((r.inherent_score,r.residual_score),(20,6))
            self.assertEqual(r.asset.name,"Demo")
            self.assertEqual(r.treatment.activities,"Enable MFA")

if __name__=="__main__": unittest.main()
