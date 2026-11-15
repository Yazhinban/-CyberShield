import unittest
from services.risk_engine import assess, classify

class RiskEngineTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual([classify(n) for n in (1,4,5,9,10,16,17,25)], ["Low","Low","Medium","Medium","High","High","Critical","Critical"])
    def test_demo_workflow_score(self):
        result=assess(4,5)
        self.assertEqual((result["score"],result["level"],result["priority"]),(20,"Critical","Immediate"))
    def test_invalid_scale_rejected(self):
        for pair in ((0,1),(1,6),(3,-1)):
            with self.assertRaises(ValueError): assess(*pair)

if __name__=="__main__": unittest.main()
