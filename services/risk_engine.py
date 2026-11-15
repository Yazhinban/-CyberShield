def classify(score: int) -> str:
    if not 1 <= int(score) <= 25: raise ValueError("Risk score must be between 1 and 25")
    return "Low" if score <= 4 else "Medium" if score <= 9 else "High" if score <= 16 else "Critical"

def assess(likelihood: int, impact: int) -> dict:
    if likelihood not in range(1, 6) or impact not in range(1, 6): raise ValueError("Likelihood and impact must be between 1 and 5")
    score = likelihood * impact
    level = classify(score)
    priority = {"Critical": "Immediate", "High": "High", "Medium": "Planned", "Low": "Routine"}[level]
    return {"score": score, "level": level, "priority": priority, "explanation": f"Likelihood {likelihood} × impact {impact} = {score}/25 ({level})."}
