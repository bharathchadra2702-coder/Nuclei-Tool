def calculate_score(severity_counts, max_score=3.0):
    """
    Computes final evaluation score and assigns a letter grade.
    Standard Hackathon scoring weights:
    - Critical vulnerability: 1.5 marks penalty
    - High vulnerability: 1.0 marks penalty
    - Medium vulnerability: 0.5 marks penalty
    - Low vulnerability: 0.2 marks penalty
    """
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)

    # Scale deductions if max_score is e.g. 10.0 or 100
    scale = max_score / 3.0
    deduction = (crit * 1.5 + high * 1.0 + med * 0.5 + low * 0.2) * scale
    final_score = max(0.0, round(max_score - deduction, 2))

    percentage = (final_score / max_score) * 100.0 if max_score > 0 else 0.0

    if percentage >= 90:
        grade = "A+"
    elif percentage >= 75:
        grade = "A"
    elif percentage >= 60:
        grade = "B"
    elif percentage >= 45:
        grade = "C"
    else:
        grade = "F"

    return final_score, grade
