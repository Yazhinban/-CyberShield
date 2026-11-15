from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch
from services.analytics import risk_rows
from services.risk_engine import classify

def make_pdf(org, assets, risks, treatments):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter), rightMargin=0.45*inch, leftMargin=0.45*inch)
    styles = getSampleStyleSheet(); story = [Paragraph("CyberShield Risk Assessment", styles["Title"]), Paragraph(org, styles["Heading2"]), Paragraph("Assessment date: " + __import__("datetime").date.today().isoformat(), styles["Normal"]), Spacer(1, 14)]
    counts = {level: sum(classify(r.inherent_score) == level for r in risks) for level in ("Critical", "High", "Medium", "Low")}
    story.append(Paragraph(f"Assets: {len(assets)} &nbsp;&nbsp; Risks: {len(risks)} &nbsp;&nbsp; Critical: {counts['Critical']} &nbsp;&nbsp; High: {counts['High']} &nbsp;&nbsp; Medium: {counts['Medium']} &nbsp;&nbsp; Low: {counts['Low']}", styles["Heading3"]))
    story.append(Paragraph("Assessment summary", styles["Heading2"]))
    summary = "Immediate attention is recommended for critical risks. Risk scores show inherent exposure before treatment. Residual scores reflect the latest reassessment entered by the risk owner. Recommendations are rule-based and should be reviewed by the organization."
    story.extend([Paragraph(summary, styles["BodyText"]), Spacer(1, 12), Paragraph("Risk Register", styles["Heading2"])])
    data = [["ID", "Asset", "Threat", "Vulnerability", "L", "I", "Score", "Level", "Residual", "Owner", "Status"]]
    for row in risk_rows(risks): data.append([row[k] for k in ("Risk ID", "Asset", "Threat", "Vulnerability", "Likelihood", "Impact", "Score", "Level", "Residual Score", "Owner", "Status")])
    table = Table(data, repeatRows=1, colWidths=[0.65*inch,1.05*inch,1.1*inch,1.15*inch,0.28*inch,0.28*inch,0.42*inch,0.62*inch,0.55*inch,0.8*inch,0.8*inch])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172033")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.grey),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#eff4fa")])]))
    story.append(table)
    story.extend([Spacer(1, 12), Paragraph("Treatment plans", styles["Heading2"])])
    td = [["Risk", "Strategy", "Activities", "Owner", "Deadline", "Status"]]
    for r in risks:
        if r.treatment:
            t=r.treatment; td.append([f"RSK-{r.id:04d}", t.strategy, t.activities, t.owner, t.deadline.isoformat() if t.deadline else "—", t.implementation_status])
    story.append(Table(td, repeatRows=1, colWidths=[0.7*inch,1.0*inch,4.2*inch,1.2*inch,0.85*inch,0.9*inch], style=TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172033")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.35,colors.grey),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP")])))
    def footer(canvas, document):
        canvas.saveState(); canvas.setFont("Helvetica",8); canvas.drawRightString(10.5*inch,0.3*inch,f"CyberShield • Page {document.page}"); canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
