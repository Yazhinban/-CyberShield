from datetime import date, datetime
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from config import APP_NAME, ASSET_TYPES, THREAT_CATEGORIES, VULNERABILITY_CATEGORIES, RISK_STATUSES, TREATMENT_STRATEGIES, LIKELIHOOD_LABELS, IMPACT_LABELS
from database.db import init_db, get_session
from database.models import Asset, Threat, Vulnerability, Risk, RiskTreatment, AssessmentHistory, Setting
from services.risk_engine import assess, classify
from services.recommendation_engine import recommend
from services.analytics import risk_dataframe
from utils.pdf_generator import make_pdf

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
init_db()
st.markdown(Path(__file__).parent.joinpath("assets/styles.css").read_text(encoding="utf-8"), unsafe_allow_html=True)
NAV = ["Dashboard", "Asset Management", "Threat Management", "Vulnerability Assessment", "Risk Assessment", "Risk Register", "Risk Treatment", "Reports & Analytics", "Settings"]

def get_setting(s, key, default=""):
    item=s.get(Setting,key)
    return item.value if item else default

def save_setting(s,key,value):
    item=s.get(Setting,key)
    if item: item.value=str(value)
    else: s.add(Setting(key=key,value=str(value)))
    s.commit()

def records(s, cls): return list(s.scalars(select(cls).order_by(cls.id.desc())).all())
def risk_label(r): return classify(r.inherent_score)
def show_risk_table(risks):
    df=risk_dataframe(risks)
    if df.empty: st.info("No risk records yet. Create an assessment to populate the register.")
    else: st.dataframe(df, use_container_width=True, hide_index=True)
def asset_selector(assets, label="Asset"):
    if not assets: st.warning("Add an asset before continuing."); return None
    return st.selectbox(label,assets,format_func=lambda x:f"AST-{x.id:04d} · {x.name}",key=label)
def status_tag(level):
    color={"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#22c55e"}.get(level,"#06b6d4")
    st.markdown(f"<span style='background:{color}22;color:{color};padding:4px 10px;border-radius:99px;font-weight:700'>{level}</span>",unsafe_allow_html=True)

with get_session() as s:
    org=get_setting(s,"organization","CyberShield Demo Organization")
    with st.sidebar:
        st.markdown("# 🛡️ CyberShield")
        st.caption("AI-assisted risk management · Rule-based recommendations")
        page=st.radio("Workspace",NAV,label_visibility="collapsed")
        st.divider(); st.caption(f"Organization\n**{org}**")
        st.caption("Local SQLite · Data persists on this device")
    st.title(page)
    if page=="Dashboard":
        assets=records(s,Asset); threats=records(s,Threat); vulns=records(s,Vulnerability); risks=records(s,Risk)
        levels=[risk_label(r) for r in risks]; resolved=sum(r.status=="Resolved" for r in risks); resolution=round(100*resolved/len(risks),1) if risks else 0
        cols=st.columns(6)
        for col,label,val in zip(cols,["Assets","Threats","Vulnerabilities","Assessed Risks","Critical Risks","Resolution Rate"],[len(assets),len(threats),len(vulns),len(risks),levels.count("Critical"),f"{resolution}%"]): col.metric(label,val)
        st.markdown(" ")
        c1,c2=st.columns([1,1])
        with c1:
            st.subheader("Risk distribution")
            counts=pd.Series(levels).value_counts().reindex(["Critical","High","Medium","Low"],fill_value=0).rename_axis("Severity").reset_index(name="Risks")
            fig=px.pie(counts,names="Severity",values="Risks",hole=.58,color="Severity",color_discrete_map={"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#22c55e"})
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#dce7f5",margin=dict(t=15,b=15,l=15,r=15),legend_title="")
            st.plotly_chart(fig,use_container_width=True)
        with c2:
            st.subheader("Risk treatment status")
            statuses=pd.Series([r.status for r in risks]).value_counts().rename_axis("Status").reset_index(name="Risks")
            st.plotly_chart(px.bar(statuses,x="Status",y="Risks",color="Status",color_discrete_sequence=["#06b6d4"]),use_container_width=True)
        st.subheader("Risk identification trend")
        if risks:
            trend=pd.DataFrame([{"Date":r.identified_at.date(),"Risk ID":r.id} for r in risks]).groupby("Date").size().rename("New risks").reset_index()
            trend=trend.sort_values("Date"); trend["Cumulative risks"]=trend["New risks"].cumsum()
            st.plotly_chart(px.line(trend,x="Date",y="Cumulative risks",markers=True),use_container_width=True)
        else: st.info("Trend data will appear after risks have been assessed.")
        c3,c4=st.columns(2)
        with c3:
            st.subheader("Risk heatmap · likelihood × impact")
            z=[[i*j for i in range(1,6)] for j in range(5,0,-1)]
            fig=go.Figure(go.Heatmap(z=z,x=["1 Rare","2 Unlikely","3 Possible","4 Likely","5 Almost Certain"],y=["5 Severe","4 Major","3 Moderate","2 Minor","1 Negligible"],text=[[f"{i*j}<br>{classify(i*j)}" for i in range(1,6)] for j in range(5,0,-1)],texttemplate="%{text}",colorscale=[[0,"#22c55e"],[.32,"#f59e0b"],[.64,"#f97316"],[1,"#ef4444"]],showscale=False))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",font_color="#dce7f5",margin=dict(t=15,b=15))
            st.plotly_chart(fig,use_container_width=True)
        with c4:
            st.subheader("Risk by asset")
            data=pd.DataFrame([{"Asset":r.asset.name,"Score":r.inherent_score,"Level":risk_label(r)} for r in risks])
            if len(data): st.plotly_chart(px.bar(data,x="Asset",y="Score",color="Level",barmode="group",color_discrete_map={"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#22c55e"}),use_container_width=True)
            else: st.info("Risk by asset will appear after the first assessment.")
        st.subheader("Critical risks requiring attention")
        critical=[r for r in risks if risk_label(r)=="Critical" and r.status not in ("Resolved","Accepted")]
        show_risk_table(critical[:10])
        pending=[a for r in risks if r.treatment for a in r.treatment.actions if a.status not in ("Completed","Cancelled")]
        if pending: st.caption(f"{len(pending)} mitigation action(s) are pending.")

    elif page=="Asset Management":
        st.caption("Inventory organizational assets and their business criticality.")
        with st.expander("＋ Register an asset",expanded=not records(s,Asset)):
            with st.form("asset_new"):
                c1,c2=st.columns(2); name=c1.text_input("Asset name *"); typ=c2.selectbox("Asset type",ASSET_TYPES); owner=c1.text_input("Owner / Department"); location=c2.text_input("Location"); ip=c1.text_input("IP address (optional)"); crit=c2.slider("Criticality",1,5,3); desc=st.text_area("Description")
                submitted=st.form_submit_button("Save asset",type="primary")
                if submitted:
                    if not name.strip(): st.error("Asset name is required.")
                    else: s.add(Asset(name=name.strip(),asset_type=typ,owner=owner or "Unassigned",location=location,ip_address=ip,criticality=crit,description=desc)); s.commit(); st.success("Asset registered."); st.rerun()
        all_assets=records(s,Asset)
        f1,f2=st.columns(2); query=f1.text_input("Search assets",key="asset_search"); type_filter=f2.selectbox("Filter by type",["All"]+ASSET_TYPES,key="asset_type_filter")
        filtered=[a for a in all_assets if query.lower() in f"{a.name} {a.owner} {a.location}".lower() and (type_filter=="All" or a.asset_type==type_filter)]
        st.dataframe(pd.DataFrame([{"ID":f"AST-{a.id:04d}","Name":a.name,"Type":a.asset_type,"Owner":a.owner,"Location":a.location,"Criticality":a.criticality,"Added":a.created_at.strftime("%Y-%m-%d")} for a in filtered]),use_container_width=True,hide_index=True)
        if all_assets:
            with st.expander("Edit or remove asset"):
                selected=st.selectbox("Select asset",all_assets,format_func=lambda a:f"AST-{a.id:04d} · {a.name}")
                with st.form("asset_edit"):
                    nm=st.text_input("Asset name",selected.name); ow=st.text_input("Owner",selected.owner); loc=st.text_input("Location",selected.location); cr=st.slider("Criticality",1,5,selected.criticality); save=st.form_submit_button("Update asset")
                    if save: selected.name=nm.strip() or selected.name; selected.owner=ow; selected.location=loc; selected.criticality=cr; s.commit(); st.success("Asset updated."); st.rerun()
                if selected.risks: st.caption(f"This asset has {len(selected.risks)} risk record(s) and cannot be deleted until those records are removed.")
                elif st.checkbox("Confirm deletion of this asset",key=f"confirm_asset_{selected.id}"):
                    if st.button("Delete selected asset",key="asset_delete"): s.delete(selected); s.commit(); st.success("Asset deleted."); st.rerun()

    elif page=="Threat Management":
        with st.expander("＋ Register a threat",expanded=not records(s,Threat)):
            with st.form("threat_new"):
                c1,c2=st.columns(2); name=c1.text_input("Threat name *"); cat=c2.selectbox("Category",THREAT_CATEGORIES); source=c1.text_input("Threat source",placeholder="External actor, employee, environmental"); impact=c2.text_input("Potential impact",placeholder="Service disruption, data exposure..."); desc=st.text_area("Description"); sub=st.form_submit_button("Save threat",type="primary")
                if sub:
                    if not name.strip(): st.error("Threat name is required.")
                    else: s.add(Threat(name=name.strip(),category=cat,source=source or "Unknown",potential_impact=impact,description=desc)); s.commit(); st.success("Threat registered."); st.rerun()
        threats=records(s,Threat); q=st.text_input("Search threats")
        st.dataframe(pd.DataFrame([{"ID":f"THR-{t.id:04d}","Name":t.name,"Category":t.category,"Source":t.source,"Status":t.status,"Description":t.description} for t in threats if q.lower() in f"{t.name} {t.category} {t.source}".lower()]),use_container_width=True,hide_index=True)
        if threats:
            with st.expander("Update or delete threat"):
                t=st.selectbox("Threat",threats,format_func=lambda x:f"THR-{x.id:04d} · {x.name}"); t.status=st.selectbox("Status",["Active","Monitoring","Inactive"],index=["Active","Monitoring","Inactive"].index(t.status) if t.status in ["Active","Monitoring","Inactive"] else 0); s.commit()
                if t.risks: st.caption("Threat is linked to risks and cannot be deleted yet.")
                elif st.checkbox("Confirm deletion of this threat",key=f"confirm_threat_{t.id}"):
                    if st.button("Delete threat"): s.delete(t); s.commit(); st.rerun()

    elif page=="Vulnerability Assessment":
        assets=records(s,Asset)
        if not assets: st.info("Register an asset before recording a vulnerability.")
        else:
            with st.expander("＋ Record a vulnerability",expanded=not records(s,Vulnerability)):
                with st.form("vuln_new"):
                    c1,c2=st.columns(2); name=c1.text_input("Vulnerability name *"); asset=asset_selector(assets,"Affected asset"); cat=c2.selectbox("Category",VULNERABILITY_CATEGORIES); severity=c1.selectbox("Severity",["Critical","High","Medium","Low"]); status=c2.selectbox("Status",["Open","In Progress","Resolved","Accepted"]); desc=st.text_area("Description"); existing=st.text_input("Existing controls"); recommended=st.text_input("Recommended controls"); sub=st.form_submit_button("Save vulnerability",type="primary")
                    if sub:
                        if not name.strip() or not asset: st.error("Name and asset are required.")
                        else: s.add(Vulnerability(name=name.strip(),asset_id=asset.id,category=cat,severity=severity,status=status,description=desc,existing_controls=existing,recommended_controls=recommended)); s.commit(); st.success("Vulnerability recorded. CyberShield does not perform scanning."); st.rerun()
            vulns=records(s,Vulnerability); q=st.text_input("Search vulnerabilities")
            st.dataframe(pd.DataFrame([{"ID":f"VUL-{v.id:04d}","Name":v.name,"Asset":v.asset.name,"Category":v.category,"Severity":v.severity,"Status":v.status,"Discovered":v.discovery_date.isoformat()} for v in vulns if q.lower() in f"{v.name} {v.asset.name} {v.category}".lower()]),use_container_width=True,hide_index=True)
            if vulns:
                with st.expander("Update vulnerability status"):
                    v=st.selectbox("Vulnerability",vulns,format_func=lambda x:f"VUL-{x.id:04d} · {x.name}"); new_status=st.selectbox("Status",["Open","In Progress","Resolved","Accepted"],index=["Open","In Progress","Resolved","Accepted"].index(v.status));
                    new_name=st.text_input("Vulnerability name",v.name)
                    if st.button("Update vulnerability"): v.status=new_status; v.name=new_name.strip() or v.name; s.commit(); st.success("Vulnerability updated."); st.rerun()
                    if v.risks: st.caption("This vulnerability is linked to risk records and cannot be deleted yet.")
                    elif st.checkbox("Confirm deletion of this vulnerability",key=f"confirm_vuln_{v.id}"):
                        if st.button("Delete vulnerability",key="vuln_delete"): s.delete(v); s.commit(); st.success("Vulnerability deleted."); st.rerun()

    elif page=="Risk Assessment":
        assets=records(s,Asset); threats=records(s,Threat); vulns=records(s,Vulnerability)
        if not assets or not threats or not vulns: st.info("To assess a risk, register at least one asset, threat, and vulnerability first.")
        else:
            st.markdown("Select a scenario and score likelihood and impact. Inherent risk is calculated before treatment; residual risk is stored separately after reassessment.")
            with st.form("risk_assess"):
                c1,c2=st.columns(2); asset=asset_selector(assets,"Risk asset"); threat=c1.selectbox("Threat",threats,format_func=lambda x:f"THR-{x.id:04d} · {x.name}"); related=[v for v in vulns if v.asset_id==asset.id] if asset else vulns
                vuln=c2.selectbox("Vulnerability",related if related else vulns,format_func=lambda x:f"VUL-{x.id:04d} · {x.name}"); owner=c1.text_input("Risk owner",asset.owner if asset else "Unassigned"); status=c2.selectbox("Initial status",RISK_STATUSES); likelihood=c1.select_slider("Likelihood",options=list(LIKELIHOOD_LABELS),format_func=lambda x:f"{x} · {LIKELIHOOD_LABELS[x]}",value=3); impact=c2.select_slider("Impact",options=list(IMPACT_LABELS),format_func=lambda x:f"{x} · {IMPACT_LABELS[x]}")
                preview=assess(likelihood,impact); st.info(f"Inherent score: **{preview['score']}/25 · {preview['level']}** · Priority: **{preview['priority']}**. {preview['explanation']}")
                sub=st.form_submit_button("Create risk assessment",type="primary")
                if sub:
                    if vuln.asset_id!=asset.id: st.error("Choose a vulnerability that belongs to the selected asset.")
                    else:
                        r=Risk(asset_id=asset.id,threat_id=threat.id,vulnerability_id=vuln.id,likelihood=likelihood,impact=impact,residual_likelihood=likelihood,residual_impact=impact,owner=owner or "Unassigned",status=status,explanation=preview["explanation"])
                        s.add(r); s.flush(); s.add(AssessmentHistory(risk_id=r.id,likelihood=likelihood,impact=impact,residual=False,notes="Initial inherent assessment")); s.commit(); st.success(f"Created RSK-{r.id:04d} · {preview['level']}."); st.rerun()

    elif page=="Risk Register":
        risks=records(s,Risk)
        f1,f2,f3=st.columns([2,1,1]); q=f1.text_input("Search by asset, threat, vulnerability, owner or ID"); severity=f2.selectbox("Severity",["All","Critical","High","Medium","Low"]); status_filter=f3.selectbox("Treatment status",["All"]+RISK_STATUSES)
        filtered=[r for r in risks if q.lower() in f"RSK-{r.id:04d} {r.asset.name} {r.threat.name} {r.vulnerability.name} {r.owner}".lower() and (severity=="All" or risk_label(r)==severity) and (status_filter=="All" or r.status==status_filter)]
        filtered.sort(key=lambda r:r.inherent_score,reverse=True); show_risk_table(filtered)
        if risks:
            st.download_button("Export filtered risk register · CSV",risk_dataframe(filtered).to_csv(index=False).encode("utf-8-sig"),"cybershield_risk_register.csv","text/csv")
            with st.expander("View or update a risk"):
                r=st.selectbox("Risk record",risks,format_func=lambda x:f"RSK-{x.id:04d} · {x.asset.name} · {risk_label(x)} ({x.inherent_score})"); status=st.selectbox("Status",RISK_STATUSES,index=RISK_STATUSES.index(r.status)); owner=st.text_input("Risk owner",r.owner); ll=st.select_slider("Likelihood",options=[1,2,3,4,5],value=r.likelihood,key="edit_risk_l"); ii=st.select_slider("Impact",options=[1,2,3,4,5],value=r.impact,key="edit_risk_i")
                st.caption(f"Updated inherent score: {ll*ii}/25 · {classify(ll*ii)}")
                if st.button("Save risk changes"): r.status=status; r.owner=owner or "Unassigned"; r.likelihood=ll; r.impact=ii; r.explanation=assess(ll,ii)["explanation"]; s.add(AssessmentHistory(risk_id=r.id,likelihood=ll,impact=ii,residual=False,notes="Risk register reassessment")); s.commit(); st.success("Risk updated."); st.rerun()
                if st.checkbox("Confirm deletion of this risk record",key=f"confirm_risk_{r.id}"):
                    if st.button("Delete risk record",type="secondary"): s.delete(r); s.commit(); st.success("Risk record deleted."); st.rerun()

    elif page=="Risk Treatment":
        risks=records(s,Risk)
        if not risks: st.info("Create a risk assessment before planning treatment.")
        else:
            r=st.selectbox("Risk to treat",risks,format_func=lambda x:f"RSK-{x.id:04d} · {x.asset.name} · {risk_label(x)} ({x.inherent_score})")
            st.markdown(f"**Scenario:** {r.threat.name} affecting **{r.asset.name}** through {r.vulnerability.name}.")
            recs=recommend(r.threat.name,r.vulnerability.name,r.vulnerability.category)
            st.markdown("**Rule-based mitigation suggestions**")
            for item in recs: st.markdown(f"- {item}")
            t=r.treatment
            with st.form("treatment_plan"):
                c1,c2=st.columns(2); strategy=c1.selectbox("Treatment strategy",TREATMENT_STRATEGIES,index=TREATMENT_STRATEGIES.index(t.strategy) if t and t.strategy in TREATMENT_STRATEGIES else 1); owner=c2.text_input("Treatment owner",t.owner if t else r.owner); activities=st.text_area("Mitigation activities",t.activities if t else "\n".join(recs)); deadline=c1.date_input("Target deadline",t.deadline if t and t.deadline else date.today()); expected=c2.text_area("Expected outcome",t.expected_outcomes if t else "Reduce likelihood of exploitation and document evidence of implemented controls."); impl=c1.selectbox("Implementation status",["Pending","In Progress","Completed","Deferred"],index=["Pending","In Progress","Completed","Deferred"].index(t.implementation_status) if t and t.implementation_status in ["Pending","In Progress","Completed","Deferred"] else 0); details=c2.text_area("Completion details",t.completion_details if t else ""); sub=st.form_submit_button("Save treatment plan",type="primary")
                if sub:
                    if t is None: t=RiskTreatment(risk_id=r.id); s.add(t)
                    t.strategy=strategy; t.owner=owner or "Unassigned"; t.activities=activities; t.deadline=deadline; t.expected_outcomes=expected; t.implementation_status=impl; t.completion_details=details
                    if r.status not in ("Resolved","Accepted"): r.status="In Progress" if impl=="In Progress" else "Treatment Planned"
                    if impl=="Completed" and r.status=="Treatment Planned": r.status="In Progress"
                    s.commit(); st.success("Treatment plan saved. Risk resolution requires an explicit status update."); st.rerun()
            st.subheader("Residual risk reassessment")
            st.caption(f"Inherent risk remains {r.inherent_score}/25 · {risk_label(r)}. Residual score is updated only by reassessment.")
            with st.form("residual_form"):
                c1,c2=st.columns(2); rl=c1.select_slider("Residual likelihood",options=[1,2,3,4,5],value=r.residual_likelihood); ri=c2.select_slider("Residual impact",options=[1,2,3,4,5],value=r.residual_impact); note=st.text_input("Reassessment notes",placeholder="Evidence or control changes"); sub=st.form_submit_button("Save residual reassessment")
                if sub:
                    r.residual_likelihood=rl; r.residual_impact=ri; s.add(AssessmentHistory(risk_id=r.id,likelihood=rl,impact=ri,residual=True,notes=note)); s.commit(); st.success(f"Residual risk saved: {rl*ri}/25 · {classify(rl*ri)}."); st.rerun()
            if t:
                st.subheader("Mitigation action tracker")
                with st.form("action_add"):
                    desc=st.text_input("Add an action"); aowner=st.text_input("Action owner",t.owner); dline=st.date_input("Action deadline",date.today()); add=st.form_submit_button("Add action")
                    if add:
                        if desc.strip(): t.actions.append(__import__("database.models",fromlist=["MitigationAction"]).MitigationAction(description=desc.strip(),owner=aowner or "Unassigned",deadline=dline)); s.commit(); st.success("Action added."); st.rerun()
                if t.actions:
                    for a in t.actions:
                        ca,cb,cc=st.columns([4,2,1]); ca.write(f"**{a.description}** · {a.owner} · due {a.deadline or '—'} · {a.status}")
                        if a.status!="Completed" and cb.button("Mark complete",key=f"complete_{a.id}"): a.status="Completed"; a.completed_at=datetime.utcnow(); s.commit(); st.rerun()
                        if cc.button("Remove",key=f"remove_{a.id}"): s.delete(a); s.commit(); st.rerun()

    elif page=="Reports & Analytics":
        assets=records(s,Asset); risks=records(s,Risk); df=risk_dataframe(risks)
        st.subheader("Assessment summary")
        st.write(f"**Organization:** {org}  ·  **Assessment date:** {date.today().isoformat()}")
        levels=[risk_label(r) for r in risks]; c=st.columns(5)
        for col,label,val in zip(c,["Total assets","Total risks","Critical","High","Treatment planned"],[len(assets),len(risks),levels.count("Critical"),levels.count("High"),sum(bool(r.treatment) for r in risks)]): col.metric(label,val)
        dist=pd.Series(levels).value_counts().reindex(["Critical","High","Medium","Low"],fill_value=0).rename_axis("Risk level").reset_index(name="Count")
        st.plotly_chart(px.bar(dist,x="Risk level",y="Count",color="Risk level",color_discrete_map={"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#22c55e"}),use_container_width=True)
        show_risk_table(risks)
        st.download_button("Download risk register CSV",df.to_csv(index=False).encode("utf-8-sig"),"cybershield_risk_register.csv","text/csv",disabled=df.empty)
        st.download_button("Download assessment report PDF",make_pdf(org,assets,risks,[r.treatment for r in risks if r.treatment]),"cybershield_assessment_report.pdf","application/pdf")
        st.caption("The assessment summary uses stored records. Recommendations are transparent rule-based guidance and should be reviewed by qualified organizational stakeholders.")

    elif page=="Settings":
        st.subheader("Organization settings")
        with st.form("settings_form"):
            name=st.text_input("Organization / Project name",org); save=st.form_submit_button("Save settings",type="primary")
            if save: save_setting(s,"organization",name.strip() or "CyberShield Organization"); st.success("Settings saved."); st.rerun()
        st.subheader("Risk scoring configuration")
        st.markdown("Risk score = likelihood × impact. Scores 1–4 Low · 5–9 Medium · 10–16 High · 17–25 Critical. Both scales use a transparent 1–5 ordinal rating.")
        st.subheader("Database information")
        st.write(f"SQLite database: `{Path(__file__).parent / 'data' / 'cybershield.db'}`")
        st.write("Records are stored locally. Keep a backup of the data folder when moving or reinstalling the application.")
        st.subheader("Demonstration data")
        st.caption("Fictional records are marked as demonstration data. Load them for a presentation, or remove all demo records here.")
        if st.button("Load sample demonstration data"):
            if any(a.demo for a in records(s,Asset)): st.warning("Demo data is already present.")
            else:
                a1=Asset(name="Student Records Database",asset_type="Database",description="Fictional academic records platform",owner="IT Operations",location="Primary data center",criticality=5,confidentiality=5,integrity=5,availability=4,demo=True)
                a2=Asset(name="Public Admissions Portal",asset_type="Website",owner="Web Services",location="Cloud",criticality=4,confidentiality=3,integrity=4,availability=5,demo=True)
                th1=Threat(name="Unauthorized Data Access",category="Unauthorized Access",description="Account compromise could expose student records.",source="External actor",potential_impact="Privacy breach and regulatory response",demo=True)
                th2=Threat(name="Phishing",category="Phishing",description="Credential theft targeting staff accounts.",source="External actor",potential_impact="Account compromise and service disruption",demo=True)
                s.add_all([a1,a2,th1,th2]); s.flush()
                v1=Vulnerability(name="Weak Password Policy",description="Password requirements and MFA coverage need review.",asset_id=a1.id,category="Access Control",severity="High",recommended_controls="Strong passwords, MFA",demo=True)
                v2=Vulnerability(name="Outdated Software",description="Portal components may be outside the patch cycle.",asset_id=a2.id,category="Software/Patching",severity="Medium",recommended_controls="Patch management",demo=True)
                s.add_all([v1,v2]); s.flush()
                r1=Risk(asset_id=a1.id,threat_id=th1.id,vulnerability_id=v1.id,likelihood=4,impact=5,residual_likelihood=2,residual_impact=5,owner="IT Operations",status="Treatment Planned",explanation=assess(4,5)["explanation"],demo=True)
                r2=Risk(asset_id=a2.id,threat_id=th2.id,vulnerability_id=v2.id,likelihood=3,impact=4,residual_likelihood=2,residual_impact=4,owner="Web Services",status="Identified",explanation=assess(3,4)["explanation"],demo=True)
                s.add_all([r1,r2]); s.flush(); s.add_all([AssessmentHistory(risk_id=r1.id,likelihood=4,impact=5,notes="Demo baseline"),AssessmentHistory(risk_id=r2.id,likelihood=3,impact=4,notes="Demo baseline")]); s.add(RiskTreatment(risk_id=r1.id,strategy="Risk Mitigation",owner="IT Operations",activities="Enable MFA\nStrengthen password policy",deadline=date.today(),expected_outcomes="Reduce likelihood of account compromise",implementation_status="In Progress")); s.commit(); st.success("Sample data loaded."); st.rerun()
        demos=[r for r in records(s,Risk) if r.demo]
        if demos and st.button("Clear demonstration data",type="secondary"):
            for r in demos: s.delete(r)
            s.flush()
            for v in records(s,Vulnerability):
                if v.demo: s.delete(v)
            for t in records(s,Threat):
                if t.demo: s.delete(t)
            for a in records(s,Asset):
                if a.demo: s.delete(a)
            s.commit(); st.success("Demonstration records cleared."); st.rerun()
