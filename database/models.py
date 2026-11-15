from datetime import datetime, date
from sqlalchemy import String, Text, Integer, DateTime, Date, ForeignKey, Boolean, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database.db import Base

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    location: Mapped[str] = mapped_column(String(120), default="")
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    confidentiality: Mapped[int] = mapped_column(Integer, default=3)
    integrity: Mapped[int] = mapped_column(Integer, default=3)
    availability: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    risks: Mapped[list["Risk"]] = relationship(back_populates="asset")

class Threat(Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(120), default="Unknown")
    potential_impact: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(40), default="Active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    risks: Mapped[list["Risk"]] = relationship(back_populates="threat")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), default="Medium")
    existing_controls: Mapped[str] = mapped_column(Text, default="")
    recommended_controls: Mapped[str] = mapped_column(Text, default="")
    discovery_date: Mapped[date] = mapped_column(Date, default=date.today)
    status: Mapped[str] = mapped_column(String(40), default="Open")
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    asset: Mapped[Asset] = relationship(back_populates="vulnerabilities")
    risks: Mapped[list["Risk"]] = relationship(back_populates="vulnerability")

class Risk(Base):
    __tablename__ = "risks"
    __table_args__ = (CheckConstraint("likelihood BETWEEN 1 AND 5"), CheckConstraint("impact BETWEEN 1 AND 5"), CheckConstraint("residual_likelihood BETWEEN 1 AND 5"), CheckConstraint("residual_impact BETWEEN 1 AND 5"))
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False)
    threat_id: Mapped[int] = mapped_column(ForeignKey("threats.id", ondelete="RESTRICT"), nullable=False)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    residual_likelihood: Mapped[int] = mapped_column(Integer, default=1)
    residual_impact: Mapped[int] = mapped_column(Integer, default=1)
    owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    status: Mapped[str] = mapped_column(String(40), default="Identified")
    identified_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    explanation: Mapped[str] = mapped_column(Text, default="")
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    asset: Mapped[Asset] = relationship(back_populates="risks")
    threat: Mapped[Threat] = relationship(back_populates="risks")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="risks")
    treatment: Mapped["RiskTreatment"] = relationship(back_populates="risk", cascade="all, delete-orphan", uselist=False)
    history: Mapped[list["AssessmentHistory"]] = relationship(back_populates="risk", cascade="all, delete-orphan")
    @property
    def inherent_score(self): return self.likelihood * self.impact
    @property
    def residual_score(self): return self.residual_likelihood * self.residual_impact

class RiskTreatment(Base):
    __tablename__ = "risk_treatments"
    id: Mapped[int] = mapped_column(primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id", ondelete="CASCADE"), unique=True)
    strategy: Mapped[str] = mapped_column(String(40), default="Risk Mitigation")
    activities: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    deadline: Mapped[date | None] = mapped_column(Date, nullable=True)
    expected_outcomes: Mapped[str] = mapped_column(Text, default="")
    implementation_status: Mapped[str] = mapped_column(String(40), default="Pending")
    completion_details: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    risk: Mapped[Risk] = relationship(back_populates="treatment")
    actions: Mapped[list["MitigationAction"]] = relationship(back_populates="treatment", cascade="all, delete-orphan")

class MitigationAction(Base):
    __tablename__ = "mitigation_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    treatment_id: Mapped[int] = mapped_column(ForeignKey("risk_treatments.id", ondelete="CASCADE"))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(120), default="Unassigned")
    deadline: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="Pending")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    treatment: Mapped[RiskTreatment] = relationship(back_populates="actions")

class AssessmentHistory(Base):
    __tablename__ = "assessment_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id", ondelete="CASCADE"))
    likelihood: Mapped[int] = mapped_column(Integer)
    impact: Mapped[int] = mapped_column(Integer)
    residual: Mapped[bool] = mapped_column(Boolean, default=False)
    assessed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    notes: Mapped[str] = mapped_column(Text, default="")
    risk: Mapped[Risk] = relationship(back_populates="history")

class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
