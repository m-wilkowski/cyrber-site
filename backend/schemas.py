"""Pydantic request/response models for CYRBER API."""

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    email: str = None
    notes: str = None


class UserUpdate(BaseModel):
    role: str = None
    email: str = None
    is_active: bool = None
    notes: str = None


class PasswordReset(BaseModel):
    new_password: str


class LicenseActivateRequest(BaseModel):
    key: str


class ScanStartRequest(BaseModel):
    target: str
    profile: str = "STRAZNIK"


class OsintStartRequest(BaseModel):
    target: str
    search_type: str = "domain"


class ScheduleCreate(BaseModel):
    target: str
    interval_hours: int


class PhishingCampaignCreate(BaseModel):
    name: str
    domain: str
    subject: str
    email_body: str
    landing_url: str = ""
    targets: list[str]


class PhishingEmailGenerate(BaseModel):
    target: str
    risk_level: str = ""
    risk_score: int = 0
    technologies: list[str] = []
    emails: list[str] = []
    vulnerabilities: list[str] = []
    executive_summary: str = ""
    language: str = "pl"


class GarakScanRequest(BaseModel):
    target_type: str = "openai"
    target_name: str = "gpt-4"
    probes: str = "encoding,dan,promptinject"
    probe_tags: str = ""
    generations: int = 3
    api_key: str = ""
    api_base: str = ""


class BeefRunModule(BaseModel):
    session: str
    module_id: str
    options: dict = {}


class EvilginxLureCreate(BaseModel):
    phishlet: str
    redirect_url: str = ""
    path: str = ""


class VerifyRequest(BaseModel):
    query: str
    type: str = "AUTO"     # url / email / company / AUTO
    country: str = "AUTO"  # PL / UK / AUTO


class MultiTargetScan(BaseModel):
    targets: list[str]
    profile: str = "STRAZNIK"


class ExplainFindingRequest(BaseModel):
    finding_name: str
    finding_description: str = ""
    target: str = ""
    severity: str = ""


class ScanAgentRequest(BaseModel):
    task_id: str
    message: str
    history: list = []


class RemediationCreate(BaseModel):
    finding_name: str
    finding_severity: str
    finding_module: str | None = None
    owner: str | None = None
    deadline: str | None = None
    notes: str | None = None


class RemediationUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    deadline: str | None = None
    notes: str | None = None


class RemediationBulk(BaseModel):
    findings: list[dict]
