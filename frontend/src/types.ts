// Response shapes mirror the FastAPI Pydantic models (api/models.py and api/routes/*).

export interface AlertSummary {
  event_id: string;
  source: string;
  event_name: string;
  event_time: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  severity: number;
  risk_tier: string;
  actor_arn: string;
  region: string;
  status: string;
  remediation_action: string | null;
}

export interface AlertDetail extends AlertSummary {
  description: string;
  account_id: string;
  source_ip: string | null;
  modifiers: string[];
  stored_at: string | null;
  updated_at: string | null;
}

export interface AlertListResponse {
  alerts: AlertSummary[];
  total: number;
  filters_applied: Record<string, unknown>;
}

export interface RemediationResponse {
  event_id: string;
  decision: string;
  action: string | null;
  action_risk_tier: string | null;
  detail: string;
  executed_at: string;
}

export interface ScanResponse {
  alerts_found: number;
  scan_duration_seconds: number;
  lookback_minutes: number;
  message: string;
}

export interface ScanDispatchResponse {
  job_id: string;
  scan_run_id: string | null;
  status: string;
  account_count: number;
  message: string;
}

export interface HealthResponse {
  status: string;
}

export interface DeepHealthResponse {
  status: string;
  aws_account: string | null;
  aws_arn: string | null;
  region: string;
  guardduty_enabled: boolean;
  cloudtrail_accessible: boolean;
  model_loaded: boolean;
  remediation_enabled: boolean;
  storage_backend: string;
}

export interface TacticCoverage {
  tactic: string;
  technique_count: number;
  active_alerts: number;
}

export interface CoverageResponse {
  total_techniques_mapped: number;
  tactics: TacticCoverage[];
  uncovered_tactics: string[];
  active_alert_count: number;
}

export interface TokenResponse {
  access_token: string;
  token_type?: string;
  refresh_token?: string;
}

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  role: string;
  organization_id: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface AccountResponse {
  id: string;
  aws_account_id: string;
  display_name: string;
  role_arn: string;
  auto_remediation_role_arn: string | null;
  destructive_remediation_role_arn: string | null;
  primary_region: string;
  additional_regions: string[] | null;
  status: string;
  last_scan_at: string | null;
  last_error: string | null;
  guardduty_enabled: boolean;
  cloudtrail_enabled: boolean;
  created_at: string;
}

export interface SetupGuideResponse {
  aws_account_id: string;
  external_id: string;
  cg_aws_account_id: string;
  role_name: string;
  trust_policy: Record<string, unknown>;
  inline_policy_url: string;
  instructions: string[];
}

export interface CloudFormationTemplateResponse {
  aws_account_id: string;
  external_id: string;
  role_name: string;
  filename: string;
  template: Record<string, unknown>;
  console_create_stack_url: string;
}

export interface PlanInfo {
  tier: string;
  display_name: string;
  price_usd_monthly: number;
  max_aws_accounts: number;
  max_monthly_alerts: number;
  features: string[];
  stripe_price_id: string;
}

export interface SubscriptionResponse {
  plan: PlanInfo;
  stripe_customer_id: string | null;
  stripe_subscription_status: string | null;
  usage: Record<string, number>;
  publishable_key: string;
}

export interface AllPlansResponse {
  plans: PlanInfo[];
}

export interface CheckoutResponse {
  checkout_url: string;
  session_id: string;
}

export interface PortalResponse {
  portal_url: string;
}

export interface PlaybookObservation {
  id: string;
  outcome: string;
  was_autonomous: boolean;
  was_rolled_back: boolean;
  attack_severity: number | null;
  analyst_action: string | null;
  analyst_notes: string | null;
  created_at: string;
}

export interface PlaybookMemory {
  observations?: PlaybookObservation[];
  id: string;
  attack_fingerprint: string;
  fingerprint_description: string;
  fingerprint_features: Record<string, unknown> | null;
  technique_id: string;
  technique_name: string;
  tactic: string;
  event_name: string;
  risk_tier: string;
  learned_action: string;
  instance_count: number;
  successful_count: number;
  false_positive_count: number;
  rollback_count: number;
  analyst_agreement: number;
  confidence_score: number;
  trust_score: number;
  learning_threshold: number;
  observe_threshold: number;
  candidate_threshold: number;
  status: string;
  status_description: string;
  version: number;
  graduated_at: string | null;
  graduation_notes: string | null;
  last_executed_at: string | null;
  last_seen_at: string;
  validation_started_at: string | null;
  created_at: string;
}

export interface LearningSummary {
  total: number;
  observing: number;
  learning: number;
  candidate: number;
  pending_graduation: number;
  autonomous: number;
  continuous_validation: number;
  disabled: number;
  total_auto_executions: number;
  average_trust_score: number;
}

export interface LearningSettings {
  learning_threshold: number;
  observe_threshold: number;
  candidate_threshold: number;
  confidence_threshold: number;
  trust_threshold: number;
  lifecycle_stages: Record<string, string>;
}

export interface ApiErrorBody {
  detail?: string;
}

export interface ApiError extends Error {
  status?: number;
}

export interface ApproveMessage {
  ok: boolean;
  text: string;
}

export interface SimulatorScenario {
  id: string;
  name: string;
  description: string;
  expected_detection: boolean;
}

export interface SimulatorResult {
  scenario_id: string;
  scenario_name: string;
  event_name: string;
  expected_detection: boolean;
  detected: boolean;
  severity: number | null;
  expected_technique_id: string | null;
  actual_technique_id: string | null;
  mapping_match: boolean;
}

export interface SimulatorReport {
  run_id: string;
  scenario_count: number;
  generated_at: string | null;
  metrics: Record<string, number | null>;
  confusion_matrix: Record<string, number>;
  results: SimulatorResult[];
}

export interface VerifyResult {
  ok: boolean;
  error?: string;
  assumed_arn?: string;
  guardduty_enabled?: boolean;
  first_scan?: { status: string; alerts_found?: number };
}

export interface DashboardSummaryResponse {
  total_findings: number;
  open_findings: number;
  findings_by_severity: { critical: number; high: number; medium: number; low: number };
  connected_accounts: number;
  active_accounts: number;
  total_assets: number;
  risk_posture_score: number;
  risk_grade: string;
}

export interface ComplianceControlRollup {
  control: string;
  framework: string;
  open_findings: number;
}

export interface ComplianceServiceRollup {
  service: string;
  total_assets: number;
  assets_with_open_findings: number;
  pass_rate: number;
}

export interface ComplianceResponse {
  controls: ComplianceControlRollup[];
  by_service: ComplianceServiceRollup[];
  frameworks_covered: string[];
  note: string;
}

export interface RiskScoreResponse {
  risk_points: number;
  posture_score: number;
  grade: string;
  breakdown: Record<string, unknown>;
}
