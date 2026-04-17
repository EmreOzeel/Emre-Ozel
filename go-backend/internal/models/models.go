package models

import (
	"time"
)

// ---------- Team ----------

type Team struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"not null;unique" json:"name"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Team) TableName() string { return "teams" }

// ---------- User ----------

type User struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Username       string    `gorm:"not null;unique" json:"username"`
	HashedPassword string    `gorm:"not null" json:"-"`
	IsAdmin        bool      `gorm:"not null;default:false" json:"is_admin"`
	TeamID         *uint     `gorm:"index" json:"team_id"`
	CreatedAt      time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (User) TableName() string { return "users" }

// ---------- Analysis ----------

type Analysis struct {
	ID                string     `gorm:"primaryKey;type:varchar(36)" json:"id"` // UUID
	UserID            uint       `gorm:"not null;index" json:"user_id"`
	Filename          string     `gorm:"not null" json:"filename"`
	FilePath          *string    `json:"file_path"`
	FileHash          *string    `gorm:"index" json:"file_hash"`
	Status            string     `gorm:"default:pending" json:"status"`
	CurrentStage      *string    `json:"current_stage"`
	ProgressPct       int        `gorm:"default:0" json:"progress_pct"`
	PacketCount       int        `gorm:"default:0" json:"packet_count"`
	IssueCount        int        `gorm:"default:0" json:"issue_count"`
	CriticalCount     int        `gorm:"default:0" json:"critical_count"`
	Error             *string    `gorm:"type:text" json:"error"`
	ResultJSON        *string    `gorm:"type:text" json:"result_json"`
	CreatedAt         time.Time  `gorm:"autoCreateTime" json:"created_at"`
	StartedAt         *time.Time `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at"`
	WorkflowState     string     `gorm:"not null;default:new;index" json:"workflow_state"`
	AssignedUserID    *uint      `gorm:"index" json:"assigned_user_id"`
	WorkflowUpdatedAt *time.Time `json:"workflow_updated_at"`
	WorkflowUpdatedBy *uint      `json:"workflow_updated_by"`
}

func (Analysis) TableName() string { return "analyses" }

// ---------- SuppressionRule ----------

type SuppressionRule struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	Scope      string     `gorm:"not null;default:user" json:"scope"`
	RuleID     *string    `json:"rule_id"`
	SrcIP      *string    `json:"src_ip"`
	DstIP      *string    `json:"dst_ip"`
	AnalysisID *string    `gorm:"index" json:"analysis_id"`
	Reason     string     `gorm:"not null;default:''" json:"reason"`
	Note       *string    `gorm:"type:text" json:"note"`
	IsActive   bool       `gorm:"not null;default:true" json:"is_active"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedBy  *uint      `json:"created_by"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (SuppressionRule) TableName() string { return "suppression_rules" }

// ---------- TelemetryEvent ----------

type TelemetryEvent struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	EventType      string    `gorm:"not null;index" json:"event_type"`
	UserID         *uint     `json:"user_id"`
	PropertiesJSON *string   `gorm:"type:text" json:"properties_json"`
	CreatedAt      time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

func (TelemetryEvent) TableName() string { return "telemetry_events" }

// ---------- FindingTriage ----------

type FindingTriage struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	AnalysisID string    `gorm:"not null;index" json:"analysis_id"`
	FindingKey string    `gorm:"not null;index" json:"finding_key"`
	Status     string    `gorm:"not null;default:new" json:"status"`
	Note       *string   `gorm:"type:text" json:"note"`
	AnalystID  *uint     `json:"analyst_id"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (FindingTriage) TableName() string { return "finding_triage" }

// ---------- PathAnalysisSavedQuery ----------

type PathAnalysisSavedQuery struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	OwnerUserID      uint      `gorm:"not null;index" json:"owner_user_id"`
	Name             string    `gorm:"not null" json:"name"`
	SourceIP         string    `gorm:"not null" json:"source_ip"`
	DestinationIP    string    `gorm:"not null" json:"destination_ip"`
	DestinationPort  *int      `json:"destination_port"`
	RolePresetID     *uint     `json:"role_preset_id"`
	FirewallIPs      string    `gorm:"type:text;not null;default:'[]'" json:"firewall_ips"`
	LoadBalancerVIPs string    `gorm:"type:text;not null;default:'[]'" json:"load_balancer_vips"`
	BackendIPs       string    `gorm:"type:text;not null;default:'[]'" json:"backend_ips"`
	BackendSubnets   string    `gorm:"type:text;not null;default:'[]'" json:"backend_subnets"`
	Note             *string   `gorm:"type:text" json:"note"`
	Scope            string    `gorm:"not null;default:private;index" json:"scope"`
	TeamID           *uint     `gorm:"index" json:"team_id"`
	CreatedBy        *uint     `json:"created_by"`
	UpdatedBy        *uint     `json:"updated_by"`
	CreatedAt        time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt        time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (PathAnalysisSavedQuery) TableName() string { return "path_analysis_saved_queries" }

// ---------- PathAnalysisRolePreset ----------

type PathAnalysisRolePreset struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	OwnerUserID      uint      `gorm:"not null;index" json:"owner_user_id"`
	Name             string    `gorm:"not null" json:"name"`
	FirewallIPs      string    `gorm:"type:text;not null;default:'[]'" json:"firewall_ips"`
	LoadBalancerVIPs string    `gorm:"type:text;not null;default:'[]'" json:"load_balancer_vips"`
	BackendIPs       string    `gorm:"type:text;not null;default:'[]'" json:"backend_ips"`
	BackendSubnets   string    `gorm:"type:text;not null;default:'[]'" json:"backend_subnets"`
	Scope            string    `gorm:"not null;default:private;index" json:"scope"`
	TeamID           *uint     `gorm:"index" json:"team_id"`
	CreatedBy        *uint     `json:"created_by"`
	UpdatedBy        *uint     `json:"updated_by"`
	CreatedAt        time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt        time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (PathAnalysisRolePreset) TableName() string { return "path_analysis_role_presets" }

// ---------- PathAnalysisCache ----------

type PathAnalysisCache struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	CacheKey        string    `gorm:"not null;unique" json:"cache_key"`
	AnalysisID      string    `gorm:"not null;index" json:"analysis_id"`
	SourceIP        string    `gorm:"not null" json:"source_ip"`
	DestinationIP   string    `gorm:"not null" json:"destination_ip"`
	DestinationPort *int      `json:"destination_port"`
	RolesHash       string    `gorm:"not null" json:"roles_hash"`
	EngineVersion   string    `gorm:"not null" json:"engine_version"`
	ResultJSON      string    `gorm:"type:text;not null" json:"result_json"`
	CreatedAt       time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (PathAnalysisCache) TableName() string { return "path_analysis_cache" }

// ---------- PathAnalysisFeedback ----------

type PathAnalysisFeedback struct {
	ID                  uint      `gorm:"primaryKey" json:"id"`
	AnalysisID          string    `gorm:"not null;index" json:"analysis_id"`
	SourceIP            string    `gorm:"not null" json:"source_ip"`
	DestinationIP       string    `gorm:"not null" json:"destination_ip"`
	DestinationPort     *int      `json:"destination_port"`
	PredictedOutcome    string    `gorm:"not null" json:"predicted_outcome"`
	PredictedImpairment *string   `json:"predicted_impairment"`
	PredictedConfidence int       `gorm:"not null" json:"predicted_confidence"`
	Verdict             string    `gorm:"not null" json:"verdict"`
	AnalystNote         *string   `gorm:"type:text" json:"analyst_note"`
	ActualRootCause     *string   `json:"actual_root_cause"`
	MisleadingStep      *string   `gorm:"type:text" json:"misleading_step"`
	AnalystID           *uint     `json:"analyst_id"`
	Scope               string    `gorm:"not null;default:private;index" json:"scope"`
	TeamID              *uint     `gorm:"index" json:"team_id"`
	CreatedAt           time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt           time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (PathAnalysisFeedback) TableName() string { return "path_analysis_feedback" }

// ---------- InvestigationNote ----------

type InvestigationNote struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	AnalysisID      string    `gorm:"not null;index" json:"analysis_id"`
	SourceIP        string    `gorm:"not null" json:"source_ip"`
	DestinationIP   string    `gorm:"not null" json:"destination_ip"`
	DestinationPort *int      `json:"destination_port"`
	Body            string    `gorm:"type:text;not null;default:''" json:"body"`
	Scope           string    `gorm:"not null;default:private;index" json:"scope"`
	TeamID          *uint     `gorm:"index" json:"team_id"`
	CreatedBy       uint      `gorm:"not null" json:"created_by"`
	UpdatedBy       *uint     `json:"updated_by"`
	CreatedAt       time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (InvestigationNote) TableName() string { return "investigation_notes" }

// ---------- MonitoredPath ----------

type MonitoredPath struct {
	ID                      uint       `gorm:"primaryKey" json:"id"`
	SavedQueryID            uint       `gorm:"not null;index" json:"saved_query_id"`
	AnalysisID              string     `gorm:"not null;index" json:"analysis_id"`
	OwnerUserID             uint       `gorm:"not null;index" json:"owner_user_id"`
	ScheduleIntervalMinutes int        `gorm:"not null;default:60" json:"schedule_interval_minutes"`
	Enabled                 bool       `gorm:"not null;default:true" json:"enabled"`
	LastRunAt               *time.Time `json:"last_run_at"`
	LastChangeAt            *time.Time `json:"last_change_at"`
	LastResultJSON          *string    `gorm:"type:text" json:"last_result_json"`
	LastChangeSummary       *string    `gorm:"type:text" json:"last_change_summary"`
	LastDriftSeverity       *string    `json:"last_drift_severity"`
	LastOutcome             *string    `json:"last_outcome"`
	LastOutcomeAt           *time.Time `json:"last_outcome_at"`
	BaselineJSON            *string    `gorm:"type:text" json:"baseline_json"`
	CreatedAt               time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt               time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

func (MonitoredPath) TableName() string { return "monitored_paths" }

// ---------- MonitorSuppression ----------

type MonitorSuppression struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	MonitoredPathID uint       `gorm:"not null;index" json:"monitored_path_id"`
	Kind            string     `gorm:"not null" json:"kind"`
	Value           *string    `json:"value"`
	Reason          *string    `gorm:"type:text" json:"reason"`
	Enabled         bool       `gorm:"not null;default:true" json:"enabled"`
	Until           *time.Time `json:"until"`
	CreatedBy       *uint      `json:"created_by"`
	CreatedAt       time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (MonitorSuppression) TableName() string { return "monitor_suppressions" }

// ---------- MonitorOutcome ----------

type MonitorOutcome struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	MonitoredPathID   uint      `gorm:"not null;index" json:"monitored_path_id"`
	Outcome           string    `gorm:"not null;index" json:"outcome"`
	RootCauseType     *string   `json:"root_cause_type"`
	Note              *string   `gorm:"type:text" json:"note"`
	SignalDriversJSON *string   `gorm:"type:text" json:"signal_drivers_json"`
	AnalystID         *uint     `gorm:"index" json:"analyst_id"`
	CreatedAt         time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

func (MonitorOutcome) TableName() string { return "monitor_outcomes" }

// ---------- MonitoredPathRun ----------

type MonitoredPathRun struct {
	ID                  uint      `gorm:"primaryKey" json:"id"`
	MonitoredPathID     uint      `gorm:"not null;index" json:"monitored_path_id"`
	RunAt               time.Time `gorm:"autoCreateTime;not null;index" json:"run_at"`
	ConnectionOutcome   string    `gorm:"not null" json:"connection_outcome"`
	PrimaryImpairment   *string   `json:"primary_impairment"`
	PathConfidenceScore int       `gorm:"not null;default:0" json:"path_confidence_score"`
	DriftSeverity       string    `gorm:"not null;default:none" json:"drift_severity"`
	ActionRequired      bool      `gorm:"not null;default:false" json:"action_required"`
	TimingJSON          *string   `gorm:"type:text" json:"timing_json"`
	ImpairmentsJSON     *string   `gorm:"type:text" json:"impairments_json"`
}

func (MonitoredPathRun) TableName() string { return "monitored_path_runs" }

// ---------- Notification ----------

type Notification struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	UserID      uint       `gorm:"not null;index" json:"user_id"`
	Type        string     `gorm:"not null;index" json:"type"`
	AnalysisID  *string    `gorm:"index" json:"analysis_id"`
	ActorUserID *uint      `json:"actor_user_id"`
	Message     string     `gorm:"type:text;not null;default:''" json:"message"`
	ReadAt      *time.Time `gorm:"index" json:"read_at"`
	CreatedAt   time.Time  `gorm:"autoCreateTime;index" json:"created_at"`
}

func (Notification) TableName() string { return "notifications" }

// ---------- LiveEvent ----------

type LiveEvent struct {
	ID                 uint      `gorm:"primaryKey" json:"id"`
	SourceID           string    `gorm:"not null;index" json:"source_id"`
	DeviceType         string    `gorm:"not null;index" json:"device_type"`
	DeviceRole         *string   `json:"device_role"`
	ParserID           string    `gorm:"not null" json:"parser_id"`
	EventTime          time.Time `gorm:"not null;index" json:"event_time"`
	ReceivedAt         time.Time `gorm:"autoCreateTime;not null" json:"received_at"`
	SourceIP           string    `gorm:"not null;index" json:"source_ip"`
	DestinationIP      string    `gorm:"not null;index" json:"destination_ip"`
	SourcePort         *int      `json:"source_port"`
	DestinationPort    *int      `json:"destination_port"`
	Protocol           *string   `json:"protocol"`
	Action             string    `gorm:"not null;index" json:"action"`
	Reason             *string   `json:"reason"`
	BytesIn            *int      `json:"bytes_in"`
	BytesOut           *int      `json:"bytes_out"`
	PacketsIn          *int      `json:"packets_in"`
	PacketsOut         *int      `json:"packets_out"`
	DurationMs         *int      `json:"duration_ms"`
	NatSourceIP        *string   `json:"nat_source_ip"`
	NatDestinationIP   *string   `json:"nat_destination_ip"`
	NatSourcePort      *int      `json:"nat_source_port"`
	NatDestinationPort *int      `json:"nat_destination_port"`
	Application        *string   `json:"application"`
	Service            *string   `json:"service"`
	BackendIP          *string   `json:"backend_ip"`
	BackendPort        *int      `json:"backend_port"`
	ResponseTimeMs     *float64  `json:"response_time_ms"`
	HealthStatus       *string   `json:"health_status"`
	RawLine            *string   `gorm:"type:text" json:"raw_line"`
	Suppressed         *bool     `gorm:"default:false" json:"suppressed"`
}

func (LiveEvent) TableName() string { return "live_events" }

// ---------- LiveFlow ----------

type LiveFlow struct {
	ID                 uint      `gorm:"primaryKey" json:"id"`
	SourceID           string    `gorm:"not null;index" json:"source_id"`
	DeviceType         string    `gorm:"not null" json:"device_type"`
	DeviceRole         *string   `json:"device_role"`
	ParserID           string    `gorm:"not null" json:"parser_id"`
	SourceIP           string    `gorm:"not null;index" json:"source_ip"`
	DestinationIP      string    `gorm:"not null;index" json:"destination_ip"`
	SourcePort         *int      `json:"source_port"`
	DestinationPort    *int      `json:"destination_port"`
	Protocol           *string   `gorm:"index" json:"protocol"`
	FirstSeen          time.Time `gorm:"not null;index" json:"first_seen"`
	LastSeen           time.Time `gorm:"not null;index" json:"last_seen"`
	DurationMs         *int      `json:"duration_ms"`
	EventCount         int       `gorm:"not null;default:0" json:"event_count"`
	TotalBytesIn       int       `gorm:"not null;default:0" json:"total_bytes_in"`
	TotalBytesOut      int       `gorm:"not null;default:0" json:"total_bytes_out"`
	TotalPacketsIn     int       `gorm:"not null;default:0" json:"total_packets_in"`
	TotalPacketsOut    int       `gorm:"not null;default:0" json:"total_packets_out"`
	AllowCount         int       `gorm:"not null;default:0" json:"allow_count"`
	DenyCount          int       `gorm:"not null;default:0" json:"deny_count"`
	DropCount          int       `gorm:"not null;default:0" json:"drop_count"`
	ResetCount         int       `gorm:"not null;default:0" json:"reset_count"`
	AlertCount         int       `gorm:"not null;default:0" json:"alert_count"`
	ActionSummary      *string   `json:"action_summary"`
	ReasonSummary      *string   `json:"reason_summary"`
	NatSourceIP        *string   `json:"nat_source_ip"`
	NatDestinationIP   *string   `json:"nat_destination_ip"`
	NatSourcePort      *int      `json:"nat_source_port"`
	NatDestinationPort *int      `json:"nat_destination_port"`
	Application        *string   `json:"application"`
	Service            *string   `json:"service"`
	BackendIP          *string   `json:"backend_ip"`
	BackendPort        *int      `json:"backend_port"`
	State              string    `gorm:"not null;default:active;index" json:"state"`
	RawEventCount      int       `gorm:"not null;default:0" json:"raw_event_count"`
	FlowType           *string   `gorm:"index" json:"flow_type"`
	ResetRatio         *float64  `json:"reset_ratio"`
	DenyRatio          *float64  `json:"deny_ratio"`
	BurstScore         *float64  `json:"burst_score"`
	AsymmetricBehavior *bool     `gorm:"default:false" json:"asymmetric_behavior"`
	SuspiciousReasons  *string   `gorm:"type:text" json:"suspicious_reasons"`
	Suppressed         *bool     `gorm:"default:false" json:"suppressed"`
	CreatedAt          time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (LiveFlow) TableName() string { return "live_flows" }

// ---------- LiveIncident ----------

type LiveIncident struct {
	ID                        uint       `gorm:"primaryKey" json:"id"`
	SourceIP                  string     `gorm:"not null;index" json:"source_ip"`
	BehaviorType              string     `gorm:"not null;index" json:"behavior_type"`
	Severity                  string     `gorm:"not null;default:low;index" json:"severity"`
	Status                    string     `gorm:"not null;default:open;index" json:"status"`
	FirstSeen                 time.Time  `gorm:"not null" json:"first_seen"`
	LastSeen                  time.Time  `gorm:"not null" json:"last_seen"`
	EventCount                int        `gorm:"not null;default:1" json:"event_count"`
	LinkedFlowCount           int        `gorm:"not null;default:0" json:"linked_flow_count"`
	LatestConfidence          *float64   `json:"latest_confidence"`
	Summary                   *string    `gorm:"type:text" json:"summary"`
	TopDestinationIPs         *string    `gorm:"type:text" json:"top_destination_ips"`
	TopPorts                  *string    `gorm:"type:text" json:"top_ports"`
	TotalDistinctDestinations *int       `json:"total_distinct_destinations"`
	TotalDistinctPorts        *int       `json:"total_distinct_ports"`
	SampleFlows               *string    `gorm:"type:text" json:"sample_flows"`
	LastActivitySummary       *string    `gorm:"type:text" json:"last_activity_summary"`
	ImpactedAssetsCount       *int       `json:"impacted_assets_count"`
	HighestTargetCriticality  *string    `json:"highest_target_criticality"`
	TargetSummary             *string    `gorm:"type:text" json:"target_summary"`
	PriorityScore             *float64   `json:"priority_score"`
	LastActivityAt            *time.Time `json:"last_activity_at"`
	DecayFactor               *float64   `json:"decay_factor"`
	LinkedPcapAnalysisIDs     *string    `gorm:"type:text;default:'[]'" json:"linked_pcap_analysis_ids"`
	PcapTriggerCount          *int       `gorm:"default:0" json:"pcap_trigger_count"`
	CreatedAt                 time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt                 time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

func (LiveIncident) TableName() string { return "live_incidents" }

// ---------- AttackSession ----------

type AttackSession struct {
	ID                       uint      `gorm:"primaryKey" json:"id"`
	SourceIP                 string    `gorm:"not null;index" json:"source_ip"`
	StartTime                time.Time `gorm:"not null" json:"start_time"`
	LastActivity             time.Time `gorm:"not null" json:"last_activity"`
	IncidentIDs              string    `gorm:"type:text;not null;default:'[]'" json:"incident_ids"`
	Behaviors                string    `gorm:"type:text;not null;default:'[]'" json:"behaviors"`
	Severity                 string    `gorm:"not null;default:low" json:"severity"`
	PriorityScore            float64   `gorm:"not null;default:0" json:"priority_score"`
	Status                   string    `gorm:"not null;default:active;index" json:"status"`
	TotalIncidents           int       `gorm:"not null;default:0" json:"total_incidents"`
	TotalDestinations        int       `gorm:"not null;default:0" json:"total_destinations"`
	TotalPorts               int       `gorm:"not null;default:0" json:"total_ports"`
	TopDestinationIPs        *string   `gorm:"type:text" json:"top_destination_ips"`
	TopPorts                 *string   `gorm:"type:text" json:"top_ports"`
	TargetSummary            *string   `gorm:"type:text" json:"target_summary"`
	HighestTargetCriticality *string   `json:"highest_target_criticality"`
	SessionSummary           *string   `gorm:"type:text" json:"session_summary"`
	RecommendedNextStep      *string   `gorm:"type:text" json:"recommended_next_step"`
	BehaviorTimeline         *string   `gorm:"type:text" json:"behavior_timeline"`
	BehaviorSequence         *string   `json:"behavior_sequence"`
	AttackIntent             *string   `json:"attack_intent"`
	AttackIntents            *string   `gorm:"type:text" json:"attack_intents"`
	IntentConfidence         *float64  `json:"intent_confidence"`
	ActivityRate             *float64  `json:"activity_rate"`
	BurstFlag                *bool     `gorm:"default:false" json:"burst_flag"`
	RecommendedAction        *string   `json:"recommended_action"`
	CreatedAt                time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt                time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (AttackSession) TableName() string { return "attack_sessions" }

// ---------- IPBaseline ----------

type IPBaseline struct {
	ID                      uint       `gorm:"primaryKey" json:"id"`
	SourceIP                string     `gorm:"not null;unique" json:"source_ip"`
	ObservationWindowDays   int        `gorm:"not null;default:7" json:"observation_window_days"`
	SampleCount             int        `gorm:"not null;default:0" json:"sample_count"`
	AvgFlowsPerWindow       float64    `gorm:"not null;default:0" json:"avg_flows_per_window"`
	AvgDistinctDestinations float64    `gorm:"not null;default:0" json:"avg_distinct_destinations"`
	AvgDistinctPorts        float64    `gorm:"not null;default:0" json:"avg_distinct_ports"`
	AvgDenyRatio            float64    `gorm:"not null;default:0" json:"avg_deny_ratio"`
	AvgResetRatio           float64    `gorm:"not null;default:0" json:"avg_reset_ratio"`
	AvgBytesPerFlow         float64    `gorm:"not null;default:0" json:"avg_bytes_per_flow"`
	StddevFlows             float64    `gorm:"not null;default:0" json:"stddev_flows"`
	StddevDenyRatio         float64    `gorm:"not null;default:0" json:"stddev_deny_ratio"`
	StddevResetRatio        float64    `gorm:"not null;default:0" json:"stddev_reset_ratio"`
	LastComputedAt          *time.Time `json:"last_computed_at"`
	CreatedAt               time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt               time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

func (IPBaseline) TableName() string { return "ip_baselines" }

// ---------- Asset ----------

type Asset struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	IPAddress   string    `gorm:"not null;unique" json:"ip_address"`
	Hostname    *string   `json:"hostname"`
	AssetType   string    `gorm:"not null;default:workstation" json:"asset_type"`
	Criticality string    `gorm:"not null;default:low" json:"criticality"`
	Environment *string   `json:"environment"`
	Tags        *string   `gorm:"type:text" json:"tags"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (Asset) TableName() string { return "assets" }

// ---------- ThreatIndicator ----------

type ThreatIndicator struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	IndicatorType  string     `gorm:"not null" json:"indicator_type"`
	IndicatorValue string     `gorm:"not null;index" json:"indicator_value"`
	ThreatType     string     `gorm:"not null;default:unknown" json:"threat_type"`
	Confidence     float64    `gorm:"not null;default:0.5" json:"confidence"`
	SourceFeed     string     `gorm:"not null" json:"source_feed"`
	FirstSeen      time.Time  `gorm:"not null" json:"first_seen"`
	LastSeen       time.Time  `gorm:"not null" json:"last_seen"`
	Expiry         *time.Time `json:"expiry"`
	Tags           *string    `gorm:"type:text" json:"tags"`
	RawData        *string    `gorm:"type:text" json:"raw_data"`
	CreatedAt      time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

func (ThreatIndicator) TableName() string { return "threat_indicators" }

// ---------- ThreatFeed ----------

type ThreatFeed struct {
	ID                   uint       `gorm:"primaryKey" json:"id"`
	Name                 string     `gorm:"not null;unique" json:"name"`
	FeedType             string     `gorm:"not null" json:"feed_type"`
	URL                  *string    `json:"url"`
	Enabled              bool       `gorm:"not null;default:true" json:"enabled"`
	LastFetchedAt        *time.Time `json:"last_fetched_at"`
	LastIndicatorCount   int        `gorm:"not null;default:0" json:"last_indicator_count"`
	FetchIntervalHours   int        `gorm:"not null;default:24" json:"fetch_interval_hours"`
	Format               string     `gorm:"not null;default:plain" json:"format"`
	CommentChar          string     `gorm:"not null;default:#" json:"comment_char"`
	IPColumn             int        `gorm:"not null;default:0" json:"ip_column"`
	DefaultThreatType    string     `gorm:"not null;default:unknown" json:"default_threat_type"`
	DefaultConfidence    float64    `gorm:"not null;default:0.5" json:"default_confidence"`
	CreatedAt            time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

func (ThreatFeed) TableName() string { return "threat_feeds" }

// ---------- CorrelationRule ----------

type CorrelationRule struct {
	ID                   uint      `gorm:"primaryKey" json:"id"`
	Name                 string    `gorm:"not null" json:"name"`
	Description          *string   `gorm:"type:text" json:"description"`
	Enabled              bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedBy            *uint     `json:"created_by"`
	Scope                string    `gorm:"not null;default:user" json:"scope"`
	ConditionField       string    `gorm:"not null" json:"condition_field"`
	ConditionOperator    string    `gorm:"not null" json:"condition_operator"`
	ConditionValue       string    `gorm:"not null" json:"condition_value"`
	AggregationType      string    `gorm:"not null" json:"aggregation_type"`
	AggregationField     *string   `json:"aggregation_field"`
	Threshold            float64   `gorm:"not null" json:"threshold"`
	TimeWindowMinutes    int       `gorm:"not null;default:10" json:"time_window_minutes"`
	TargetEntity         string    `gorm:"not null" json:"target_entity"`
	Severity             string    `gorm:"not null;default:medium" json:"severity"`
	IncidentBehaviorType string    `gorm:"not null" json:"incident_behavior_type"`
	CooldownMinutes      int       `gorm:"not null;default:30" json:"cooldown_minutes"`
	CreatedAt            time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt            time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (CorrelationRule) TableName() string { return "correlation_rules" }

// ---------- GeoIPCache ----------

type GeoIPCache struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	IP          string    `gorm:"not null;unique" json:"ip"`
	CountryCode *string   `json:"country_code"`
	CountryName *string   `json:"country_name"`
	City        *string   `json:"city"`
	Latitude    *float64  `json:"latitude"`
	Longitude   *float64  `json:"longitude"`
	ASN         *int      `json:"asn"`
	ASNOrg      *string   `json:"asn_org"`
	IsPrivate   bool      `gorm:"not null;default:false" json:"is_private"`
	IsBogon     bool      `gorm:"not null;default:false" json:"is_bogon"`
	Source      string    `gorm:"not null" json:"source"`
	LookedUpAt  time.Time `gorm:"not null" json:"looked_up_at"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (GeoIPCache) TableName() string { return "geoip_cache" }

// AllModels returns a slice of pointers to all model types for use with AutoMigrate.
func AllModels() []interface{} {
	return []interface{}{
		&Team{},
		&User{},
		&Analysis{},
		&SuppressionRule{},
		&TelemetryEvent{},
		&FindingTriage{},
		&PathAnalysisSavedQuery{},
		&PathAnalysisRolePreset{},
		&PathAnalysisCache{},
		&PathAnalysisFeedback{},
		&InvestigationNote{},
		&MonitoredPath{},
		&MonitorSuppression{},
		&MonitorOutcome{},
		&MonitoredPathRun{},
		&Notification{},
		&LiveEvent{},
		&LiveFlow{},
		&LiveIncident{},
		&AttackSession{},
		&IPBaseline{},
		&Asset{},
		&ThreatIndicator{},
		&ThreatFeed{},
		&CorrelationRule{},
		&GeoIPCache{},
	}
}
