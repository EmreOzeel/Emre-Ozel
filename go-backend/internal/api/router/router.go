package router

import (
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/api/handlers"
	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/config"
	"gorm.io/gorm"
)

// Setup creates and configures the Gin engine with all routes registered.
func Setup(db *gorm.DB, cfg *config.Config, h *handlers.Handler) *gin.Engine {
	r := gin.Default()

	// CORS configuration
	origins := strings.Split(cfg.AllowedOrigins, ",")
	r.Use(cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	api := r.Group("/api")

	// Health (no auth)
	api.GET("/health", h.Health)

	// Auth (no auth required for login)
	authG := api.Group("/auth")
	authG.POST("/login", h.Login)
	authG.GET("/me", auth.Middleware(), h.Me)

	// Protected routes
	p := api.Group("")
	p.Use(auth.Middleware())

	// ── Analyses ──
	p.POST("/analyses", h.CreateAnalysis)
	p.GET("/analyses", h.ListAnalyses)
	p.GET("/analyses/compare", h.CompareAnalyses)
	p.GET("/analyses/:id", h.GetAnalysis)
	p.GET("/analyses/:id/status", h.GetAnalysisStatus)
	p.DELETE("/analyses/:id", h.DeleteAnalysis)
	p.GET("/analyses/:id/report", h.GetAnalysisReport)
	p.GET("/analyses/:id/export", h.ExportAnalysis)

	// ── Workflow ──
	p.PUT("/analyses/:id/workflow", h.UpdateWorkflow)
	p.PUT("/analyses/:id/assign", h.AssignAnalysis)
	p.GET("/analyses/:id/triage", h.ListTriage)
	p.PUT("/analyses/:id/triage/:finding_key", h.UpdateTriage)
	p.GET("/analyses/:id/investigation-notes", h.ListInvestigationNotes)
	p.POST("/analyses/:id/investigation-notes", h.CreateInvestigationNote)
	p.PUT("/analyses/:id/investigation-notes/:note_id", h.UpdateInvestigationNote)
	p.DELETE("/analyses/:id/investigation-notes/:note_id", h.DeleteInvestigationNote)

	// ── Users ──
	p.GET("/users", h.ListUsers)

	// ── Notifications ──
	p.GET("/notifications", h.ListNotifications)
	p.GET("/notifications/unread-count", h.UnreadNotificationCount)
	p.POST("/notifications/mark-read", h.MarkNotificationsRead)

	// ── Work Queue ──
	p.GET("/work-queue", h.GetWorkQueue)

	// ── Suppressions ──
	p.GET("/suppressions", h.ListSuppressions)
	p.POST("/suppressions", h.CreateSuppression)
	p.PATCH("/suppressions/:id", h.UpdateSuppression)
	p.DELETE("/suppressions/:id", h.DeleteSuppression)

	// ── Live Events ──
	p.GET("/live-events", h.ListLiveEvents)
	p.GET("/live-events/stats", h.LiveEventStats)
	p.GET("/live-events/timeline", h.LiveEventTimeline)
	p.GET("/live-events/risk-scores", h.LiveEventRiskScores)

	// ── Live Flows ──
	p.GET("/live-flows", h.ListLiveFlows)
	p.GET("/live-flows/stats", h.LiveFlowStats)
	p.GET("/live-flows/timeline", h.LiveFlowTimeline)
	p.GET("/live-flows/behaviors", h.LiveFlowBehaviors)

	// ── Web Transactions ──
	p.GET("/web-transactions", h.ListWebTransactions)
	p.GET("/web-transactions/stats", h.WebTransactionStats)
	p.GET("/web-transactions/:id", h.GetWebTransaction)

	// ── Live Incidents ──
	p.GET("/live-incidents", h.ListLiveIncidents)
	p.GET("/live-incidents/:id", h.GetLiveIncident)
	p.PUT("/live-incidents/:id/status", h.UpdateLiveIncidentStatus)
	p.GET("/live-incidents/:id/pcaps", h.GetLiveIncidentPcaps)

	// ── Correlation Rules ──
	p.GET("/correlation-rules", h.ListCorrelationRules)
	p.POST("/correlation-rules", h.CreateCorrelationRule)
	p.GET("/correlation-rules/:id", h.GetCorrelationRule)
	p.PUT("/correlation-rules/:id", h.UpdateCorrelationRule)
	p.DELETE("/correlation-rules/:id", h.DeleteCorrelationRule)
	p.PATCH("/correlation-rules/:id/toggle", h.ToggleCorrelationRule)

	// ── Threat Intel ──
	p.GET("/threat-feeds", h.ListThreatFeeds)
	p.POST("/threat-feeds/:id/fetch", h.FetchThreatFeed)
	p.POST("/threat-feeds/refresh-all", h.RefreshAllFeeds)
	p.GET("/threat-indicators", h.ListThreatIndicators)
	p.GET("/threat-indicators/lookup", h.LookupThreatIP)
	p.DELETE("/threat-indicators/:id", h.DeleteThreatIndicator)

	// ── GeoIP ──
	p.GET("/geo/lookup", h.GeoLookup)
	p.POST("/geo/batch-lookup", h.GeoBatchLookup)
	p.GET("/geo/cache-stats", h.GeoCacheStats)

	// ── Baselines ──
	p.GET("/baselines", h.ListBaselines)
	p.GET("/baselines/:source_ip", h.GetIPBaseline)

	// ── Attack Sessions ──
	p.GET("/attack-sessions", h.ListAttackSessions)
	p.GET("/attack-sessions/:id", h.GetAttackSession)

	// ── Path Analysis ──
	p.POST("/analyses/:id/path-analysis", h.RunPathAnalysis)
	p.GET("/analyses/:id/path-analysis/feedback", h.ListPathFeedback)
	p.POST("/path-analysis/compare", h.PathCompare)
	p.POST("/path-analysis/export/json", h.PathExportJSON)
	p.POST("/path-analysis/export/html", h.PathExportHTML)
	p.POST("/path-analysis/feedback", h.CreatePathFeedback)
	p.GET("/path-analysis/feedback", h.ListPathFeedback)
	p.GET("/path-analysis/feedback/summary", h.PathFeedbackSummary)
	p.GET("/path-analysis/feedback/calibration", h.PathFeedbackCalibration)
	p.POST("/path-analysis/saved-queries", h.CreateSavedQuery)
	p.GET("/path-analysis/saved-queries", h.ListSavedQueries)
	p.GET("/path-analysis/saved-queries/:id", h.GetSavedQuery)
	p.PUT("/path-analysis/saved-queries/:id", h.UpdateSavedQuery)
	p.DELETE("/path-analysis/saved-queries/:id", h.DeleteSavedQuery)
	p.POST("/path-analysis/presets", h.CreatePreset)
	p.GET("/path-analysis/presets", h.ListPresets)
	p.GET("/path-analysis/presets/:id", h.GetPreset)
	p.PUT("/path-analysis/presets/:id", h.UpdatePreset)
	p.DELETE("/path-analysis/presets/:id", h.DeletePreset)

	// ── Path Monitors ──
	p.POST("/path-monitors", h.CreateMonitor)
	p.GET("/path-monitors", h.ListMonitors)
	p.GET("/path-monitors/:id", h.GetMonitor)
	p.PUT("/path-monitors/:id", h.UpdateMonitor)
	p.DELETE("/path-monitors/:id", h.DeleteMonitor)
	p.POST("/path-monitors/:id/run", h.RunMonitor)
	p.POST("/path-monitors/tick", h.MonitorTick)
	p.GET("/path-monitors/:id/history", h.ListMonitorHistory)
	p.GET("/path-monitors/:id/trend", h.MonitorTrend)
	p.POST("/path-monitors/:id/outcomes", h.CreateOutcome)
	p.GET("/path-monitors/:id/outcomes", h.ListOutcomes)
	p.GET("/path-monitors/:id/learnings", h.GetLearnings)
	p.POST("/path-monitors/:id/suppressions", h.CreateMonitorSuppression)
	p.GET("/path-monitors/:id/suppressions", h.ListMonitorSuppressions)
	p.DELETE("/path-monitors/:id/suppressions/:sid", h.DeleteMonitorSuppression)
	p.PUT("/path-monitors/:id/baseline", h.UpdateMonitorBaseline)
	p.GET("/path-monitors/:id/baseline", h.GetMonitorBaseline)

	// ── System Insights ──
	p.GET("/system-insights", h.SystemInsights)

	// ── Dashboard ──
	p.GET("/dashboard/summary", h.DashboardSummary)

	// ── PCAP Trigger (501) ──
	p.GET("/pcap-trigger/status", h.NotImplemented)
	p.POST("/pcap-trigger/manual", h.NotImplemented)

	// ── Packet Engine (501) ──
	p.GET("/packet-engine/watches", h.NotImplemented)
	p.POST("/packet-engine/watches", h.NotImplemented)
	p.DELETE("/packet-engine/watches/:ip/:port", h.NotImplemented)

	// ── Ingest (packet-engine token auth) ──
	api.POST("/ingest/packet-events", h.IngestPacketEvents)
	api.POST("/ingest/packet-alerts", h.IngestPacketAlert)

	// ── Collector ──
	p.GET("/collector/status", h.CollectorStatus)

	// ── Telemetry (501) ──
	p.GET("/telemetry/summary", h.NotImplemented)

	return r
}
