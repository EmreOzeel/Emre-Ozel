package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/analyzer/causal_path"
	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// visibleFilter scopes a query to records visible to the current user:
// own records, global records, and team records if the user has a team.
func visibleFilter(db *gorm.DB, user *models.User) *gorm.DB {
	q := db.Where("owner_user_id = ? OR scope = 'global'", user.ID)
	if user.TeamID != nil {
		q = q.Or("scope = 'team' AND team_id = ?", *user.TeamID)
	}
	return q
}

// ---------- RunPathAnalysis ----------

// RunPathAnalysis handles POST /api/analyses/:id/path-analysis.
func (h *Handler) RunPathAnalysis(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	analysisID := c.Param("id")

	var req struct {
		SourceIP         string   `json:"source_ip"`
		DestinationIP    string   `json:"destination_ip"`
		DestinationPort  int      `json:"destination_port"`
		FirewallIPs      []string `json:"firewall_ips"`
		LoadBalancerVIPs []string `json:"load_balancer_vips"`
		BackendIPs       []string `json:"backend_ips"`
		BackendSubnets   []string `json:"backend_subnets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	// Build sorted roles map for cache key.
	roles := map[string][]string{
		"firewall_ips":       req.FirewallIPs,
		"load_balancer_vips": req.LoadBalancerVIPs,
		"backend_ips":        req.BackendIPs,
		"backend_subnets":    req.BackendSubnets,
	}
	for _, v := range roles {
		sort.Strings(v)
	}
	rolesJSON, _ := json.Marshal(roles)

	raw := fmt.Sprintf("%s%s%s%d%sv1", analysisID, req.SourceIP, req.DestinationIP, req.DestinationPort, string(rolesJSON))
	hash := sha256.Sum256([]byte(raw))
	cacheKey := fmt.Sprintf("%x", hash)

	var cached models.PathAnalysisCache
	if err := h.DB.Where("cache_key = ?", cacheKey).First(&cached).Error; err == nil {
		var parsed interface{}
		if err := json.Unmarshal([]byte(cached.ResultJSON), &parsed); err == nil {
			result := gin.H{"from_cache": true}
			if m, ok := parsed.(map[string]interface{}); ok {
				for k, v := range m {
					result[k] = v
				}
			} else {
				result["result"] = parsed
			}
			c.JSON(http.StatusOK, result)
			return
		}
	}

	// Cache miss — run engine
	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", analysisID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Analysis not found"})
		return
	}
	if analysis.ResultJSON == nil || *analysis.ResultJSON == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Analysis has no results yet"})
		return
	}

	// Parse result_json to extract packets/flows/findings
	packets, flows, findings := convertResultToEngine(*analysis.ResultJSON)

	// Build roles map for engine
	engineRoles := map[string]interface{}{
		"firewall_ips":       req.FirewallIPs,
		"load_balancer_vips": req.LoadBalancerVIPs,
		"backend_ips":        req.BackendIPs,
		"backend_subnets":    req.BackendSubnets,
	}

	var dstPort *int
	if req.DestinationPort > 0 {
		dp := req.DestinationPort
		dstPort = &dp
	}

	// Run causal path engine
	engine := causal_path.NewEngine(packets, flows, findings)
	pathResult := engine.Analyze(req.SourceIP, req.DestinationIP, dstPort, engineRoles)

	// Store in cache
	resultBytes, _ := json.Marshal(pathResult)
	rolesHash := fmt.Sprintf("%x", sha256.Sum256(rolesJSON))
	h.DB.Create(&models.PathAnalysisCache{
		CacheKey:        cacheKey,
		AnalysisID:      analysisID,
		SourceIP:        req.SourceIP,
		DestinationIP:   req.DestinationIP,
		DestinationPort: dstPort,
		RolesHash:       rolesHash,
		EngineVersion:   causal_path.CacheEngineVersion,
		ResultJSON:      string(resultBytes),
	})

	c.JSON(http.StatusOK, pathResult)
}

// convertResultToEngine parses an analysis result_json into causal path engine inputs.
func convertResultToEngine(resultJSON string) ([]causal_path.NormalizedPacket, []causal_path.FlowRecord, []causal_path.Finding) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(resultJSON), &raw); err != nil {
		return nil, nil, nil
	}

	var packets []causal_path.NormalizedPacket
	var flows []causal_path.FlowRecord
	var findings []causal_path.Finding

	// Extract packets from result
	if rawPkts, ok := raw["packets"].([]interface{}); ok {
		for i, rp := range rawPkts {
			m, ok := rp.(map[string]interface{})
			if !ok {
				continue
			}
			p := causal_path.NormalizedPacket{
				Num:      i + 1,
				Time:     getFloat(m, "time"),
				SrcIP:    getMapStr(m, "src_ip"),
				DstIP:    getMapStr(m, "dst_ip"),
				SrcPort:  getMapInt(m, "src_port"),
				DstPort:  getMapInt(m, "dst_port"),
				Protocol: getMapStr(m, "protocol"),
				IPProto:  getMapInt(m, "ip_proto"),
				Length:   getMapInt(m, "length"),
				FrameLen: getMapInt(m, "frame_len"),
				TCPPayloadLen: getMapInt(m, "tcp_payload_len"),
				TCPFlags: map[string]bool{
					"syn": getMapBool(m, "tcp_flags_syn"),
					"ack": getMapBool(m, "tcp_flags_ack"),
					"fin": getMapBool(m, "tcp_flags_fin"),
					"rst": getMapBool(m, "tcp_flags_rst"),
					"psh": getMapBool(m, "tcp_flags_psh"),
				},
			}
			packets = append(packets, p)
		}
	}

	// Extract findings
	if rawFindings, ok := raw["findings"].([]interface{}); ok {
		for _, rf := range rawFindings {
			m, ok := rf.(map[string]interface{})
			if !ok {
				continue
			}
			findings = append(findings, causal_path.Finding{
				ID:       getMapStr(m, "id"),
				RuleID:   getMapStr(m, "rule_id"),
				Severity: getMapStr(m, "severity"),
				Category: getMapStr(m, "category"),
				Title:    getMapStr(m, "title"),
				SrcIP:    getMapStr(m, "src_ip"),
				DstIP:    getMapStr(m, "dst_ip"),
			})
		}
	}

	return packets, flows, findings
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64: return n
		case int: return float64(n)
		}
	}
	return 0
}

func getMapStr(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok { return v }
	return ""
}

func getMapInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64: return int(n)
		case int: return n
		}
	}
	return 0
}

func getMapBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok { return v }
	return false
}

// ---------- Path Feedback ----------

// ListPathFeedback handles GET /api/analyses/:id/path-analysis/feedback
// and GET /api/path-analysis/feedback?analysis_id=...
func (h *Handler) ListPathFeedback(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	analysisID := c.Param("id")
	if analysisID == "" {
		analysisID = c.Query("analysis_id")
	}
	if analysisID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "analysis_id is required"})
		return
	}

	var feedback []models.PathAnalysisFeedback
	q := h.DB.Where("analysis_id = ?", analysisID)

	// Scope filtering: private = own only, team = same team.
	q = q.Where(
		h.DB.Where("scope = 'private' AND analyst_id = ?", user.ID).
			Or("scope = 'global'").
			Or("scope = 'team' AND team_id = ?", user.TeamID),
	)

	q.Order("created_at DESC").Find(&feedback)
	c.JSON(http.StatusOK, feedback)
}

// CreatePathFeedback handles POST /api/path-analysis/feedback.
func (h *Handler) CreatePathFeedback(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var fb models.PathAnalysisFeedback
	if err := c.ShouldBindJSON(&fb); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	fb.AnalystID = &user.ID
	fb.Scope = "private"
	if user.TeamID != nil {
		fb.TeamID = user.TeamID
		fb.Scope = "team"
	}

	// Upsert by (analysis_id, source_ip, destination_ip, destination_port, analyst_id).
	var existing models.PathAnalysisFeedback
	upsertQ := h.DB.Where(
		"analysis_id = ? AND source_ip = ? AND destination_ip = ? AND analyst_id = ?",
		fb.AnalysisID, fb.SourceIP, fb.DestinationIP, user.ID,
	)
	if fb.DestinationPort != nil {
		upsertQ = upsertQ.Where("destination_port = ?", *fb.DestinationPort)
	} else {
		upsertQ = upsertQ.Where("destination_port IS NULL")
	}

	if err := upsertQ.First(&existing).Error; err == nil {
		// Update existing record.
		h.DB.Model(&existing).Updates(map[string]interface{}{
			"predicted_outcome":    fb.PredictedOutcome,
			"predicted_impairment": fb.PredictedImpairment,
			"predicted_confidence": fb.PredictedConfidence,
			"verdict":              fb.Verdict,
			"analyst_note":         fb.AnalystNote,
			"actual_root_cause":    fb.ActualRootCause,
			"misleading_step":      fb.MisleadingStep,
			"scope":                fb.Scope,
			"team_id":              fb.TeamID,
		})
		h.DB.First(&existing, existing.ID)
		c.JSON(http.StatusCreated, existing)
		return
	}

	if err := h.DB.Create(&fb).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create feedback"})
		return
	}
	c.JSON(http.StatusCreated, fb)
}

// PathFeedbackSummary handles GET /api/path-analysis/feedback/summary.
func (h *Handler) PathFeedbackSummary(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	type verdictCount struct {
		Verdict string `json:"verdict"`
		Count   int    `json:"count"`
	}

	var total int64
	h.DB.Model(&models.PathAnalysisFeedback{}).Count(&total)

	var counts []verdictCount
	h.DB.Model(&models.PathAnalysisFeedback{}).
		Select("verdict, COUNT(*) as count").
		Group("verdict").
		Scan(&counts)

	byVerdict := map[string]int{}
	for _, vc := range counts {
		byVerdict[vc.Verdict] = vc.Count
	}

	var avgConfidence float64
	h.DB.Model(&models.PathAnalysisFeedback{}).
		Select("COALESCE(AVG(predicted_confidence), 0)").
		Scan(&avgConfidence)

	c.JSON(http.StatusOK, gin.H{
		"total":                      total,
		"by_verdict":                 byVerdict,
		"avg_predicted_confidence":   avgConfidence,
	})
}

// PathFeedbackCalibration handles GET /api/path-analysis/feedback/calibration.
func (h *Handler) PathFeedbackCalibration(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	type bucket struct {
		Label          string  `json:"label"`
		Total          int     `json:"total"`
		CorrectCount   int     `json:"correct_count"`
		IncorrectCount int     `json:"incorrect_count"`
		AccuracyPct    float64 `json:"accuracy_pct"`
	}

	var allFeedback []models.PathAnalysisFeedback
	h.DB.Find(&allFeedback)

	buckets := []bucket{
		{Label: "0-20"}, {Label: "20-40"}, {Label: "40-60"}, {Label: "60-80"}, {Label: "80-100"},
	}

	for _, fb := range allFeedback {
		idx := fb.PredictedConfidence / 20
		if idx >= 5 {
			idx = 4
		}
		buckets[idx].Total++
		if fb.Verdict == "correct" {
			buckets[idx].CorrectCount++
		} else if fb.Verdict == "incorrect" {
			buckets[idx].IncorrectCount++
		}
	}

	for i := range buckets {
		if buckets[i].Total > 0 {
			buckets[i].AccuracyPct = float64(buckets[i].CorrectCount) / float64(buckets[i].Total) * 100
		}
	}

	c.JSON(http.StatusOK, buckets)
}

// ---------- Stub endpoints ----------

// PathCompare handles POST /api/path-analysis/compare.
func (h *Handler) PathCompare(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "Path analysis engine not yet ported",
	})
}

// PathExportJSON handles POST /api/path-analysis/export/json.
func (h *Handler) PathExportJSON(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "Path analysis engine not yet ported",
	})
}

// PathExportHTML handles POST /api/path-analysis/export/html.
func (h *Handler) PathExportHTML(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":  "not implemented",
		"detail": "Path analysis engine not yet ported",
	})
}

// ---------- Saved Queries ----------

// ListSavedQueries handles GET /api/path-analysis/saved-queries.
func (h *Handler) ListSavedQueries(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var queries []models.PathAnalysisSavedQuery
	visibleFilter(h.DB.Model(&models.PathAnalysisSavedQuery{}), user).
		Order("updated_at DESC").
		Find(&queries)

	c.JSON(http.StatusOK, queries)
}

// CreateSavedQuery handles POST /api/path-analysis/saved-queries.
func (h *Handler) CreateSavedQuery(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var q models.PathAnalysisSavedQuery
	if err := c.ShouldBindJSON(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	if q.Scope == "global" && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only admins can create global saved queries"})
		return
	}

	q.OwnerUserID = user.ID
	q.CreatedBy = &user.ID
	if user.TeamID != nil {
		q.TeamID = user.TeamID
	}

	if err := h.DB.Create(&q).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create saved query"})
		return
	}

	c.JSON(http.StatusCreated, q)
}

// GetSavedQuery handles GET /api/path-analysis/saved-queries/:id.
func (h *Handler) GetSavedQuery(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var q models.PathAnalysisSavedQuery
	if err := visibleFilter(h.DB, user).First(&q, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Saved query not found"})
		return
	}

	c.JSON(http.StatusOK, q)
}

// UpdateSavedQuery handles PUT /api/path-analysis/saved-queries/:id.
func (h *Handler) UpdateSavedQuery(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var q models.PathAnalysisSavedQuery
	if err := h.DB.First(&q, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Saved query not found"})
		return
	}

	if q.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only the owner or an admin can edit this query"})
		return
	}

	var updates models.PathAnalysisSavedQuery
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	updates.UpdatedBy = &user.ID
	h.DB.Model(&q).Updates(updates)
	h.DB.First(&q, uint(id))

	c.JSON(http.StatusOK, q)
}

// DeleteSavedQuery handles DELETE /api/path-analysis/saved-queries/:id.
func (h *Handler) DeleteSavedQuery(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var q models.PathAnalysisSavedQuery
	if err := h.DB.First(&q, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Saved query not found"})
		return
	}

	if q.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only the owner or an admin can delete this query"})
		return
	}

	h.DB.Delete(&q)
	c.Status(http.StatusNoContent)
}

// ---------- Presets ----------

// ListPresets handles GET /api/path-analysis/presets.
func (h *Handler) ListPresets(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var presets []models.PathAnalysisRolePreset
	visibleFilter(h.DB.Model(&models.PathAnalysisRolePreset{}), user).
		Order("updated_at DESC").
		Find(&presets)

	c.JSON(http.StatusOK, presets)
}

// CreatePreset handles POST /api/path-analysis/presets.
func (h *Handler) CreatePreset(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	var p models.PathAnalysisRolePreset
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	p.OwnerUserID = user.ID
	p.CreatedBy = &user.ID
	if user.TeamID != nil {
		p.TeamID = user.TeamID
	}

	if err := h.DB.Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "Failed to create preset"})
		return
	}

	c.JSON(http.StatusCreated, p)
}

// GetPreset handles GET /api/path-analysis/presets/:id.
func (h *Handler) GetPreset(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var p models.PathAnalysisRolePreset
	if err := visibleFilter(h.DB, user).First(&p, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Preset not found"})
		return
	}

	c.JSON(http.StatusOK, p)
}

// UpdatePreset handles PUT /api/path-analysis/presets/:id.
func (h *Handler) UpdatePreset(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var p models.PathAnalysisRolePreset
	if err := h.DB.First(&p, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Preset not found"})
		return
	}

	if p.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only the owner or an admin can edit this preset"})
		return
	}

	var updates models.PathAnalysisRolePreset
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid request body"})
		return
	}

	updates.UpdatedBy = &user.ID
	h.DB.Model(&p).Updates(updates)
	h.DB.First(&p, uint(id))

	c.JSON(http.StatusOK, p)
}

// DeletePreset handles DELETE /api/path-analysis/presets/:id.
func (h *Handler) DeletePreset(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "Not authenticated"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid ID"})
		return
	}

	var p models.PathAnalysisRolePreset
	if err := h.DB.First(&p, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "Preset not found"})
		return
	}

	if p.OwnerUserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "Only the owner or an admin can delete this preset"})
		return
	}

	h.DB.Delete(&p)
	c.Status(http.StatusNoContent)
}
