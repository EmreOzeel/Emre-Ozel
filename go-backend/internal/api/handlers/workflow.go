package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
	"gorm.io/gorm"
)

// ---------- helpers ----------

var validWorkflowStates = map[string]bool{
	"new":          true,
	"in_progress":  true,
	"needs_review": true,
	"resolved":     true,
	"dismissed":    true,
}

var validTriageStatuses = map[string]bool{
	"new":            true,
	"acknowledged":   true,
	"in_progress":    true,
	"resolved":       true,
	"false_positive": true,
}

// canManageAnalysis returns true if the user is the owner, assignee, or admin.
func canManageAnalysis(user *models.User, a *models.Analysis) bool {
	if user.IsAdmin {
		return true
	}
	if a.UserID == user.ID {
		return true
	}
	if a.AssignedUserID != nil && *a.AssignedUserID == user.ID {
		return true
	}
	return false
}

// ---------- UpdateWorkflow ----------

// UpdateWorkflow handles PUT /api/analyses/:id/workflow
func (h *Handler) UpdateWorkflow(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	analysisID := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", analysisID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "analysis not found"})
		return
	}

	if !canManageAnalysis(user, &analysis) {
		c.JSON(http.StatusForbidden, gin.H{"detail": "not authorized to update workflow"})
		return
	}

	var body struct {
		WorkflowState string `json:"workflow_state" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "workflow_state is required"})
		return
	}

	if !validWorkflowStates[body.WorkflowState] {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid workflow_state"})
		return
	}

	now := time.Now()
	analysis.WorkflowState = body.WorkflowState
	analysis.WorkflowUpdatedAt = &now
	analysis.WorkflowUpdatedBy = &user.ID

	if err := h.DB.Save(&analysis).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to update workflow"})
		return
	}

	// Create notifications on specific state transitions.
	if body.WorkflowState == "needs_review" || body.WorkflowState == "resolved" {
		notifyUserIDs := map[uint]bool{}
		// Notify the owner if actor is not the owner.
		if analysis.UserID != user.ID {
			notifyUserIDs[analysis.UserID] = true
		}
		// Notify the assignee if actor is not the assignee.
		if analysis.AssignedUserID != nil && *analysis.AssignedUserID != user.ID {
			notifyUserIDs[*analysis.AssignedUserID] = true
		}

		for uid := range notifyUserIDs {
			notif := models.Notification{
				UserID:      uid,
				Type:        "workflow_" + body.WorkflowState,
				AnalysisID:  &analysis.ID,
				ActorUserID: &user.ID,
				Message:     fmt.Sprintf("Analysis %s moved to %s", analysis.Filename, body.WorkflowState),
			}
			h.DB.Create(&notif)
		}
	}

	c.JSON(http.StatusOK, analysis)
}

// ---------- AssignAnalysis ----------

// AssignAnalysis handles PUT /api/analyses/:id/assign
func (h *Handler) AssignAnalysis(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	analysisID := c.Param("id")

	var analysis models.Analysis
	if err := h.DB.First(&analysis, "id = ?", analysisID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "analysis not found"})
		return
	}

	// Only owner or admin can reassign.
	if analysis.UserID != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "only owner or admin can reassign"})
		return
	}

	var body struct {
		UserID uint `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "user_id is required"})
		return
	}

	// Verify assignee exists.
	var assignee models.User
	if err := h.DB.First(&assignee, body.UserID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "target user not found"})
		return
	}

	now := time.Now()
	analysis.AssignedUserID = &body.UserID
	analysis.WorkflowUpdatedAt = &now
	analysis.WorkflowUpdatedBy = &user.ID

	if err := h.DB.Save(&analysis).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to assign analysis"})
		return
	}

	// Notify the new assignee (unless assigning to self).
	if body.UserID != user.ID {
		notif := models.Notification{
			UserID:      body.UserID,
			Type:        "assignment",
			AnalysisID:  &analysis.ID,
			ActorUserID: &user.ID,
			Message:     fmt.Sprintf("You have been assigned analysis %s", analysis.Filename),
		}
		h.DB.Create(&notif)
	}

	c.JSON(http.StatusOK, analysis)
}

// ---------- ListTriage ----------

// ListTriage handles GET /api/analyses/:id/triage
func (h *Handler) ListTriage(c *gin.Context) {
	analysisID := c.Param("id")

	var triages []models.FindingTriage
	if err := h.DB.Where("analysis_id = ?", analysisID).
		Order("created_at desc").
		Find(&triages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to list triage records"})
		return
	}

	c.JSON(http.StatusOK, triages)
}

// ---------- UpdateTriage ----------

// UpdateTriage handles PUT /api/analyses/:id/triage/:finding_key
func (h *Handler) UpdateTriage(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	analysisID := c.Param("id")
	findingKey := c.Param("finding_key")

	var body struct {
		Status string  `json:"status"`
		Note   *string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid request body"})
		return
	}

	if body.Status != "" && !validTriageStatuses[body.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid triage status"})
		return
	}

	var triage models.FindingTriage
	err := h.DB.Where("analysis_id = ? AND finding_key = ?", analysisID, findingKey).First(&triage).Error

	if err == gorm.ErrRecordNotFound {
		// Create new record.
		triage = models.FindingTriage{
			AnalysisID: analysisID,
			FindingKey: findingKey,
			Status:     "new",
			AnalystID:  &user.ID,
		}
		if body.Status != "" {
			triage.Status = body.Status
		}
		if body.Note != nil {
			triage.Note = body.Note
		}
		if err := h.DB.Create(&triage).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to create triage"})
			return
		}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "database error"})
		return
	} else {
		// Update existing record.
		updates := map[string]interface{}{
			"analyst_id": user.ID,
		}
		if body.Status != "" {
			updates["status"] = body.Status
		}
		if body.Note != nil {
			updates["note"] = *body.Note
		}
		if err := h.DB.Model(&triage).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to update triage"})
			return
		}
		// Reload for response.
		h.DB.First(&triage, triage.ID)
	}

	c.JSON(http.StatusOK, triage)
}

// ---------- ListInvestigationNotes ----------

// ListInvestigationNotes handles GET /api/analyses/:id/investigation-notes
func (h *Handler) ListInvestigationNotes(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	analysisID := c.Param("id")

	q := h.DB.Where("analysis_id = ?", analysisID)

	if srcIP := c.Query("source_ip"); srcIP != "" {
		q = q.Where("source_ip = ?", srcIP)
	}
	if dstIP := c.Query("destination_ip"); dstIP != "" {
		q = q.Where("destination_ip = ?", dstIP)
	}
	if dstPort := c.Query("destination_port"); dstPort != "" {
		if port, err := strconv.Atoi(dstPort); err == nil {
			q = q.Where("destination_port = ?", port)
		}
	}

	// Visibility filter: private notes only visible to author, team notes visible to same team.
	q = q.Where(
		h.DB.Where("scope = ? AND created_by = ?", "private", user.ID).
			Or("scope = ? AND (team_id IS NULL OR team_id = ?)", "team", user.TeamID).
			Or("scope = ?", "public"),
	)

	var notes []models.InvestigationNote
	if err := q.Order("created_at desc").Find(&notes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to list notes"})
		return
	}

	c.JSON(http.StatusOK, notes)
}

// ---------- CreateInvestigationNote ----------

// CreateInvestigationNote handles POST /api/analyses/:id/investigation-notes
func (h *Handler) CreateInvestigationNote(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	analysisID := c.Param("id")

	var body struct {
		SourceIP        string `json:"source_ip" binding:"required"`
		DestinationIP   string `json:"destination_ip" binding:"required"`
		DestinationPort *int   `json:"destination_port"`
		Body            string `json:"body" binding:"required"`
		Scope           string `json:"scope"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "source_ip, destination_ip, and body are required"})
		return
	}

	scope := "private"
	if body.Scope != "" {
		scope = body.Scope
	}

	note := models.InvestigationNote{
		AnalysisID:      analysisID,
		SourceIP:        body.SourceIP,
		DestinationIP:   body.DestinationIP,
		DestinationPort: body.DestinationPort,
		Body:            body.Body,
		Scope:           scope,
		CreatedBy:       user.ID,
	}

	// Set team_id if scope is team.
	if scope == "team" && user.TeamID != nil {
		note.TeamID = user.TeamID
	}

	if err := h.DB.Create(&note).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to create note"})
		return
	}

	c.JSON(http.StatusCreated, note)
}

// ---------- UpdateInvestigationNote ----------

// UpdateInvestigationNote handles PUT /api/analyses/:id/investigation-notes/:note_id
func (h *Handler) UpdateInvestigationNote(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	noteID := c.Param("note_id")

	var note models.InvestigationNote
	if err := h.DB.First(&note, noteID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "note not found"})
		return
	}

	if note.CreatedBy != user.ID {
		c.JSON(http.StatusForbidden, gin.H{"detail": "only the author can edit this note"})
		return
	}

	var body struct {
		Body string `json:"body" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "body is required"})
		return
	}

	note.Body = body.Body
	note.UpdatedBy = &user.ID

	if err := h.DB.Save(&note).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to update note"})
		return
	}

	c.JSON(http.StatusOK, note)
}

// ---------- DeleteInvestigationNote ----------

// DeleteInvestigationNote handles DELETE /api/analyses/:id/investigation-notes/:note_id
func (h *Handler) DeleteInvestigationNote(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	noteID := c.Param("note_id")

	var note models.InvestigationNote
	if err := h.DB.First(&note, noteID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "note not found"})
		return
	}

	if note.CreatedBy != user.ID && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"detail": "only the author or admin can delete this note"})
		return
	}

	if err := h.DB.Delete(&note).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to delete note"})
		return
	}

	c.Status(http.StatusNoContent)
}

// ---------- ListUsers ----------

// ListUsers handles GET /api/users
func (h *Handler) ListUsers(c *gin.Context) {
	var users []models.User
	if err := h.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "failed to list users"})
		return
	}

	type userDTO struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
		TeamID   *uint  `json:"team_id"`
	}

	result := make([]userDTO, len(users))
	for i, u := range users {
		result[i] = userDTO{ID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin, TeamID: u.TeamID}
	}

	c.JSON(http.StatusOK, result)
}

// ---------- GetWorkQueue ----------

// workQueueItem is the shape returned for each analysis in a work queue section.
type workQueueItem struct {
	ID             string     `json:"id"`
	Filename       string     `json:"filename"`
	Status         string     `json:"status"`
	WorkflowState  string     `json:"workflow_state"`
	AssignedUserID *uint      `json:"assigned_user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	IssueCount     int        `json:"issue_count"`
	CriticalCount  int        `json:"critical_count"`
}

func analysesToItems(analyses []models.Analysis) []workQueueItem {
	items := make([]workQueueItem, len(analyses))
	for i, a := range analyses {
		items[i] = workQueueItem{
			ID:             a.ID,
			Filename:       a.Filename,
			Status:         a.Status,
			WorkflowState:  a.WorkflowState,
			AssignedUserID: a.AssignedUserID,
			CreatedAt:      a.CreatedAt,
			IssueCount:     a.IssueCount,
			CriticalCount:  a.CriticalCount,
		}
	}
	return items
}

// GetWorkQueue handles GET /api/work-queue
func (h *Handler) GetWorkQueue(c *gin.Context) {
	user := auth.CurrentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"detail": "authentication required"})
		return
	}

	uid := user.ID

	// 1. needs_review: workflow_state="needs_review" AND (assigned to me OR owned by me)
	var needsReview []models.Analysis
	h.DB.Where("workflow_state = ? AND (assigned_user_id = ? OR user_id = ?)", "needs_review", uid, uid).
		Order("workflow_updated_at desc").
		Find(&needsReview)

	// 2. assigned_to_me: assigned to me, state NOT IN (resolved, dismissed)
	var assignedToMe []models.Analysis
	h.DB.Where("assigned_user_id = ? AND workflow_state NOT IN ?", uid, []string{"resolved", "dismissed"}).
		Order("created_at desc").
		Find(&assignedToMe)

	// 3. new_analyses: owned by me, state="new"
	var newAnalyses []models.Analysis
	h.DB.Where("user_id = ? AND workflow_state = ?", uid, "new").
		Order("created_at desc").
		Find(&newAnalyses)

	// 4. unresolved: owned by me, state="in_progress"
	var unresolved []models.Analysis
	h.DB.Where("user_id = ? AND workflow_state = ?", uid, "in_progress").
		Order("created_at desc").
		Find(&unresolved)

	// 5. recent_resolved: owned by me, state IN (resolved, dismissed), limit 10
	var recentResolved []models.Analysis
	h.DB.Where("user_id = ? AND workflow_state IN ?", uid, []string{"resolved", "dismissed"}).
		Order("workflow_updated_at desc").
		Limit(10).
		Find(&recentResolved)

	totalOpen := len(needsReview) + len(assignedToMe) + len(newAnalyses) + len(unresolved)

	c.JSON(http.StatusOK, gin.H{
		"sections": gin.H{
			"needs_review":    analysesToItems(needsReview),
			"assigned_to_me":  analysesToItems(assignedToMe),
			"new_analyses":    analysesToItems(newAnalyses),
			"unresolved":      analysesToItems(unresolved),
			"recent_resolved": analysesToItems(recentResolved),
		},
		"total_open": totalOpen,
		"counts": gin.H{
			"needs_review":    len(needsReview),
			"assigned_to_me":  len(assignedToMe),
			"new_analyses":    len(newAnalyses),
			"unresolved":      len(unresolved),
			"recent_resolved": len(recentResolved),
		},
	})
}
