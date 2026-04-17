package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/emreozeel/pcap-analyzer/backend/internal/auth"
	"github.com/emreozeel/pcap-analyzer/backend/internal/models"
)

var (
	validConditionOperators = map[string]bool{
		"eq": true, "neq": true, "gt": true, "lt": true,
		"gte": true, "lte": true, "in": true, "contains": true,
	}
	validAggregationTypes = map[string]bool{
		"count": true, "distinct_count": true, "sum": true, "avg": true, "any": true,
	}
	validTargetEntities = map[string]bool{
		"source_ip": true, "destination_ip": true, "src_dst_pair": true,
	}
	validSeverities = map[string]bool{
		"low": true, "medium": true, "high": true, "critical": true,
	}
)

// correlationRuleInput is the JSON body for create/update.
type correlationRuleInput struct {
	Name                 string  `json:"name" binding:"required"`
	Description          *string `json:"description"`
	Enabled              *bool   `json:"enabled"`
	Scope                string  `json:"scope"`
	ConditionField       string  `json:"condition_field" binding:"required"`
	ConditionOperator    string  `json:"condition_operator" binding:"required"`
	ConditionValue       string  `json:"condition_value" binding:"required"`
	AggregationType      string  `json:"aggregation_type" binding:"required"`
	AggregationField     *string `json:"aggregation_field"`
	Threshold            float64 `json:"threshold"`
	TimeWindowMinutes    int     `json:"time_window_minutes"`
	TargetEntity         string  `json:"target_entity" binding:"required"`
	Severity             string  `json:"severity" binding:"required"`
	IncidentBehaviorType string  `json:"incident_behavior_type" binding:"required"`
	CooldownMinutes      int     `json:"cooldown_minutes"`
}

func validateCorrelationRule(input *correlationRuleInput) string {
	if !validConditionOperators[input.ConditionOperator] {
		return "invalid condition_operator"
	}
	if !validAggregationTypes[input.AggregationType] {
		return "invalid aggregation_type"
	}
	if !validTargetEntities[input.TargetEntity] {
		return "invalid target_entity"
	}
	if !validSeverities[input.Severity] {
		return "invalid severity"
	}
	return ""
}

// canSeeRule checks whether the user can view the given rule.
func canSeeRule(user *models.User, rule *models.CorrelationRule) bool {
	if rule.Scope == "global" {
		return true
	}
	return rule.CreatedBy != nil && *rule.CreatedBy == user.ID
}

// canEditRule checks whether the user can edit/delete the given rule.
func canEditRule(user *models.User, rule *models.CorrelationRule) bool {
	if user.IsAdmin {
		return true
	}
	return rule.CreatedBy != nil && *rule.CreatedBy == user.ID
}

// ListCorrelationRules returns rules visible to the current user.
func (h *Handler) ListCorrelationRules(c *gin.Context) {
	user := auth.CurrentUser(c)

	var rules []models.CorrelationRule
	h.DB.Where("scope = ? OR created_by = ?", "global", user.ID).
		Order("created_at desc").
		Find(&rules)

	c.JSON(http.StatusOK, rules)
}

// CreateCorrelationRule creates a new correlation rule.
func (h *Handler) CreateCorrelationRule(c *gin.Context) {
	user := auth.CurrentUser(c)

	var input correlationRuleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if msg := validateCorrelationRule(&input); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	if input.Scope == "global" && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "only admins can create global rules"})
		return
	}
	if input.Scope == "" {
		input.Scope = "user"
	}

	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	rule := models.CorrelationRule{
		Name:                 input.Name,
		Description:          input.Description,
		Enabled:              enabled,
		CreatedBy:            &user.ID,
		Scope:                input.Scope,
		ConditionField:       input.ConditionField,
		ConditionOperator:    input.ConditionOperator,
		ConditionValue:       input.ConditionValue,
		AggregationType:      input.AggregationType,
		AggregationField:     input.AggregationField,
		Threshold:            input.Threshold,
		TimeWindowMinutes:    input.TimeWindowMinutes,
		TargetEntity:         input.TargetEntity,
		Severity:             input.Severity,
		IncidentBehaviorType: input.IncidentBehaviorType,
		CooldownMinutes:      input.CooldownMinutes,
	}

	if err := h.DB.Create(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rule"})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// GetCorrelationRule returns a single rule if visible to the user.
func (h *Handler) GetCorrelationRule(c *gin.Context) {
	user := auth.CurrentUser(c)

	var rule models.CorrelationRule
	if err := h.DB.First(&rule, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	if !canSeeRule(user, &rule) {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// UpdateCorrelationRule updates an existing rule (creator or admin only).
func (h *Handler) UpdateCorrelationRule(c *gin.Context) {
	user := auth.CurrentUser(c)

	var rule models.CorrelationRule
	if err := h.DB.First(&rule, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	if !canEditRule(user, &rule) {
		c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
		return
	}

	var input correlationRuleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if msg := validateCorrelationRule(&input); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	if input.Scope == "global" && !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "only admins can set scope to global"})
		return
	}

	enabled := rule.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	rule.Name = input.Name
	rule.Description = input.Description
	rule.Enabled = enabled
	rule.Scope = input.Scope
	rule.ConditionField = input.ConditionField
	rule.ConditionOperator = input.ConditionOperator
	rule.ConditionValue = input.ConditionValue
	rule.AggregationType = input.AggregationType
	rule.AggregationField = input.AggregationField
	rule.Threshold = input.Threshold
	rule.TimeWindowMinutes = input.TimeWindowMinutes
	rule.TargetEntity = input.TargetEntity
	rule.Severity = input.Severity
	rule.IncidentBehaviorType = input.IncidentBehaviorType
	rule.CooldownMinutes = input.CooldownMinutes

	if err := h.DB.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update rule"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// DeleteCorrelationRule deletes a rule (creator or admin only).
func (h *Handler) DeleteCorrelationRule(c *gin.Context) {
	user := auth.CurrentUser(c)

	var rule models.CorrelationRule
	if err := h.DB.First(&rule, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	if !canEditRule(user, &rule) {
		c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
		return
	}

	h.DB.Delete(&rule)
	c.Status(http.StatusNoContent)
}

// ToggleCorrelationRule toggles the enabled field and returns the updated rule.
func (h *Handler) ToggleCorrelationRule(c *gin.Context) {
	user := auth.CurrentUser(c)

	var rule models.CorrelationRule
	if err := h.DB.First(&rule, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	if !canEditRule(user, &rule) {
		c.JSON(http.StatusForbidden, gin.H{"error": "permission denied"})
		return
	}

	rule.Enabled = !rule.Enabled
	h.DB.Save(&rule)

	c.JSON(http.StatusOK, rule)
}
