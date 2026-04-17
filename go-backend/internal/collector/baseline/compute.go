package baseline

import (
	"log"

	"gorm.io/gorm"
)

// ComputeBaselines recalculates IP baselines from historical flow data.
// This is a stub that will be implemented with statistical analysis.
func ComputeBaselines(db *gorm.DB) {
	log.Println("[baseline] computation not yet implemented")
}
