package db

import (
	"log"
	"os"
	"strings"
	"time"

	"modern-dns/config"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitMySQL() {
	dsn := config.C.MySQL.DSN
	// Append interpolateParams to avoid extra Prepare round-trip on remote DB
	if !strings.Contains(dsn, "interpolateParams") {
		if strings.Contains(dsn, "?") {
			dsn += "&interpolateParams=true"
		} else {
			dsn += "?interpolateParams=true"
		}
	}

	slowLogger := logger.New(
		log.New(os.Stdout, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second, // 1s (remote DB friendly)
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
		},
	)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:      slowLogger,
		PrepareStmt: true, // cache prepared statements
	})
	if err != nil {
		log.Fatalf("[mysql] connect failed: %v", err)
	}

	sqlDB, _ := DB.DB()
	sqlDB.SetMaxOpenConns(50)
	sqlDB.SetMaxIdleConns(25) // keep more idle conns alive for remote DB
	sqlDB.SetConnMaxLifetime(10 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	log.Println("[mysql] connected")
}

// ApplyPool re-tunes the live *sql.DB pool. Called on startup (after
// system_config is loaded) and on every save of the General Settings
// page so operators can adjust pool sizing under load without a
// restart. Zero on any field means "keep the current value", which is
// what we want when an older config row is loaded that doesn't have
// the new columns populated yet.
func ApplyPool(maxOpen, maxIdle, connMaxLifetimeMin, connMaxIdleMin int) {
	if DB == nil {
		return
	}
	sqlDB, err := DB.DB()
	if err != nil || sqlDB == nil {
		return
	}
	if maxOpen > 0 {
		sqlDB.SetMaxOpenConns(maxOpen)
	}
	if maxIdle >= 0 {
		// 0 is a valid value for MaxIdleConns (means "no idle pool"),
		// distinct from "leave unchanged"; the API contract here is
		// "negative means unchanged".
		sqlDB.SetMaxIdleConns(maxIdle)
	}
	if connMaxLifetimeMin > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(connMaxLifetimeMin) * time.Minute)
	}
	if connMaxIdleMin > 0 {
		sqlDB.SetConnMaxIdleTime(time.Duration(connMaxIdleMin) * time.Minute)
	}
	log.Printf("[mysql] pool tuned: maxOpen=%d maxIdle=%d lifetime=%dm idle=%dm",
		maxOpen, maxIdle, connMaxLifetimeMin, connMaxIdleMin)
}
