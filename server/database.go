package main

import (
	"encoding/json"
	"silkwire/shared"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database holds the database connection and methods
type Database struct {
	db *gorm.DB
}

// NewDatabase creates a new database connection
func NewDatabase(dbPath string) (*Database, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Reduce log noise
	})
	if err != nil {
		return nil, err
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(
		&DBSession{},
		&DBCommand{},
		&DBCommandResult{},
		&DBListener{},
		&DBTask{},
		&DBImplantBuild{},
	)
	if err != nil {
		return nil, err
	}

	database := &Database{db: db}

	// Populate codenames for existing sessions that don't have them
	err = database.populateCodenames()
	if err != nil {
		return nil, err
	}

	return database, nil
}

// Session operations
func (d *Database) SaveSession(session *Session) error {
	networkIfacesJSON, _ := json.Marshal(session.NetworkIfaces)

	dbSession := &DBSession{
		ImplantID:     session.ImplantID,
		SessionToken:  session.SessionToken,
		Codename:      session.Codename,
		Hostname:      session.Hostname,
		Username:      session.Username,
		OS:            session.OS,
		Arch:          session.Arch,
		ProcessName:   session.ProcessName,
		PID:           session.PID,
		NetworkIfaces: string(networkIfacesJSON),
		LastSeen:      session.LastSeen,
		Transport:     session.Transport,
		CreatedAt:     session.Created,
	}

	return d.db.Create(dbSession).Error
}

func (d *Database) UpdateSessionLastSeen(implantID string, lastSeen time.Time) error {
	return d.db.Model(&DBSession{}).Where("implant_id = ?", implantID).Update("last_seen", lastSeen).Error
}

func (d *Database) UpdateSessionTransport(implantID string, transport string) error {
	return d.db.Model(&DBSession{}).Where("implant_id = ?", implantID).Update("transport", transport).Error
}

func (d *Database) GetSession(implantID string) (*Session, error) {
	var dbSession DBSession
	err := d.db.Where("implant_id = ?", implantID).First(&dbSession).Error
	if err != nil {
		return nil, err
	}

	var networkIfaces []string
	json.Unmarshal([]byte(dbSession.NetworkIfaces), &networkIfaces)

	return &Session{
		ImplantID:     dbSession.ImplantID,
		SessionToken:  dbSession.SessionToken,
		Codename:      dbSession.Codename,
		Hostname:      dbSession.Hostname,
		Username:      dbSession.Username,
		OS:            dbSession.OS,
		Arch:          dbSession.Arch,
		ProcessName:   dbSession.ProcessName,
		PID:           dbSession.PID,
		NetworkIfaces: networkIfaces,
		LastSeen:      dbSession.LastSeen,
		Created:       dbSession.CreatedAt,
		Transport:     dbSession.Transport,
	}, nil
}

func (d *Database) GetAllSessions() ([]*Session, error) {
	var dbSessions []DBSession
	err := d.db.Find(&dbSessions).Error
	if err != nil {
		return nil, err
	}

	var sessions []*Session
	for _, dbSession := range dbSessions {
		var networkIfaces []string
		json.Unmarshal([]byte(dbSession.NetworkIfaces), &networkIfaces)

		session := &Session{
			ImplantID:     dbSession.ImplantID,
			SessionToken:  dbSession.SessionToken,
			Codename:      dbSession.Codename,
			Hostname:      dbSession.Hostname,
			Username:      dbSession.Username,
			OS:            dbSession.OS,
			Arch:          dbSession.Arch,
			ProcessName:   dbSession.ProcessName,
			PID:           dbSession.PID,
			NetworkIfaces: networkIfaces,
			LastSeen:      dbSession.LastSeen,
			Created:       dbSession.CreatedAt,
			Transport:     dbSession.Transport,
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (d *Database) DeleteSession(implantID string) error {
	return d.db.Where("implant_id = ?", implantID).Delete(&DBSession{}).Error
}

// Command operations
func (d *Database) SaveCommand(commandID, implantID, cmdType, command string, args []string, data []byte, timeout int32) error {
	argsJSON, _ := json.Marshal(args)

	dbCommand := &DBCommand{
		CommandID: commandID,
		ImplantID: implantID,
		Type:      cmdType,
		Command:   command,
		Args:      string(argsJSON),
		Data:      data,
		Timeout:   timeout,
		Status:    "pending",
	}

	return d.db.Create(dbCommand).Error
}

func (d *Database) UpdateCommandStatus(commandID, status string) error {
	return d.db.Model(&DBCommand{}).Where("command_id = ?", commandID).Update("status", status).Error
}

func (d *Database) GetCommand(commandID string) (*DBCommand, error) {
	var dbCommand DBCommand
	err := d.db.Where("command_id = ?", commandID).First(&dbCommand).Error
	if err != nil {
		return nil, err
	}
	return &dbCommand, nil
}

func (d *Database) GetCommandsByImplant(implantID string, limit int) ([]DBCommand, error) {
	var commands []DBCommand
	if limit <= 0 {
		limit = 100
	}
	err := d.db.Where("implant_id = ?", implantID).Order("created_at desc").Limit(limit).Find(&commands).Error
	return commands, err
}

func (d *Database) GetRecentCommands(limit int) ([]DBCommand, error) {
	var commands []DBCommand
	if limit <= 0 {
		limit = 100
	}
	err := d.db.Order("created_at desc").Limit(limit).Find(&commands).Error
	return commands, err
}

// Command result operations
func (d *Database) SaveCommandResult(result *CommandResult) error {
	dbResult := &DBCommandResult{
		CommandID: result.CommandID,
		ImplantID: "", // We'll need to get this from the command
		Success:   result.Success,
		Output:    result.Output,
		Error:     result.Error,
	}

	// Get implant ID from command
	var dbCommand DBCommand
	if err := d.db.Where("command_id = ?", result.CommandID).First(&dbCommand).Error; err == nil {
		dbResult.ImplantID = dbCommand.ImplantID
	}

	return d.db.Create(dbResult).Error
}

func (d *Database) GetCommandResult(commandID string) (*CommandResult, error) {
	var dbResult DBCommandResult
	err := d.db.Where("command_id = ?", commandID).First(&dbResult).Error
	if err != nil {
		return nil, err
	}

	return &CommandResult{
		CommandID: dbResult.CommandID,
		Success:   dbResult.Success,
		Output:    dbResult.Output,
		Error:     dbResult.Error,
		Timestamp: dbResult.CreatedAt,
	}, nil
}

// Task operations
func (d *Database) SaveTask(taskID, implantID, taskType, command string, args []string, data []byte, timeout int32) error {
	argsJSON, _ := json.Marshal(args)

	dbTask := &DBTask{
		TaskID:    taskID,
		ImplantID: implantID,
		Type:      taskType,
		Command:   command,
		Args:      string(argsJSON),
		Data:      data,
		Timeout:   timeout,
		Status:    "queued",
	}

	return d.db.Create(dbTask).Error
}

func (d *Database) UpdateTaskStatus(taskID, status string) error {
	return d.db.Model(&DBTask{}).Where("task_id = ?", taskID).Update("status", status).Error
}

func (d *Database) GetPendingTasksByImplant(implantID string) ([]DBTask, error) {
	var tasks []DBTask
	err := d.db.Where("implant_id = ? AND status IN ?", implantID, []string{"queued", "sent"}).Order("created_at asc").Find(&tasks).Error
	return tasks, err
}

// Listener operations
func (d *Database) SaveListener(listenerID, address, listenerType, certFile, keyFile, caFile string) error {
	dbListener := &DBListener{
		ListenerID: listenerID,
		Address:    address,
		Type:       listenerType,
		CertFile:   certFile,
		KeyFile:    keyFile,
		CaFile:     caFile,
		StartedAt:  time.Now(),
		Status:     "running",
	}

	return d.db.Create(dbListener).Error
}

func (d *Database) UpdateListenerStopped(listenerID string) error {
	now := time.Now()
	return d.db.Model(&DBListener{}).Where("listener_id = ?", listenerID).Updates(map[string]interface{}{
		"stopped_at": &now,
		"status":     "stopped",
	}).Error
}

func (d *Database) UpdateListenerStatus(listenerID string, status string) error {
	updates := map[string]interface{}{
		"status": status,
	}

	if status == "stopped" || status == "failed" {
		now := time.Now()
		updates["stopped_at"] = &now
	}

	return d.db.Model(&DBListener{}).Where("listener_id = ?", listenerID).Updates(updates).Error
}

func (d *Database) GetAllListeners() ([]DBListener, error) {
	var listeners []DBListener
	err := d.db.Find(&listeners).Error
	return listeners, err
}

func (d *Database) GetActiveListeners() ([]DBListener, error) {
	var listeners []DBListener
	err := d.db.Where("status = ?", "running").Find(&listeners).Error
	return listeners, err
}

// Utility functions
func (d *Database) Close() error {
	if db, err := d.db.DB(); err == nil {
		return db.Close()
	}
	return nil
}

// CleanupOldSessions removes sessions that haven't been seen for a specified duration
func (d *Database) CleanupOldSessions(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)
	return d.db.Where("last_seen < ?", cutoff).Delete(&DBSession{}).Error
}

// GetSessionStats returns basic statistics about sessions
func (d *Database) GetSessionStats() (map[string]int64, error) {
	stats := make(map[string]int64)

	// Total sessions
	var total int64
	if err := d.db.Model(&DBSession{}).Count(&total).Error; err != nil {
		return nil, err
	}
	stats["total"] = total

	// Active sessions (seen in last 10 minutes)
	var active int64
	tenMinutesAgo := time.Now().Add(-10 * time.Minute)
	if err := d.db.Model(&DBSession{}).Where("last_seen > ?", tenMinutesAgo).Count(&active).Error; err != nil {
		return nil, err
	}
	stats["active"] = active

	// Commands executed today
	var commandsToday int64
	today := time.Now().Truncate(24 * time.Hour)
	if err := d.db.Model(&DBCommand{}).Where("created_at > ?", today).Count(&commandsToday).Error; err != nil {
		return nil, err
	}
	stats["commands_today"] = commandsToday

	return stats, nil
}

// populateCodenames generates codenames for existing sessions that don't have them
func (d *Database) populateCodenames() error {
	var sessions []DBSession

	// Find sessions without codenames
	err := d.db.Where("codename = ? OR codename IS NULL", "").Find(&sessions).Error
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return nil // No sessions need codenames
	}

	// Generate codenames for sessions that need them
	for _, session := range sessions {
		codename := shared.GenerateCodename()
		err := d.db.Model(&session).Update("codename", codename).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// Implant build operations
func (d *Database) SaveImplantBuild(build *DBImplantBuild) error {
	return d.db.Create(build).Error
}

func (d *Database) GetImplantBuild(buildID string) (*DBImplantBuild, error) {
	var build DBImplantBuild
	err := d.db.Where("build_id = ?", buildID).First(&build).Error
	if err != nil {
		return nil, err
	}
	return &build, nil
}

func (d *Database) GetAllImplantBuilds() ([]DBImplantBuild, error) {
	var builds []DBImplantBuild
	err := d.db.Order("created_at desc").Find(&builds).Error
	return builds, err
}

func (d *Database) DeleteImplantBuild(buildID string) error {
	return d.db.Where("build_id = ?", buildID).Delete(&DBImplantBuild{}).Error
}
