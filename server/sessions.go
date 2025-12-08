package main

import (
	pb "silkwire/proto"

	"github.com/sirupsen/logrus"
)

// loadListenersFromDB loads and restarts active listeners from database on server startup
func (s *C2Server) loadListenersFromDB() {
	listeners, err := s.db.GetActiveListeners()
	if err != nil {
		logrus.Errorf("Error loading listeners from database: %v", err)
		return
	}

	if len(listeners) == 0 {
		logrus.Info("No active listeners to restore from database")
		return
	}

	logrus.Infof("Restoring %d listener(s) from database...", len(listeners))

	for _, dbListener := range listeners {
		// Convert stored type string back to proto enum
		listenerType := pb.ListenerType_LISTENER_HTTPS // default
		if val, ok := pb.ListenerType_value[dbListener.Type]; ok {
			listenerType = pb.ListenerType(val)
		}

		// Build the request to restart the listener
		req := &pb.ListenerAddRequest{
			Address:  dbListener.Address,
			Type:     listenerType,
			CertFile: dbListener.CertFile,
			KeyFile:  dbListener.KeyFile,
			CaFile:   dbListener.CaFile,
		}

		// Use existing restartListener which handles persistent certificates
		if err := s.restartListener(dbListener.ListenerID, req); err != nil {
			logrus.Errorf("Failed to restore listener %s (%s): %v", dbListener.ListenerID, dbListener.Address, err)
			s.db.UpdateListenerStatus(dbListener.ListenerID, "failed")
		} else {
			logrus.Infof("Restored listener %s on %s (%s)", dbListener.ListenerID, dbListener.Address, dbListener.Type)
		}
	}
}

// loadSessionsFromDB loads existing sessions from database into memory
func (s *C2Server) loadSessionsFromDB() {
	sessions, err := s.db.GetAllSessions()
	if err != nil {
		logrus.Errorf("Error loading sessions from database: %v", err)
		return
	}

	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()

	for _, session := range sessions {
		s.sessions[session.ImplantID] = session
		// Create task queue for existing sessions
		s.queuesMux.Lock()
		s.taskQueues[session.ImplantID] = make(chan *pb.Task, 100)
		s.queuesMux.Unlock()
	}

	logrus.Infof("Loaded %d sessions from database", len(sessions))
}