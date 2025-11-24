package main

import (
	pb "silkwire/proto"

	"github.com/sirupsen/logrus"
)

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