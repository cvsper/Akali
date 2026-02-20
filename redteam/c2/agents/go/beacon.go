package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const ZimMemoryAPI = "http://10.0.0.209:5001"

type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Args    string `json:"args"`
}

type Message struct {
	FromAgent string                 `json:"from_agent"`
	ToAgent   string                 `json:"to_agent"`
	Subject   string                 `json:"subject"`
	Body      string                 `json:"body"`
	Priority  string                 `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

func (a *Agent) checkZimMemory() []Task {
	// GET /messages/inbox?agent_id=<agent-id>&status=unread
	url := fmt.Sprintf("%s/messages/inbox?agent_id=%s&status=unread", ZimMemoryAPI, a.ID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return []Task{}
	}
	defer resp.Body.Close()

	var messages []Message
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return []Task{}
	}

	// Convert messages to tasks
	tasks := []Task{}
	for _, msg := range messages {
		// Parse message body as task
		tasks = append(tasks, Task{
			ID:      msg.Subject, // Use subject as task ID
			Command: msg.Body,
			Args:    "",
		})
	}

	return tasks
}

func (a *Agent) reportResult(taskID string, result string) {
	msg := Message{
		FromAgent: a.ID,
		ToAgent:   "akali",
		Subject:   fmt.Sprintf("Task %s complete", taskID),
		Body:      result,
		Priority:  "normal",
	}

	jsonData, _ := json.Marshal(msg)

	url := fmt.Sprintf("%s/messages/send", ZimMemoryAPI)
	client := &http.Client{Timeout: 5 * time.Second}
	client.Post(url, "application/json", bytes.NewBuffer(jsonData))
}
