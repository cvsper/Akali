package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

type Agent struct {
	ID             string
	Hostname       string
	Platform       string
	Mode           string
	BeaconInterval time.Duration
}

func NewAgent(mode string) *Agent {
	hostname, _ := os.Hostname()

	return &Agent{
		ID:             generateID(),
		Hostname:       hostname,
		Platform:       runtime.GOOS,
		Mode:           mode,
		BeaconInterval: 30 * time.Second,
	}
}

func generateID() string {
	// Simple ID generation (improve later)
	return fmt.Sprintf("agent-%d", time.Now().Unix())
}

func (a *Agent) Run() {
	fmt.Printf("[*] Agent %s started on %s (%s)\n", a.ID, a.Hostname, a.Platform)
	fmt.Printf("[*] Mode: %s, Beacon interval: %s\n", a.Mode, a.BeaconInterval)

	for {
		a.beacon()
		time.Sleep(a.BeaconInterval)
	}
}

func (a *Agent) beacon() {
	fmt.Printf("[*] Beacon from %s\n", a.ID)
	// TODO: Check for commands
}

func main() {
	agent := NewAgent("zim")
	agent.Run()
}
