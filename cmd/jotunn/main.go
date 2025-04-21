package main

import (
	"os"
	"time"

	"github.com/LinharesAron/jotunn/internal/attack"
	"github.com/LinharesAron/jotunn/internal/config"
	"github.com/LinharesAron/jotunn/internal/io"
	"github.com/LinharesAron/jotunn/internal/logger"
)

func main() {

	cfg := config.Load()

	logger.Init(cfg.LogFile)

	logger.Info("🔥 Jötunn – From the blood of giants, only ruin will remains 🔥")
	logger.Info("Starting attack on: %s", cfg.URL)
	logger.Info("Method: %s | Threads: %d", cfg.Method, cfg.Threads)
	logger.Info("Users: %s | Passwords: %s\n", cfg.UserList, cfg.PassList)

	start := time.Now()
	logger.Info("[~] Loading wordlists and initializing...")

	users, err := io.ReadLines(cfg.UserList)
	if err != nil {
		logger.Error("[!] Failed to read users file: %v", err)
		os.Exit(1)
	}

	passwords, err := io.ReadLines(cfg.PassList)
	if err != nil {
		logger.Error("[!] Failed to read passwords file: %v", err)
		os.Exit(1)
	}

	logger.Info("[~] Starting the BruteForce...")
	logger.InitProgressTracker(len(users) * len(passwords))

	dispatcher := attack.NewDispatcher(cfg.Threads, cfg.ThreadsRetry, 1000)
	limiter := attack.NewRateLimitManager(cfg.Threshold, cfg.RateLimitStatusCodes)

	dispatcher.Start(cfg, limiter)
	dispatcher.StartWorkers(cfg, limiter)

	for _, user := range users {
		for _, pass := range passwords {
			dispatcher.Dispatch(attack.Attempt{Username: user, Password: pass})
		}
	}
	dispatcher.CloseAttempts()
	dispatcher.WaitAttemps()

	dispatcher.CloseRetries()
	dispatcher.WaitRetries()

	duration := time.Since(start)
	logger.Info("✅ Done in %s", duration)
}
