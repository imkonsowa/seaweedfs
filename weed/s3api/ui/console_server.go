package ui

import (
	"context"
	"crypto/rand"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/seaweedfs/seaweedfs/weed/s3api"
	"github.com/seaweedfs/seaweedfs/weed/s3api/ui/handlers"
)

//go:embed static/*
var staticFS embed.FS

// ConsoleConfig holds console server configuration
type ConsoleConfig struct {
	Port        int    `json:"port"`
	AdminKey    string `json:"admin_key"`
	AdminSecret string `json:"admin_secret"`
}

// ConsoleServer manages the console web server
type ConsoleServer struct {
	config     ConsoleConfig
	s3Ops      *s3api.S3Operations
	handlers   *handlers.ConsoleHandlers
	httpServer *http.Server
}

// NewConsoleServer creates a new console server instance
func NewConsoleServer(config ConsoleConfig, s3Ops *s3api.S3Operations) (*ConsoleServer, error) {
	if config.Port <= 0 {
		return nil, fmt.Errorf("invalid console port: %d", config.Port)
	}

	if config.AdminKey == "" || config.AdminSecret == "" {
		return nil, fmt.Errorf("console admin credentials are required")
	}

	adminCred := s3api.ConsoleCredential{
		AccessKey: config.AdminKey,
		SecretKey: config.AdminSecret,
	}

	// Create console handlers
	consoleHandlers := handlers.NewConsoleHandlers(s3Ops, adminCred)

	server := &ConsoleServer{
		config:   config,
		s3Ops:    s3Ops,
		handlers: consoleHandlers,
	}

	return server, nil
}

// Start starts the console server
func (cs *ConsoleServer) Start(ctx context.Context) error {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Session store - auto-generate session key
	sessionKeyBytes := make([]byte, 32)
	_, err := rand.Read(sessionKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to generate session key: %w", err)
	}
	store := cookie.NewStore(sessionKeyBytes)
	r.Use(sessions.Sessions("console-session", store))

	// Static files - serve from embedded filesystem
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("failed to create static sub filesystem: %w", err)
	}
	r.StaticFS("/static", http.FS(staticSubFS))

	// Setup console routes
	cs.handlers.SetupRoutes(r)

	// Create HTTP server
	addr := fmt.Sprintf(":%d", cs.config.Port)
	cs.httpServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting SeaweedFS S3 Console on port %d", cs.config.Port)
		log.Printf("Console URL: http://localhost:%d/ui/", cs.config.Port)

		if err := cs.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Console server error: %v", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	log.Println("Shutting down console server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := cs.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("console server forced to shutdown: %w", err)
	}

	return nil
}

// Stop stops the console server
func (cs *ConsoleServer) Stop() error {
	if cs.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return cs.httpServer.Shutdown(ctx)
	}
	return nil
}

// GetStaticFS returns the embedded static filesystem for external use
func GetStaticFS() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}
