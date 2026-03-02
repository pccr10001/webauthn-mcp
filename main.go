package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pccr10001/webauthn-mcp/config"
	"github.com/pccr10001/webauthn-mcp/internal/api"
	"github.com/pccr10001/webauthn-mcp/internal/mcp"
	"github.com/pccr10001/webauthn-mcp/internal/token"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize storage
	storage, err := token.NewStorage(cfg.Storage.Path)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Check if running as MCP server (via stdio)
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		runMCPServer(storage)
		return
	}

	// Run HTTP server
	runHTTPServer(cfg, storage)
}

func runMCPServer(storage *token.Storage) {
	mcpServer := mcp.NewMCPServer(storage)
	if err := mcpServer.Serve(); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

func runHTTPServer(cfg *config.Config, storage *token.Storage) {
	router := api.NewRouter(storage)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	log.Printf("Starting WebAuthn MCP server on %s", addr)

	if cfg.Security.APIKey != "" {
		log.Printf("API Key authentication enabled")
	}

	if err := router.Run(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
