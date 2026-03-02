package api

import (
	"github.com/gin-gonic/gin"
	"github.com/pccr10001/webauthn-mcp/internal/token"
)

func NewRouter(storage *token.Storage) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(CORS())

	handler := NewHandler(storage)

	api := r.Group("/api")
	api.Use(APIKeyAuth())
	{
		// Token endpoints
		api.POST("/token", handler.CreateToken)
		api.GET("/token", handler.ListTokens)
		api.GET("/token/:id", handler.GetToken)
		api.DELETE("/token/:id", handler.DeleteToken)

		// Credential endpoints
		api.GET("/token/:id/credentials", handler.ListCredentials)
		api.DELETE("/token/:id/credentials/:credId", handler.DeleteCredential)

		// WebAuthn endpoints
		api.POST("/token/:id/register", handler.Register)
		api.POST("/token/:id/authenticate", handler.Authenticate)
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	return r
}
