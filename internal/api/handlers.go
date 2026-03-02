package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pccr10001/webauthn-mcp/internal/token"
	"github.com/pccr10001/webauthn-mcp/internal/webauthn"
)

type Handler struct {
	storage *token.Storage
}

func NewHandler(storage *token.Storage) *Handler {
	return &Handler{storage: storage}
}

// POST /api/token
func (h *Handler) CreateToken(c *gin.Context) {
	var req CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body
		req = CreateTokenRequest{}
	}

	tok := token.NewToken(req.Name)
	if err := h.storage.Save(tok); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "storage_error",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, TokenResponse{
		ID:              tok.ID,
		Name:            tok.Name,
		CreatedAt:       tok.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		CredentialCount: len(tok.Credentials),
	})
}

// GET /api/token
func (h *Handler) ListTokens(c *gin.Context) {
	tokens := h.storage.List()
	resp := make([]TokenResponse, len(tokens))
	for i, tok := range tokens {
		resp[i] = TokenResponse{
			ID:              tok.ID,
			Name:            tok.Name,
			CreatedAt:       tok.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			CredentialCount: len(tok.Credentials),
		}
	}
	c.JSON(http.StatusOK, resp)
}

// GET /api/token/:id
func (h *Handler) GetToken(c *gin.Context) {
	id := c.Param("id")
	tok, err := h.storage.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Token not found",
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		ID:              tok.ID,
		Name:            tok.Name,
		CreatedAt:       tok.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		CredentialCount: len(tok.Credentials),
	})
}

// DELETE /api/token/:id
func (h *Handler) DeleteToken(c *gin.Context) {
	id := c.Param("id")
	if err := h.storage.Delete(id); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Token not found",
		})
		return
	}
	c.Status(http.StatusNoContent)
}

// GET /api/token/:id/credentials
func (h *Handler) ListCredentials(c *gin.Context) {
	id := c.Param("id")
	tok, err := h.storage.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Token not found",
		})
		return
	}

	resp := make([]CredentialResponse, len(tok.Credentials))
	for i, cred := range tok.Credentials {
		resp[i] = CredentialResponse{
			CredentialID:    cred.CredentialID,
			RPId:            cred.RPId,
			UserHandle:      cred.UserHandle,
			UserName:        cred.UserName,
			UserDisplayName: cred.UserDisplayName,
			Counter:         cred.Counter,
			ResidentKey:     cred.ResidentKey,
			CreatedAt:       cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	c.JSON(http.StatusOK, resp)
}

// DELETE /api/token/:id/credentials/:credId
func (h *Handler) DeleteCredential(c *gin.Context) {
	id := c.Param("id")
	credId := c.Param("credId")

	tok, err := h.storage.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Token not found",
		})
		return
	}

	if err := tok.DeleteCredential(credId); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Credential not found",
		})
		return
	}

	if err := h.storage.Save(tok); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "storage_error",
			Message: err.Error(),
		})
		return
	}

	c.Status(http.StatusNoContent)
}

// POST /api/token/:id/register
func (h *Handler) Register(c *gin.Context) {
	id := c.Param("id")
	tok, err := h.storage.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Token not found",
		})
		return
	}

	var req RegisterRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	resp, cred, err := webauthn.Register(tok, req.Request, req.Overrides)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "registration_failed",
			Message: err.Error(),
		})
		return
	}

	// Save credential to token
	tok.AddCredential(*cred)
	if err := h.storage.Save(tok); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "storage_error",
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, RegisterResponseDTO{
		Response: resp,
		Credential: &CredentialResponse{
			CredentialID:    cred.CredentialID,
			RPId:            cred.RPId,
			UserHandle:      cred.UserHandle,
			UserName:        cred.UserName,
			UserDisplayName: cred.UserDisplayName,
			Counter:         cred.Counter,
			ResidentKey:     cred.ResidentKey,
			CreatedAt:       cred.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
	})
}

// POST /api/token/:id/authenticate
func (h *Handler) Authenticate(c *gin.Context) {
	id := c.Param("id")
	tok, err := h.storage.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "not_found",
			Message: "Token not found",
		})
		return
	}

	var req AuthenticateRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
		})
		return
	}

	// Find credential
	var cred *token.Credential
	if req.CredentialID != "" {
		cred, err = tok.GetCredential(req.CredentialID)
	} else if len(req.Request.AllowCredentials) > 0 {
		// Try to find matching credential
		for _, allowed := range req.Request.AllowCredentials {
			cred, err = tok.GetCredential(allowed.ID)
			if err == nil {
				break
			}
		}
	} else {
		// Resident key mode - find by RP ID
		cred, err = tok.GetCredentialByRPId(req.Request.RPId)
	}

	if err != nil || cred == nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "credential_not_found",
			Message: "No matching credential found",
		})
		return
	}

	resp, err := webauthn.Authenticate(cred, req.Request, req.Overrides)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "authentication_failed",
			Message: err.Error(),
		})
		return
	}

	// Update counter (unless overridden)
	if req.Overrides == nil || req.Overrides.Counter == nil {
		cred.IncrementCounter()
		if err := h.storage.Save(tok); err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error:   "storage_error",
				Message: err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, AuthenticateResponseDTO{
		Response: resp,
		Counter:  cred.Counter,
	})
}
