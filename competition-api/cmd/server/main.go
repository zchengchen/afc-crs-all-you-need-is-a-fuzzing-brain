package main

import (
    "log"
    "os"
    "strings"
    "net/http"
    _ "net/http/pprof"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    
    "competition-api/internal/handlers"
    "competition-api/internal/telemetry"
)

// maskSensitiveHeaders masks sensitive values in headers for logging
func maskSensitiveHeaders(headers map[string]string) map[string]string {
    maskedHeaders := make(map[string]string)
    for k, v := range headers {
        if strings.Contains(strings.ToLower(k), "authorization") ||
           strings.Contains(strings.ToLower(k), "token") ||
           strings.Contains(strings.ToLower(k), "key") {
            maskedHeaders[k] = "<redacted>"
        } else {
            maskedHeaders[k] = v
        }
    }
    return maskedHeaders
}

func setupRouter(apiKeyID, apiToken string) *gin.Engine {
    // Create default gin router
    r := gin.Default()

    // Create new handler instance
    h := handlers.NewHandler()
    if os.Getenv("LOCAL_TEST") != "" {
        h.SetHostAPIBaseURL("http://localhost:1323")
    }

    r.POST("/sarifx/", h.SubmitSARIFX)

    // Authenticated routes
    v1 := r.Group("/v1", gin.BasicAuth(gin.Accounts{
        apiKeyID: apiToken,
    }))
    {
        // Ping endpoint
        v1.GET("/ping/", h.Ping)
        
        v1.GET("/task/:task_id/pov_stats/", h.GetPOVStats)

        // v1.GET("/task/:task_id/valid_povs/", h.GetTaskValidPOVs)
        v1.POST("/sarifx/invalid/:task_id/:broadcast_sarif_id/", h.SubmitSarifInvalid)
        v1.POST("/sarifx/:task_id/:broadcast_sarif_id/", h.CheckSarifValidity)
        v1.POST("/sarifx/check_invalid/:task_id/:broadcast_sarif_id/", h.CheckSarifInValidity)
        // POV endpoints
        v1.POST("/task/:task_id/pov/", h.SubmitPOV)
        // v1.GET("/task/:task_id/pov/:pov_id/", h.GetPOVStatus)
        // Patch endpoints
        v1.POST("/task/:task_id/patch/", h.SubmitPatch)
        // v1.GET("/task/:task_id/patch/:patch_id/", h.GetPatchStatus)

        // Freeform endpoint
        v1.POST("/task/:task_id/freeform/pov/", h.SubmitFreeformPOV)
        v1.POST("/task/:task_id/freeform/patch/", h.SubmitFreeformPatch)

        v1.POST("/task", h.HandleTask)

        // SARIF endpoints
        // v1.POST("/task/:task_id/submitted-sarif/", h.SubmitSARIF)
        // v1.POST("/task/:task_id/broadcast-sarif-assessment/:broadcast_sarif_id/", h.SubmitBroadcastSarifAssessment)
        
        // Bundle endpoints
        // v1.POST("/task/:task_id/bundle/", h.SubmitBundle)
        // v1.GET("/task/:task_id/bundle/:bundle_id/", h.GetBundle)
        // v1.PATCH("/task/:task_id/bundle/:bundle_id/", h.UpdateBundle)
        // v1.DELETE("/task/:task_id/bundle/:bundle_id/", h.DeleteBundle)
    }

    return r
}

func main() {
    // Load environment variables from .env file
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found, using environment variables")
    }

    // Initialize telemetry
    config, err := telemetry.InitTelemetry("afc-crs-all-you-need-is-a-fuzzing-brain-submission-node")
    if err != nil {
        log.Printf("Warning: Failed to initialize telemetry: %v", err)
    } else {
        log.Printf("Telemetry Configuration:")
        log.Printf("Endpoint: %s", config.Endpoint)
        log.Printf("Enabled: %v", config.Enabled)
        log.Printf("Headers: %v", maskSensitiveHeaders(config.Headers))
    }

    // Get API credentials from environment variables
    apiKeyID := getEnvWithFallback("COMPETITION_API_KEY_ID", "api_key_id")
    apiToken := getEnvWithFallback("COMPETITION_API_KEY_TOKEN", "api_key_token")

    // Log configuration (with sensitive data masked)
    log.Printf("Server Configuration:")
    log.Printf("API Key ID: %s", maskSensitiveValue(apiKeyID))
    log.Printf("API Token: %s", "<redacted>")

    // Inside main() or initialization code
    go func() {
        http.ListenAndServe("localhost:6060", nil)
    }()

    // Setup router with authentication
    router := setupRouter(apiKeyID, apiToken)

    // Get port from environment variable or use default
    port := getEnvWithFallback("PORT", "7081")
    
    // Start server
    serverAddr := ":" + port
    log.Printf("CRS submission node listening at port %s", port)
    if err := router.Run(serverAddr); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}

// getEnvWithFallback returns environment variable value or fallback if not set
func getEnvWithFallback(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}

// maskSensitiveValue masks sensitive values for logging
func maskSensitiveValue(value string) string {
    if value == "" {
        return "<empty>"
    }
    if len(value) <= 4 {
        return "<redacted>"
    }
    // Show first 2 and last 2 characters, mask the rest
    return value[:2] + "..." + value[len(value)-2:]
}