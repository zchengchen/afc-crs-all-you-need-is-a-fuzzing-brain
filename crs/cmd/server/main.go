package main

import (
    "log"
    "os"
    "strconv"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "crs/internal/handlers"
    "crs/internal/services"
    "crs/internal/telemetry"

)

func main() {
    // Load .env file
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found, using default values")
    }

    // Initialize telemetry
    _, err := telemetry.InitTelemetry("afc-crs-all-you-need-is-a-fuzzing-brain-webapp-node")
    if err != nil {
        log.Printf("Warning: Failed to initialize telemetry: %v", err)
    } 
    // Get credentials from environment variables with fallback values
    apiKeyID := os.Getenv("CRS_KEY_ID")
    if apiKeyID == "" {
        apiKeyID = "api_key_id"
    }
    apiToken := os.Getenv("CRS_KEY_TOKEN")
    if apiToken == "" {
        apiToken = "api_key_token"
    }

    // log.Printf("CRS_KEY_ID: %s", os.Getenv("CRS_KEY_ID"))
    // log.Printf("CRS_KEY_TOKEN: %s", os.Getenv("CRS_KEY_TOKEN"))
    // log.Printf("COMPETITION_API_KEY_ID: %s", os.Getenv("COMPETITION_API_KEY_ID"))
    // log.Printf("COMPETITION_API_KEY_TOKEN: %s", os.Getenv("COMPETITION_API_KEY_TOKEN"))

    // Get worker configuration
    workerNodesStr := os.Getenv("WORKER_NODES")
    workerNodes, err := strconv.Atoi(workerNodesStr)
    if err != nil || workerNodes <= 0 {
        workerNodes = 24 // Default to 24 worker nodes
    }
    
    workerBasePortStr := os.Getenv("WORKER_BASE_PORT")
    workerBasePort, err := strconv.Atoi(workerBasePortStr)
    if err != nil || workerBasePort <= 0 {
        workerBasePort = 9081 // Default base port
    }
    
    submissionService := os.Getenv("SUBMISSION_SERVICE")
    if submissionService == "" {
        submissionService = "http://crs-sub"
    }

    analysisService := os.Getenv("ANALYSIS_SERVICE")
    if analysisService == "" {
        analysisService = "http://crs-analysis"
    }

    if os.Getenv("ANALYSIS_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
        analysisService = "http://localhost:7082"
    }
    if os.Getenv("SUBMISSION_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
        submissionService = "http://localhost:7081"
    }

    r := gin.Default()

    // Initialize services
    crsService := services.NewCRSService(workerNodes,workerBasePort)
    crsService.SetAnalysisServiceUrl(analysisService)
    crsService.SetSubmissionEndpoint(submissionService)

    log.Printf("Worker configuration: %d nodes starting at port %d", workerNodes, workerBasePort)

    // Initialize handlers with task distribution capability
    h := handlers.NewHandler(crsService, analysisService,submissionService)
    // Unauthenticated routes
    r.GET("/status/", h.GetStatus)

    // for testing only
    r.POST("/sarifx/", h.SubmitSarif)

    // Authenticated routes
    v1 := r.Group("/v1", gin.BasicAuth(gin.Accounts{
       apiKeyID: apiToken,
    }))
    {
        // SARIF endpoints
        v1.POST("/sarif/", h.SubmitSarif)
        
        // Task endpoints
        v1.POST("/task/", h.SubmitTask)  
        v1.DELETE("/task/", h.CancelAllTasks)
        v1.DELETE("/task/:task_id/", h.CancelTask)
        
        // Status reset endpoint
        v1.POST("/status/reset/", h.ResetStatus)
    }
    
    if os.Getenv("LOCAL_TEST") == "" {
        log.Printf("Task distribution node listening at port 7080")
        log.Fatal(r.Run(":7080"))
    } else {
        log.Printf("LOCAL_TEST node listening at port 5080")
        log.Fatal(r.Run(":5080"))
    }
}