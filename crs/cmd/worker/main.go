package main

import (
    "log"
    "os"
    "strings"
    "strconv"
    "fmt"
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
    _, err := telemetry.InitTelemetry("afc-crs-all-you-need-is-a-fuzzing-brain-worker-node")
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
    podName := os.Getenv("POD_NAME")
    workerIndex := os.Getenv("WORKER_INDEX")
    if workerIndex == "" {
        // Extract index from pod name if not explicitly set
        if podName != "" {
            parts := strings.Split(podName, "-")
            if len(parts) > 0 {
                workerIndex = parts[len(parts)-1]
            }
        }
        if workerIndex == "" {
            workerIndex = "0"
        }
    }

    // Get worker configuration
    workerNodesStr := os.Getenv("WORKER_NODES")
    workerNodes, err := strconv.Atoi(workerNodesStr)
    if err != nil || workerNodes <= 0 {
        workerNodes = 24 // Default to 24 worker nodes
    }
    workerPortStr := os.Getenv("WORKER_PORT")
    workerPort, err := strconv.Atoi(workerPortStr)
    if err != nil || workerPort <= 0 {
        workerPort = 9081
    }
    
    submissionService := os.Getenv("SUBMISSION_SERVICE")
    if submissionService == "" {
        submissionService = "http://crs-sub"
    }

    analysisService := os.Getenv("ANALYSIS_SERVICE")
    if analysisService == "" {
        analysisService = "http://crs-analysis"
    }

    r := gin.Default()

    // Initialize services
    crsService := services.NewCRSService(workerNodes,workerPort)
    crsService.SetAnalysisServiceUrl(analysisService)
    // Configure the service to forward submissions to the submission service
    crsService.SetSubmissionEndpoint(submissionService)
    crsService.SetWorkerIndex(workerIndex)

    log.Printf("Initialized worker %s (index: %s) services", podName, workerIndex)

    // Initialize handlers
    h := handlers.NewHandler(crsService,analysisService,submissionService)

    // Unauthenticated routes
    r.GET("/status/", h.GetStatus)
    r.POST("/sarif_worker/", h.SubmitWorkerSarif)

    // Authenticated routes
    v1 := r.Group("/v1", gin.BasicAuth(gin.Accounts{
       apiKeyID: apiToken,
    }))
    {
        // SARIF endpoints
        v1.POST("/sarif/", h.SubmitSarif)
        
        // Task endpoints
        v1.POST("/task/", h.SubmitWorkerTask)
        v1.DELETE("/task/", h.CancelAllTasks)
        v1.DELETE("/task/:task_id/", h.CancelTask)
        
        // Status reset endpoint
        v1.POST("/status/reset/", h.ResetStatus)
    }
    
    // Start the worker on the configured port
    listenAddr := fmt.Sprintf(":%d", workerPort)
    log.Printf("Worker node %s listening at %s", podName, listenAddr)
    log.Fatal(r.Run(listenAddr))
}