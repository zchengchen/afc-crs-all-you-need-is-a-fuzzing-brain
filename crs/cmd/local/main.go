package main

import (
    "log"
    "os"
    "strconv"
    "github.com/joho/godotenv"
    "crs/internal/handlers"
    "crs/internal/services"
    "crs/internal/telemetry"

)

func main() {

        // Check if task path is provided as first argument
        if len(os.Args) < 2 {
            log.Fatal("Task path is required as first argument")
        }
        taskPath := os.Args[1]

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

    // Initialize services
    crsService := services.NewCRSService(workerNodes,workerBasePort)
    crsService.SetAnalysisServiceUrl(analysisService)
    crsService.SetSubmissionEndpoint(submissionService)

    log.Printf("Worker configuration: %d nodes starting at port %d", workerNodes, workerBasePort)

    // Initialize handlers with task distribution capability
    h := handlers.NewHandler(crsService, analysisService,submissionService)
   
    h.SubmitLocalTask(taskPath)
}