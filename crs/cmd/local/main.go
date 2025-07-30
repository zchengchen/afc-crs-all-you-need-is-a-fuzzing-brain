package main

import (
    "log"
    "os"
    "path/filepath"
    "strconv"
    "github.com/joho/godotenv"
    "crs/internal/handlers"
    "crs/internal/services"
)

func main() {

    // Check if task path is provided as first argument
    if len(os.Args) < 2 {
        log.Fatal("Task path is required as first argument")
    }
    taskPath := os.Args[1]

    // Get absolute paths
    absTaskDir, err := filepath.Abs(taskPath)
    if err != nil {
        log.Fatal("Failed to get absolute task dir path: %v", err)
    }

    // Load .env file
    if err := godotenv.Load(); err != nil {
        log.Printf("Warning: .env file not found, using default values")
    }

	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		log.Fatal("ANTHROPIC_API_KEY is not set")
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

    // Initialize handlers with task distribution capability
    h := handlers.NewHandler(crsService, analysisService,submissionService)
   
    h.SubmitLocalTask(absTaskDir)
}