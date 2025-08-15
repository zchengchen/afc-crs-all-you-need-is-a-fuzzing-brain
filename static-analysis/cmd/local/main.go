package main

import (
	"flag"
	"log"
	"os"
	"io/fs"
	"encoding/json"
	"path/filepath"
	"strings"
	"static-analysis/internal/engine"
	"static-analysis/internal/engine/models"
)

func main() {
	flag.Parse()
	// Check if task path is provided
	if len(flag.Args()) < 1 {
		log.Fatal("Task path is required as an argument")
	}
	taskPath := flag.Arg(0)

	// Get absolute paths
	_, err := filepath.Abs(taskPath)
	if err != nil {
		log.Fatalf("Failed to get absolute task dir path: %v", err)
	}

    //----------------------------------------------------------
    // Locate and load task_detail*.json (if present)
    //----------------------------------------------------------
    var (
        taskDetail models.TaskDetail
        jsonFound  bool
    )

    walkErr := filepath.WalkDir(taskPath, func(p string, d fs.DirEntry, err error) error {
        if err != nil || d.IsDir() {
            return nil // Skip errors & directories
        }

        name := d.Name()
        if strings.HasPrefix(name, "task_detail") && strings.HasSuffix(name, ".json") {
            data, rdErr := os.ReadFile(p)
            if rdErr != nil {
                log.Printf("Failed to read %s: %v (continuing search)", p, rdErr)
                return nil
            }
            if umErr := json.Unmarshal(data, &taskDetail); umErr != nil {
                log.Printf("Failed to unmarshal %s: %v (continuing search)", p, umErr)
                return nil
            }
            // log.Printf("Loaded task detail from %s", p)
            jsonFound = true
            return filepath.SkipDir // Stop walking once we succeed
        }
        return nil
    })
    if walkErr != nil {
        log.Printf("Directory walk error: %v", walkErr)
    }

	// Fallback to stub when JSON isn’t found / can’t be parsed
	if !jsonFound {
		log.Printf("No valid task_detail.json found!")
	} else{
		results, err:=engine.EngineMainAnalysisCore(taskDetail, taskPath)
		if err != nil {
			log.Fatalf("Analysis failed: %v", err)
		}
		log.Printf("Analysis complete: %+v", results)
	}
}