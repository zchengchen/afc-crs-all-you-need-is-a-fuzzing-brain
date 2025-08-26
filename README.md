## Quick Start

### 1. Set up API Keys

First, export your required API keys:

```bash
export OPENAI_API_KEY=
export ANTHROPIC_API_KEY=
export GEMINI_API_KEY=
```

### 2. Build the Local CRS Image

```bash
cd afc-crs-all-you-need-is-a-fuzzing-brain/crs/
./build-local-crs-image.sh
```

Alternatively, you can pull the pre-built image:
```bash
docker pull ghcr.io/o2lab/crs-local:latest
```

### 3. Set up Challenge Benchmarks

Download the AIXCC challenge benchmarks to the required directories:

```bash
# Clone the benchmark repository
git clone https://github.com/o2lab/FuzzingBrain-AIXCC-Challenges.git

# Copy C/C++ challenges
sudo cp -r FuzzingBrain-AIXCC-Challenges/c-challenges/* /aixcc/c-challenges/

# Copy Java challenges  
sudo cp -r FuzzingBrain-AIXCC-Challenges/java-challenges/* /aixcc/java-challenges/
```

### 4. Run Evaluation

```bash
./Evaluation.sh
```

This will run comprehensive evaluations across multiple AI models and challenge scenarios, testing both C and Java challenges.


## Supported AI Models

The system supports multiple AI models for analysis:
- Claude Sonnet 4 (2025-05-14)
- Claude Opus 4.1 (2025-08-05)
- Gemini 2.5 Flash
- Gemini 2.5 Pro
- GPT-5
- GPT-5 Mini

