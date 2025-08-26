#!/bin/bash

models=(
  "claude-sonnet-4-20250514"
  "claude-opus-4-1-20250805"
  "gemini-2.5-flash"
  "gemini-2.5-pro"
  "gpt-5"
  "gpt-5-mini"
)

base_cmd="./afc-crs-all-you-need-is-a-fuzzing-brain/crs/eval_qx.sh"
log_dir="./afc-crs-all-you-need-is-a-fuzzing-brain/evaluation"

c_challenges=(
  "local-test-curl-delta-01"
  "local-test-curl-full-01"
  "local-test-freerdp-delta-01"
  "local-test-freerdp-full-01"
  "local-test-libexif-delta-01-exif-003"
  "local-test-libexif-delta-01-exif-004"
  "local-test-libexif-delta-01-exif-005"
  "local-test-libxml2-delta-01"
  "local-test-libxml2-delta-02"
  "local-test-libxml2-full-01"
  "local-test-sqlite3-full-01"
  "local-test-sqlite3-delta-01"
  "local-test-sqlite3-delta-02"
  "local-test-sqlite3-delta-03"
)

for challenge in "${c_challenges[@]}"; do
  challenge_path="/aixcc/c-challenges/$challenge"
  challenge_name=$(echo "$challenge" | sed 's/local-test-//')

  project_prefix=$(echo "$challenge" | sed -E 's/local-test-([a-zA-Z0-9-]+)-(delta|full).*/\1/')
  afc_pattern="afc-${project_prefix}-*"

  for model in "${models[@]}"; do
    log_file="$log_dir/${challenge_name}-${model}.log"
    echo "==> Running: $challenge on $model"
    "$base_cmd" -m "$model" "$challenge_path" 2>&1 | tee "$log_file"

    echo "--> Cleaning up files in: $challenge_path"
    sudo rm -rf "$challenge_path"/${afc_pattern} \
                 "$challenge_path"/ap* \
                 "$challenge_path"/xp* \
                 "$challenge_path"/*corpus \
                 "$challenge_path"/fuzz-tooling/build/ \
                 "$challenge_path"/patch* \
                 "$challenge_path"/vul_fun* \
                 "$challenge_path"/codeql_databases/ \
                 "$challenge_path"/detect_timeout_crash
  done
done

java_challenges=(
  "local-test-commons-compress-delta-02"
  "local-test-commons-compress-delta-03"
  "local-test-commons-compress-full-01-vuln_0"
  "local-test-commons-compress-full-01-vuln_1"
  "local-test-commons-compress-full-01-vuln_2"
  "local-test-commons-compress-full-01-vuln_5"
  "local-test-tika-delta-01"
  "local-test-tika-delta-02"
  "local-test-tika-delta-03"
  "local-test-tika-delta-04"
  "local-test-tika-delta-05"
  "local-test-tika-full-01-vuln_0"
  "local-test-tika-full-01-vuln_1"
  "local-test-tika-full-01-vuln_6"
  "local-test-tika-full-01-vuln_7"
  "local-test-tika-full-01-vuln_8"
  "local-test-zookeeper-delta-01"
  "local-test-zookeeper-delta-02"
  "local-test-zookeeper-full-01"
)

for challenge in "${java_challenges[@]}"; do
  challenge_path="/aixcc/java-challenges/$challenge"
  challenge_name=$(echo "$challenge" | sed 's/local-test-//')

  project_prefix=$(echo "$challenge" | sed -E 's/local-test-([a-zA-Z0-9-]+)-(delta|full).*/\1/')
  afc_pattern="afc-${project_prefix}-*"

  for model in "${models[@]}"; do
    log_file="$log_dir/${challenge_name}-${model}.log"
    echo "==> Running: $challenge on $model"
    "$base_cmd" -m "$model" "$challenge_path" 2>&1 | tee "$log_file"

    echo "--> Cleaning up files in: $challenge_path"
    sudo rm -rf "$challenge_path"/${afc_pattern} \
                 "$challenge_path"/ap* \
                 "$challenge_path"/xp* \
                 "$challenge_path"/*corpus \
                 "$challenge_path"/fuzz-tooling/build/ \
                 "$challenge_path"/patch* \
                 "$challenge_path"/vul_fun* \
                 "$challenge_path"/codeql_databases/ \
                 "$challenge_path"/detect_timeout_crash
  done
done
