curl -s -X POST "http://localhost:7080/v1/task/" \
  -H "Content-Type: application/json" \
  --user "e8f90226-7d1d-4721-a0d6-3f3556218efe:mnMu8ESMlO4YHOH7O90VCfZuPSkENBy9" \
  -d '{
    "message_id": "91405a4a-3991-444f-b3a7-86b118a81f78",
    "message_time": 1746729805828,
    "tasks": [
      {
        "task_id": "0196b135-a80a-7673-81af-2d2211a2252d",
        "type": "delta",
        "deadline": 1746758605827,
        "focus": "round-exhibition2-libpng",
        "harnesses_included": true,
        "metadata": {
          "round.id": "exhibition2",
          "task.id": "0196b135-a80a-7673-81af-2d2211a2252d"
        },
        "project_name": "libpng",
        "source": [
          {
                    "type": "repo",
                    "url": "https://aixcctfstate123.blob.core.windows.net/test-aixcc/89702741fb390ba118338151867da936efd5589c599807f3277dcd3209c7cd04?se=2025-06-15T19%3A19%3A55Z&sp=rl&sv=2022-11-02&sr=c&sig=DgE/W0KfIXU3XhIBO0gfLXl8cR/TvZQaQ/rr9sqGT2Q%3D",
                    "sha256": "89702741fb390ba118338151867da936efd5589c599807f3277dcd3209c7cd04"
          },
          {
                    "type": "fuzz-tooling",
                    "url": "https://aixcctfstate123.blob.core.windows.net/test-aixcc/6b837066332bb8d08a701767fcebedede996b566c3de669e01ffda49c318513b?se=2025-06-15T19%3A19%3A55Z&sp=rl&sv=2022-11-02&sr=c&sig=DgE/W0KfIXU3XhIBO0gfLXl8cR/TvZQaQ/rr9sqGT2Q%3D",
                    "sha256": "6b837066332bb8d08a701767fcebedede996b566c3de669e01ffda49c318513b"
          },
          {
                    "type": "diff",
                    "url": "https://aixcctfstate123.blob.core.windows.net/test-aixcc/d964188f40199241e9f1b472b8b3eedfc534d7dd765e4626e824316f1361708d?se=2025-06-15T19%3A19%3A55Z&sp=rl&sv=2022-11-02&sr=c&sig=DgE/W0KfIXU3XhIBO0gfLXl8cR/TvZQaQ/rr9sqGT2Q%3D",
                    "sha256": "d964188f40199241e9f1b472b8b3eedfc534d7dd765e4626e824316f1361708d"
          }
]
      }
    ]
  }'