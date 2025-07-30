# Get the Git reference and save it to VERSION file
git_ref=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)
echo "$git_ref" > ./VERSION
echo "Building version: $git_ref"

# Build the Docker image
docker build -f Dockerfile.local -t crs-local:latest .
docker tag crs-local:latest ghcr.io/parasol-aser/crs-local:latest
docker push ghcr.io/parasol-aser/crs-local:latest