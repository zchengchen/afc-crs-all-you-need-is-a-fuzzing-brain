## Test LOCAL CRS:

```
docker run -it --rm --privileged crs-local:latest
```
```
export ANTHROPIC_API_KEY=...
```
```
./crs-local /crs-workdir/local-test-integration-delta-01/
```
```
./crs-local /crs-workdir/local-test-libxml2-delta-01/
```
```
./crs-local /crs-workdir/local-test-sqlite3-full-01/
```
```
./crs-local /crs-workdir/local-test-tika-delta-01/
```
```
./crs-local /crs-workdir/local-test-zookeeper-delta-01/
```

## Deploy LOCAL CRS:
```
cd crs
./build-local-crs-image.sh
```

## CRS Development:
```
cd crs
go run ./cmd/local/main.go /crs-workdir/local-test-integration-delta-01/
```