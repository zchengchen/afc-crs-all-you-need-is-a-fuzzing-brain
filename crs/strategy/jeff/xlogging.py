import os
import time
import logging
import atexit
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

# Define global variables at the module level
_tracer_provider = None

def initialize_tracer(fuzzer_name="unknown", project_name="unknown", do_patch_only=False):
    """Initialize OpenTelemetry tracer with OTLP exporter."""
    global _tracer_provider
    
    # Debug: Print all environment variables related to OpenTelemetry
    for key, value in os.environ.items():
        if key.startswith("OTEL_"):
            if "HEADERS" in key:
                # Don't print the full headers as they may contain sensitive information
                logging.info(f"Environment variable {key} is set (value redacted)")
            else:
                logging.info(f"Environment variable {key} = {value}")

    otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    otel_headers_str = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "")
    
    if not otel_endpoint:
        logging.warning("OTEL_EXPORTER_OTLP_ENDPOINT is not set. Telemetry will not be exported.")
        return None

    # Extract headers into a dictionary with proper validation
    headers_dict = {}
    if otel_headers_str:
        try:
            # Parse the Authorization header
            if "Authorization=Basic" in otel_headers_str or "authorization=Basic" in otel_headers_str:
                # Extract the token after "Basic", handling both quoted and unquoted formats
                if '"' in otel_headers_str:
                    auth_token = otel_headers_str.split('Basic ')[1].split('"')[0].strip()
                else:
                    auth_token = otel_headers_str.split('Basic ')[1].strip()
                
                # Use lowercase "authorization" as the key (this is important for gRPC)
                headers_dict["authorization"] = f"Basic {auth_token}"
                logging.info("Added authorization header with Basic format")
                logging.info(f"Authorization header value: Basic {auth_token[:5]}...")
                logging.info(f"Final headers dictionary: {headers_dict}")
            else:
                logging.warning(f"No Basic authorization token found in headers string: {otel_headers_str[:20]}...")
        except Exception as e:
            logging.error(f"Error parsing OTEL headers: {e}")
            logging.error(f"Original headers string: {otel_headers_str[:20]}...")

    # Create service name with patch suffix if do_patch_only is True
    service_name = f"crs-strategy-{fuzzer_name}-{project_name}"
    if do_patch_only:
        service_name += "-patch"

    # Create a resource with service information
    resource = Resource.create({
        ResourceAttributes.SERVICE_NAME: service_name,
        ResourceAttributes.SERVICE_VERSION: "1.0.0",
    })

    try:
        # Configure the OTLP exporter
        otlp_exporter = OTLPSpanExporter(
            endpoint=otel_endpoint,
            headers=headers_dict,
            timeout=10  # seconds
        )

        # Configure the tracer provider
        _tracer_provider = TracerProvider(resource=resource)
        span_processor = BatchSpanProcessor(otlp_exporter)
        _tracer_provider.add_span_processor(span_processor)
        trace.set_tracer_provider(_tracer_provider)
        
        # Register shutdown handler
        atexit.register(shutdown_tracer)

        # Get a tracer
        tracer = trace.get_tracer(__name__)

        # Create a test span
        with tracer.start_as_current_span("telemetry-initialization") as span:
            span.set_attribute("service.name", service_name)
            span.set_attribute("initialization.time", time.time())
            logging.info("Created test span for telemetry initialization")
        
        # Force flush to verify connection
        _tracer_provider.force_flush(timeout_millis=5000)
        
        logging.info(f"OpenTelemetry tracer initialized with endpoint: {otel_endpoint}")
        return tracer
    except Exception as e:
        logging.error(f"Failed to initialize tracer: {e}")
        return None

def shutdown_tracer():
    """Properly shut down the tracer provider to ensure all spans are exported."""
    global _tracer_provider
    if _tracer_provider:
        try:
            _tracer_provider.force_flush(timeout_millis=10000)
            _tracer_provider.shutdown(timeout_millis=10000)
            logging.info("Tracer provider shutdown complete")
        except Exception as e:
            logging.error(f"Error during tracer shutdown: {e}")