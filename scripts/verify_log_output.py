
import logging
import os
import sys

# Ensure src is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aws_cli_mcp.logging_utils import configure_logging

def verify_logging():
    log_file = "test_verify.log"
    # Clean up previous run
    if os.path.exists(log_file):
        os.remove(log_file)
        
    # Mock environment variable for log file
    os.environ["LOG_FILE"] = log_file
    
    # Configure logging
    configure_logging()
    
    # Log messages
    logging.info("TEST_INFO_MESSAGE")
    logging.error("TEST_ERROR_MESSAGE")
    
    # Check file content
    if not os.path.exists(log_file):
        print("FAILURE: Log file was not created.")
        sys.exit(1)
        
    with open(log_file, "r") as f:
        content = f.read()
        
    print(f"Log Content:\n{content}")
    
    if "TEST_INFO_MESSAGE" in content and "TEST_ERROR_MESSAGE" in content:
        print("SUCCESS: Both INFO and ERROR messages found in log file.")
    else:
        print("FAILURE: Missing expected messages.")
        sys.exit(1)

    # Clean up
    if os.path.exists(log_file):
        os.remove(log_file)

if __name__ == "__main__":
    verify_logging()
