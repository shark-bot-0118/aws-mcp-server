import os
import json
import boto3
from botocore.exceptions import UnknownServiceError

MODEL_DIR = "data/smithy_cache/api-models-aws/models"

def get_smithy_service_names():
    services = set()
    if not os.path.exists(MODEL_DIR):
        return services

    for service_dir in os.listdir(MODEL_DIR):
        dir_path = os.path.join(MODEL_DIR, service_dir)
        if not os.path.isdir(dir_path):
            continue
            
        json_files = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".json"):
                    json_files.append(os.path.join(root, file))
        
        if not json_files:
            continue
            
        model_path = sorted(json_files)[-1]
        try:
            with open(model_path, 'r') as f:
                data = json.load(f)
            
            shapes = data.get("shapes", {})
            for shape_id, shape in shapes.items():
                if shape.get("type") == "service":
                    traits = shape.get("traits", {})
                    service_trait = traits.get("aws.api#service")
                    name = None
                    if isinstance(service_trait, dict):
                        endpoint = service_trait.get("endpointPrefix")
                        if endpoint:
                            name = endpoint.lower()
                        else:
                            sdk_id = service_trait.get("sdkId")
                            if sdk_id:
                                name = sdk_id.replace(" ", "").lower()
                    
                    if not name:
                        name = shape_id.split("#")[-1]
                        if name.startswith("Amazon"):
                            name = name.replace("Amazon", "", 1)
                        name = name.lower()
                    
                    services.add(name)
        except Exception:
            pass
    return sorted(list(services))

def verify_services():
    smithy_names = get_smithy_service_names()
    print(f"Found {len(smithy_names)} Smithy services.")
    
    valid_services = []
    invalid_services = []
    
    # Get official boto3 list
    session = boto3.Session()
    boto3_available = set(session.get_available_services())
    
    for name in smithy_names:
        # Check against available services first (fast)
        if name in boto3_available:
            valid_services.append(name)
            continue
            
        # Try explicit instantiation (slow but sure)
        try:
            boto3.client(name, region_name='us-east-1')
            valid_services.append(name)
        except (UnknownServiceError, Exception) as e:
            invalid_services.append((name, str(e)))

    print("\nINVALID_SERVICES_START")
    for name, err in invalid_services:
        print(f"{name} | {err}")
    print("INVALID_SERVICES_END")

    print("\nVALID_SERVICES_START")
    for name in valid_services:
        print(name)
    print("VALID_SERVICES_END")

if __name__ == "__main__":
    verify_services()
