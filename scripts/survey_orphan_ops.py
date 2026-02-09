
import sys
import os
from collections import defaultdict

# Ensure src is in path
sys.path.append(os.path.join(os.getcwd(), "src"))

from aws_cli_mcp.app import get_app_context
from aws_cli_mcp.smithy.parser import ServiceShape, OperationShape
from aws_cli_mcp.smithy.catalog import _service_name

def survey_orphans():
    print("--- Surveying Orphaned Operations ---")
    
    try:
        ctx = get_app_context()
        print("App Context Initialized.")
        print(f"Model Cache Path: {ctx.settings.smithy.cache_path}")
    except Exception as e:
        print(f"Failed to initialize app context: {e}")
        return

    model = ctx.smithy_model
    
    # 1. Map Namespaces to Services
    # namespace -> (service_id, service_name, attached_op_count)
    namespace_service_map = {}
    
    # Track all attached operations globally to identifying orphans
    attached_ops_global = set()

    print("\n[1] Analyzing Service Shapes...")
    for shape_id, shape in model.shapes.items():
        if isinstance(shape, ServiceShape):
            service_name = _service_name(shape)
            feature_count = len(shape.operations)
            
            if "#" in shape_id:
                ns = shape_id.split("#")[0]
                # If multiple services share a namespace (rare?), we note it
                if ns in namespace_service_map:
                    print(f"  [WARN] Multiple services in namespace {ns}: {namespace_service_map[ns][1]} AND {service_name}")
                
                namespace_service_map[ns] = {
                    "shape_id": shape_id,
                    "name": service_name,
                    "attached_count": feature_count
                }
                
                for op in shape.operations:
                    attached_ops_global.add(op)

    print(f"  Found {len(namespace_service_map)} service namespaces.")

    # 2. Scan for Orphaned Operations
    # namespace -> list of orphaned op_ids
    orphans_by_ns = defaultdict(list)
    
    print("\n[2] Scanning for Orphaned Operations...")
    for shape_id, shape in model.shapes.items():
        if isinstance(shape, OperationShape):
            if shape_id not in attached_ops_global:
                # It's an orphan!
                if "#" in shape_id:
                    ns = shape_id.split("#")[0]
                    orphans_by_ns[ns].append(shape_id)
                else:
                    print(f"  [weird] Orphan without namespace: {shape_id}")

    # 3. Report Results
    print("\n[3] Survey Report:")
    print(f"{'Service Name':<20} | {'Namespace':<30} | {'Attached':<10} | {'Orphans':<10} | {'Total':<10} | {'Status'}")
    print("-" * 110)
    
    affected_count = 0
    
    # Iterate through known service namespaces first
    sorted_ns = sorted(namespace_service_map.keys())
    
    for ns in sorted_ns:
        info = namespace_service_map[ns]
        svc_name = info["name"]
        attached = info["attached_count"]
        orphans = len(orphans_by_ns.get(ns, []))
        total = attached + orphans
        
        status = "OK"
        if orphans > 0:
            status = "FIXED" if attached == 0 else "PARTIAL" 
            # FIXED means likely the same issue as lambda (0 attached, all orphans)
            # PARTIAL means some attached, some not
            affected_count += 1
            
        print(f"{svc_name:<20} | {ns:<30} | {attached:<10} | {orphans:<10} | {total:<10} | {status}")

    print("-" * 110)
    print(f"\nTotal Services with Orphans: {affected_count}")
    
    # 4. Check for Orphans in namespaces with NO Service Definition
    print("\n[4] Orphaned Namespaces (No Service Shape Found):")
    for ns, ops in orphans_by_ns.items():
        if ns not in namespace_service_map:
            print(f"  Namespace: {ns:<30} | Orphans: {len(ops)}")
            # Sample
            if ops:
                print(f"    Sample: {ops[0]}")

if __name__ == "__main__":
    survey_orphans()
