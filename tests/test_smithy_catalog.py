import pytest
from unittest.mock import MagicMock
from aws_cli_mcp.smithy.catalog import SmithyCatalog, _service_name
from aws_cli_mcp.smithy.parser import SmithyModel, ServiceShape, OperationShape

@pytest.fixture
def mock_model():
    model = MagicMock(spec=SmithyModel)
    
    # 1. Standard Service with attached operations
    s3_shape = MagicMock(spec=ServiceShape)
    s3_shape.shape_id = "com.amazonaws.s3#AmazonS3"
    s3_shape.traits = {"aws.api#service": {"sdkId": "S3", "endpointPrefix": "s3"}}
    s3_shape.operations = ["com.amazonaws.s3#ListBuckets", "com.amazonaws.s3#CreateBucket"]
    
    list_op = MagicMock(spec=OperationShape)
    list_op.documentation = "Lists all buckets."
    
    create_op = MagicMock(spec=OperationShape)
    create_op.documentation = "Creates a new bucket."
    
    # 2. Orphan operation sharing namespace
    orphan_op = MagicMock(spec=OperationShape)
    orphan_op.documentation = "Orphan op."
    
    # 3. Service with weird name traits
    weird_shape = MagicMock(spec=ServiceShape)
    weird_shape.shape_id = "com.foo#WeirdService"
    weird_shape.traits = {} # No aws traits, fallback to name
    weird_shape.operations = []
    
    shapes = {
        "com.amazonaws.s3#AmazonS3": s3_shape,
        "com.amazonaws.s3#ListBuckets": list_op,
        "com.amazonaws.s3#CreateBucket": create_op,
        "com.amazonaws.s3#OrphanOp": orphan_op,
        "com.foo#WeirdService": weird_shape
    }
    
    model.shapes = shapes
    model.get_shape.side_effect = shapes.get
    
    return model

def test_catalog_indexing(mock_model):
    catalog = SmithyCatalog(mock_model)
    
    # Check S3 operations
    s3_list = catalog.find_operation("s3", "ListBuckets")
    assert s3_list is not None
    assert s3_list.ref.service == "s3"
    assert s3_list.operation_shape_id == "com.amazonaws.s3#ListBuckets"
    
    # Check Orphan Rescue
    s3_orphan = catalog.find_operation("s3", "OrphanOp")
    # assert s3_orphan is not None (Orphan rescue logic relies on namespace sharing)
    # The code says if shape_id has #, split. com.amazonaws.s3 matches com.amazonaws.s3#AmazonS3's namespace
    assert s3_orphan is not None
    assert s3_orphan.ref.service == "s3"

    # Check Weird Service
    # Name fallback: WeirdService -> weirdservice
    assert catalog.find_operation("weirdservice", "NonExistent") is None

def test_search(mock_model):
    catalog = SmithyCatalog(mock_model)
    
    # Exact match query
    results = catalog.search("ListBuckets")
    assert len(results) >= 1
    assert results[0].ref.operation == "ListBuckets"
    
    # Service filter
    results = catalog.search("Bucket", service="s3")
    assert len(results) >= 2 # List & Create
    
    # Documentation match
    results = catalog.search("Lists all")
    assert len(results) == 1
    assert results[0].ref.operation == "ListBuckets"
    
    # No match
    results = catalog.search("NonExistentThing")
    assert len(results) == 0

def test_service_name_logic():
    # Valid sdkId
    s1 = MagicMock(spec=ServiceShape)
    s1.shape_id = "ns#S1"
    s1.traits = {"aws.api#service": {"sdkId": "My Service"}}
    assert _service_name(s1) == "myservice"
    
    # Valid endpointPrefix
    s2 = MagicMock(spec=ServiceShape)
    s2.shape_id = "ns#S2"
    s2.traits = {"aws.api#service": {"endpointPrefix": "custom-endpoint"}}
    assert _service_name(s2) == "custom-endpoint"
    
    # Fallback to name
    s3 = MagicMock(spec=ServiceShape)
    s3.shape_id = "ns#SomeService"
    s3.traits = {}
    assert _service_name(s3) == "someservice"

    # Amazon prefix removal
    s4 = MagicMock(spec=ServiceShape)
    s4.shape_id = "ns#AmazonKinesis"
    s4.traits = {}
    assert _service_name(s4) == "kinesis"
