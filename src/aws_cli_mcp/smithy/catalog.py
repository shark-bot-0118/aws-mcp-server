"""Operation catalog built from Smithy models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aws_cli_mcp.domain.operations import OperationRef
from aws_cli_mcp.smithy.parser import OperationShape, ServiceShape, SmithyModel


@dataclass
class OperationEntry:
    ref: OperationRef
    operation_shape_id: str
    documentation: str | None


class SmithyCatalog:
    def __init__(self, model: SmithyModel) -> None:
        self._model = model
        self._operations: dict[str, OperationEntry] = {}
        self._build_index()

    def _build_index(self) -> None:
        # Track which operations are explicitly attached to services
        attached_ops: set[str] = set()
        
        # Track namespace -> service_name mapping for orphan rescue
        # e.g. "com.amazonaws.lambda" -> "lambda"
        namespace_map: dict[str, str] = {}

        for shape in self._model.shapes.values():
            if isinstance(shape, ServiceShape):
                service_name = _service_name(shape)
                
                # Map namespace to service name
                # Shape ID: com.amazonaws.lambda#AWSGirApiService -> namespace: com.amazonaws.lambda
                if "#" in shape.shape_id:
                    ns = shape.shape_id.split("#")[0]
                    namespace_map[ns] = service_name

                for op_id in shape.operations:
                    op_shape = self._model.get_shape(op_id)
                    if not isinstance(op_shape, OperationShape):
                        continue
                    
                    attached_ops.add(op_id)
                    self._index_operation(service_name, op_id, op_shape)
        
        # Orphan Rescue: Find operations not attached to any service
        # but sharing a namespace with a known service.
        for op_id, shape in self._model.shapes.items():
            if isinstance(shape, OperationShape) and op_id not in attached_ops:
                if "#" in op_id:
                    ns = op_id.split("#")[0]
                    if ns in namespace_map:
                        service_name = namespace_map[ns]
                        self._index_operation(service_name, op_id, shape)

    def _index_operation(self, service: str, op_id: str, shape: OperationShape) -> None:
        op_name = _operation_name(op_id)
        ref = OperationRef(service=service, operation=op_name)
        # Avoid overwriting if existing (though orphans shouldn't conflict)
        if ref.key not in self._operations:
            self._operations[ref.key] = OperationEntry(
                ref=ref,
                operation_shape_id=op_id,
                documentation=shape.documentation,
            )

    def list_operations(self) -> Iterable[OperationEntry]:
        return self._operations.values()

    def find_operation(self, service: str, operation: str) -> OperationEntry | None:
        # Try exact match first
        key = OperationRef(service=service, operation=operation).key
        if key in self._operations:
            return self._operations[key]
        
        # Try case-insensitive / snake-case match
        target_svc = service.lower()
        target_op = operation.lower().replace("-", "").replace("_", "")
        
        for entry in self._operations.values():
            if entry.ref.service.lower() == target_svc:
                op_norm = entry.ref.operation.lower().replace("-", "").replace("_", "")
                if op_norm == target_op:
                    return entry
        return None

    def search(self, query: str, service: str | None = None) -> list[OperationEntry]:
        terms = query.lower().split()
        if not terms:
            return []

        results = []
        for entry in self._operations.values():
            # If explicit service hint is provided, filter strictly
            if service and entry.ref.service != service:
                continue

            # Check if all terms match
            matches_all = True
            
            # Prepare searchable text
            svc = entry.ref.service.lower()
            op = entry.ref.operation.lower()
            doc = (entry.documentation or "").lower()
            
            for term in terms:
                # Term matches if it appears in service, operation, or doc
                term_hit = (term in svc) or (term in op) or (term in doc)
                if not term_hit:
                    matches_all = False
                    break
            
            if matches_all:
                results.append(entry)

        return results


def _operation_name(shape_id: str) -> str:
    return shape_id.split("#")[-1]


def _service_name(shape: ServiceShape) -> str:
    trait = shape.traits.get("aws.api#service")
    if isinstance(trait, dict):
        endpoint = trait.get("endpointPrefix")
        if isinstance(endpoint, str) and endpoint:
            return endpoint.lower()
        sdk_id = trait.get("sdkId")
        if isinstance(sdk_id, str) and sdk_id:
            return sdk_id.replace(" ", "").lower()
    name = shape.shape_id.split("#")[-1]
    if name.startswith("Amazon"):
        name = name.replace("Amazon", "", 1)
    return name.lower()
