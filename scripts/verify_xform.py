
from botocore import xform_name

ops = [
    "DescribeDBInstances",
    "DescribeDbInstances",
    "ListBuckets",
    "GetObject",
]

print(f"{'Input':<30} | {'Output':<30}")
print("-" * 60)
for op in ops:
    converted = xform_name(op)
    print(f"{op:<30} | {converted:<30}")
