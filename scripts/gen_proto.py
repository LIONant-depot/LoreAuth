#!/usr/bin/env python3
"""Generate Python gRPC stubs from proto/auth_api.proto into src/lore_auth/generated/."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    proto_dir = root / "proto"
    proto_file = proto_dir / "auth_api.proto"
    out_dir = root / "src" / "lore_auth" / "generated"
    if not proto_file.is_file():
        print(f"missing {proto_file}", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "__init__.py").write_text(
        '"""Generated gRPC stubs — do not edit by hand."""\n',
        encoding="utf-8",
    )

    from grpc_tools import protoc

    # Import path so generated modules live under lore_auth.generated
    rc = protoc.main(
        [
            "grpc_tools.protoc",
            f"-I{proto_dir}",
            f"--python_out={out_dir}",
            f"--grpc_python_out={out_dir}",
            str(proto_file),
        ]
    )
    if rc != 0:
        print("protoc failed", file=sys.stderr)
        return rc

    # Fix import in *_pb2_grpc.py to use relative/package import
    grpc_py = out_dir / "auth_api_pb2_grpc.py"
    text = grpc_py.read_text(encoding="utf-8")
    text = text.replace(
        "import auth_api_pb2 as auth__api__pb2",
        "from lore_auth.generated import auth_api_pb2 as auth__api__pb2",
    )
    # also handle relative variant some versions emit
    text = text.replace(
        "import auth_api_pb2 as auth_api_pb2",
        "from lore_auth.generated import auth_api_pb2 as auth_api_pb2",
    )
    grpc_py.write_text(text, encoding="utf-8")
    print(f"generated stubs in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
