import os
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
clones = root.parent
cases = [
    (
        "obot-native",
        "pkg/api/handlers/mcpgateway",
        "obot_filter_test.go",
        "TestIsMaliciousPublishedFilterNative",
    ),
    (
        "toolhive-native",
        "pkg/webhook/validating",
        "toolhive_filter_test.go",
        "TestIsMaliciousPublishedWebhookNative",
    ),
]
env = os.environ.copy()
env["ISMALICIOUS_FILTER_SCRIPT"] = str(root / "gateway_filters.py")
for clone, package, source, pattern in cases:
    work = clones / clone
    target = work / package / "ismalicious_external_test.go"
    shutil.copy(root / "native-tests" / source, target)
    try:
        if clone == "toolhive-native":
            taskfile = work / "Taskfile.ismalicious.yml"
            linker = "-ldflags=-extldflags=-Wl,-w " if sys.platform == "darwin" else ""
            taskfile.write_text(
                "version: '3'\ntasks:\n  validate:\n    cmds:\n      - go test "
                + linker
                + "-v -race ./"
                + package
                + " -run "
                + pattern
                + " -count=1\n"
            )
            command = [
                "go",
                "run",
                "github.com/go-task/task/v3/cmd/task@v3.45.4",
                "--taskfile",
                str(taskfile),
                "validate",
            ]
        else:
            command = ["go", "test", "./" + package, "-run", pattern, "-v", "-count=1"]
        subprocess.run(command, cwd=work, env=env, check=True)
    finally:
        target.unlink(missing_ok=True)
        if clone == "toolhive-native":
            taskfile.unlink(missing_ok=True)
