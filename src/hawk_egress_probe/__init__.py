import json
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox

# python one-liner: DNS + HTTP egress check with a hard timeout
CHECK = (
    "import json,socket,urllib.request\n"
    "out={}\n"
    "try:\n"
    "    socket.setdefaulttimeout(10)\n"
    "    out['dns']=bool(socket.getaddrinfo('example.com',443))\n"
    "except Exception as e:\n"
    "    out['dns']=f'FAIL {type(e).__name__}'\n"
    "try:\n"
    "    r=urllib.request.urlopen('https://example.com',timeout=10)\n"
    "    out['http']=r.status\n"
    "except Exception as e:\n"
    "    out['http']=f'FAIL {type(e).__name__}'\n"
    "print(json.dumps(out))\n"
)


@solver
def probe() -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        results = {}
        for service in ("default", "benchmark"):
            box = sandbox() if service == "default" else sandbox(service)
            r = await box.exec(["python", "-c", CHECK], timeout=60)
            results[service] = json.loads(r.stdout) if r.success else f"exec failed: {r.stderr}"
        # sibling reachability: benchmark resolves and is reachable from default
        r = await sandbox().exec(
            ["python", "-c", "import socket;print(socket.getaddrinfo('benchmark',None)[0][4][0])"],
            timeout=30,
        )
        results["sibling_dns"] = r.stdout.strip() if r.success else f"FAIL {r.stderr[:100]}"
        state.store.set("egress", results)
        state.output.completion = json.dumps(results)
        return state

    return solve


@task
def egress_probe() -> Task:
    values = Path(__file__).parent / "values.yaml"
    return Task(
        dataset=[Sample(input="probe", target="probe")],
        solver=probe(),
        sandbox=("k8s", str(values)),
    )
