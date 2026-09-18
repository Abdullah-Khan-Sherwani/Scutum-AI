"""
Entry point: brings up the isolated target, runs the LangGraph agent to
completion, and writes the transcript and final report to output/.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

CONFIG_PATH = Path(__file__).parent / os.environ.get("SCUTUM_CONFIG", "config.json")
CONFIG = json.loads(CONFIG_PATH.read_text())
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def check_docker() -> None:
    result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=15)
    if result.returncode != 0:
        sys.exit(
            "Docker does not appear to be running. Start Docker Desktop and re-run.\n"
            f"{result.stderr}"
        )


def main() -> None:
    import os
    if not os.environ.get("OPENROUTER_API_KEY"):
        sys.exit("Set OPENROUTER_API_KEY in agent/.env (copy .env.example) before running.")

    check_docker()

    from tools import ensure_target_running
    if CONFIG.get("container_image"):
        print(f"Starting {CONFIG['container_name']} on {CONFIG['docker_network']} ...")
    else:
        print("No container configured -- assuming target was started externally.")
    ensure_target_running()
    print(f"Target ready at {CONFIG['target_url']}")

    from graph import build_graph, initial_messages
    app = build_graph()

    print("Running agent (this can take a few minutes: ZAP scan is the slow step)...")
    final_state = app.invoke(
        {"messages": initial_messages()},
        config={
            "recursion_limit": CONFIG["max_recursion"],
            "configurable": {"thread_id": "assessment-run-1"},
        },
    )

    messages = final_state["messages"]
    (OUTPUT_DIR / "transcript.json").write_text(
        json.dumps([m.model_dump() if hasattr(m, "model_dump") else m for m in messages],
                   indent=2, default=str),
        encoding="utf-8",
    )

    final_text = messages[-1].content
    (OUTPUT_DIR / "report_raw.txt").write_text(final_text, encoding="utf-8")

    try:
        report = json.loads(final_text)
        (OUTPUT_DIR / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nDone. {len(report.get('findings', []))} finding(s). "
              f"See output/report.json and output/report_raw.txt")
    except json.JSONDecodeError:
        print("\nDone, but the model's final reply was not valid JSON. "
              "Raw text saved to output/report_raw.txt -- inspect output/transcript.json "
              "for the full run.")


if __name__ == "__main__":
    main()
