"""
AI VM Builder — Phase 2: Docker Integration with full package installation
Supports apt/apk, pip, npm package installation inside containers.
"""
import sys, json, argparse
from pathlib import Path
from phase1_cli import analyze_request, validate_config, print_config_summary

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
except ImportError:
    print("ERROR: Run: pip install docker"); sys.exit(1)

OS_IMAGES = {
    "ubuntu-22.04": "ubuntu:22.04",
    "debian-12":    "debian:12-slim",
    "alpine":       "alpine:latest",
}

def get_docker_client():
    try:
        client = docker.from_env()
        client.ping()
        return client
    except DockerException:
        print("\nERROR: Docker Desktop is not running. Please start it and retry.")
        sys.exit(1)

def run_in_container(container, cmd, description=""):
    if description:
        print(f"  {description}...")
    exit_code, output = container.exec_run(
        ["/bin/sh", "-c", cmd],
        environment={"DEBIAN_FRONTEND": "noninteractive"},
    )
    output_str = output.decode(errors="replace")
    if exit_code != 0:
        print(f"  WARNING (exit {exit_code}): {output_str[-300:]}")
    return exit_code, output_str

def install_system_packages(container, config):
    packages = config.get("packages", [])
    if not packages:
        print("  No system packages to install.")
        return
    pkg_str = " ".join(packages)
    os_type = config["os"]
    if os_type == "alpine":
        cmd = f"apk add --no-cache {pkg_str}"
    else:
        cmd = f"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg_str} && apt-get clean"
    run_in_container(container, cmd, f"Installing system packages: {pkg_str}")

def install_pip_packages(container, config):
    pip_pkgs = config.get("pip_packages", [])
    if not pip_pkgs:
        return
    pkg_str = " ".join(pip_pkgs)
    # Ensure pip is available
    run_in_container(container, "python3 -m ensurepip --upgrade 2>/dev/null || true", "Ensuring pip")
    run_in_container(container, f"pip3 install --quiet --no-cache-dir {pkg_str}", f"Installing pip packages: {pkg_str}")

def install_npm_packages(container, config):
    npm_pkgs = config.get("npm_packages", [])
    if not npm_pkgs:
        return
    pkg_str = " ".join(npm_pkgs)
    run_in_container(container, f"npm install -g --silent {pkg_str}", f"Installing npm packages: {pkg_str}")

def create_container(client, config):
    image_name = OS_IMAGES.get(config["os"], "ubuntu:22.04")
    print(f"  Pulling image: {image_name}...")
    try:
        client.images.pull(image_name)
    except ImageNotFound:
        print(f"  ERROR: Image '{image_name}' not found."); sys.exit(1)

    safe_os  = config["os"].replace(".", "-")
    name     = f"ai-vm-{safe_os}-{config['cpu']}cpu"
    try:
        existing = client.containers.get(name)
        print(f"  Removing old container: {name}")
        existing.stop(); existing.remove()
    except docker.errors.NotFound:
        pass

    port_bindings = {}
    for port in config.get("ports", []):
        port_bindings[f"{port}/tcp"] = port

    print(f"  Creating container: {name}...")
    container = client.containers.run(
        image_name, name=name, detach=True, tty=True, stdin_open=True,
        mem_limit=f"{config['ram_gb']}g",
        nano_cpus=config["cpu"] * 1_000_000_000,
        ports=port_bindings or None,
        environment=config.get("env_vars", {}),
        command="/bin/sh" if config["os"] == "alpine" else "/bin/bash",
        labels={
            "ai-vm-builder": "true",
            "purpose": config.get("purpose", ""),
            "security_profile": config.get("security_profile", "standard"),
        },
    )
    print(f"  Container created: {container.short_id}")
    return container

def build_and_run(config):
    is_valid, errors = validate_config(config)
    if not is_valid:
        print("Config validation failed:")
        for err in errors: print(f"  - {err}")
        return None

    print_config_summary(config)
    print("\nBuilding container...")
    client = get_docker_client()
    container = create_container(client, config)

    print("\nInstalling packages...")
    install_system_packages(container, config)
    install_pip_packages(container, config)
    install_npm_packages(container, config)

    container.reload()
    shell = "/bin/sh" if config["os"] == "alpine" else "/bin/bash"
    print("\n" + "="*52)
    print("  CONTAINER READY")
    print("="*52)
    print(f"  ID     : {container.short_id}")
    print(f"  Name   : {container.name}")
    print(f"  Status : {container.status}")
    print(f"\n  Shell  : docker exec -it {container.short_id} {shell}")
    print(f"  Stop   : docker stop {container.short_id}")
    print("="*52)
    return container

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--last", action="store_true")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    if args.last:
        config_path = Path(__file__).parent / "last_config.json"
        if not config_path.exists():
            print("No last_config.json. Run phase1_cli.py first."); sys.exit(1)
        config = json.loads(config_path.read_text())
        print("Loaded config from last_config.json")
    else:
        print("\nAI VM Builder — Phase 2: Docker")
        user_input = input("Describe your VM > ").strip()
        if not user_input: return
        print("\nAnalyzing with LLM...")
        config = analyze_request(user_input, provider=args.provider, model=args.model)

    build_and_run(config)

if __name__ == "__main__":
    main()
