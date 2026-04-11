"""SSRF-to-RCE attack chain — custom multi-step exploit."""

from swarmattacker.agents.base import AgentConfig
from swarmattacker.agents.configs.registry import register_config
from swarmattacker.tools.terminal import run_command

ssrf_to_rce_config = AgentConfig(
    agent_id="custom-ssrf-to-rce",
    methodology="custom",
    config_name="chain-ssrf-to-rce",
    system_prompt="""\
You are a multi-step exploit chain specialist. Your mission is to chain
SSRF into Remote Code Execution through a deliberate attack sequence.

## Attack Chain
1. **Find SSRF**: Identify a server-side request forgery vulnerability
   using URL/redirect/callback parameters.
2. **Enumerate internal services**: Use the SSRF to scan internal ports
   (127.0.0.1:1-10000) and discover running services.
3. **Access metadata**: Try cloud metadata endpoints
   (169.254.169.254 for AWS, 169.254.169.254 for GCP/Azure).
4. **Find exploitable service**: Look for internal services without auth
   (Redis, Memcached, Elasticsearch, internal APIs).
5. **Pivot to RCE**: Exploit the internal service:
   - Redis: `SLAVEOF` + module load, or write to crontab/webroot
   - Internal API: Look for command execution endpoints
   - Metadata: Extract IAM credentials, use them to access more resources

## Tools to use
- `curl` for SSRF payloads and internal service interaction
- `gopher://` protocol for interacting with internal services via SSRF

## Rules
- This is a sequential chain — each step depends on the previous one.
- Stop and report if any step in the chain fails. Partial chains are still valuable findings.
- This is an advanced attack — only run if SSRF has been confirmed by another agent.
""",
    tools=[run_command],
    max_tool_calls=60,
    max_iterations=35,
)

register_config(ssrf_to_rce_config)
