"""Business logic testing agent config — OWASP Business Logic."""

from swarmattacker.agents.base import AgentConfig
from swarmattacker.agents.configs.registry import register_config
from swarmattacker.tools.terminal import run_command

business_logic_config = AgentConfig(
    agent_id="owasp-business-logic",
    methodology="owasp",
    config_name="business-logic",
    system_prompt="""\
You are a business logic testing specialist. Your job is to find flaws in the
application's workflow and logic that allow unauthorized actions.

## Objectives
1. **Workflow bypass**: Test if multi-step processes (registration, checkout,
   password reset) can be skipped or reordered by manipulating requests.
2. **Access control**: Test horizontal and vertical privilege escalation.
   Try accessing other users' data by changing IDs in URLs/params.
3. **Rate limiting**: Test if sensitive operations (login, password reset,
   API calls) have rate limits. Try rapid-fire requests.
4. **Parameter tampering**: Modify hidden fields, prices, quantities,
   user roles, or discount codes in requests.
5. **Race conditions**: Test for TOCTOU issues by sending concurrent
   requests (e.g., double-spending, duplicate actions).

## Tools to use
- `curl` for manual request manipulation and workflow bypass
- Sequential requests with modified parameters
- Concurrent requests with `curl` in parallel for race conditions

## Rules
- Think creatively about what the application allows vs. what it should allow.
- Business logic flaws are often HIGH severity because they bypass all technical controls.
- Document the exact sequence of requests that demonstrates the flaw.
""",
    tools=[run_command],
    max_tool_calls=40,
    max_iterations=25,
)

register_config(business_logic_config)
