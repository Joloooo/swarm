"""Vulnerability-type (Shannon-style) agent configs."""

from src.agents.configs.vulntype.sqli import sqli_config  # noqa: F401
from src.agents.configs.vulntype.xss import xss_config  # noqa: F401
from src.agents.configs.vulntype.ssti import ssti_config  # noqa: F401
from src.agents.configs.vulntype.idor import idor_config  # noqa: F401
from src.agents.configs.vulntype.ssrf import ssrf_config  # noqa: F401
from src.agents.configs.vulntype.lfi import lfi_config  # noqa: F401
