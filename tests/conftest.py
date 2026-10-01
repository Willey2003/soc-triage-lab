import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.llm import LLMResult  # noqa: E402
from app.models import LLMVerdict  # noqa: E402


class FakeLLM:
    """Returns a fixed answer and records what it was shown."""
    model = "fake"

    def __init__(self, disposition="close", raw=None):
        self.disposition, self.raw, self.seen = disposition, raw, []

    def triage(self, alert, ctx, hardened):
        self.seen.append((alert, ctx, hardened))
        if self.raw is not None:
            return LLMResult(None, 0.01, False, self.raw)
        v = LLMVerdict(disposition=self.disposition, severity="low", confidence=0.9,
                       mitre_technique="NONE", reasoning="fake", next_steps=[])
        return LLMResult(v, 0.01, True, v.model_dump_json())

    def ready(self):
        return True
