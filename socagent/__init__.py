"""socagent: companion code for 'AI Agents for Security Operations'."""
from .agent import Agent, AgentRun
from .schemas import Alert, Evidence, ProposedAction, Severity, TriageResult, Verdict

__all__ = ["Agent", "AgentRun", "Alert", "Evidence", "ProposedAction", "Severity", "TriageResult", "Verdict"]
__version__ = "1.0.0"
