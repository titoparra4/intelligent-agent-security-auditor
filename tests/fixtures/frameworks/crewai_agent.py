"""Synthetic CrewAI fixture (never executed)."""
from crewai import Agent, Crew

analyst = Agent(role="analyst", goal="analyse", backstory="data analyst", allow_code_execution=True,
                code_execution_mode="unsafe", allow_delegation=True, max_iter=5)
writer = Agent(role="writer", goal="write", backstory="writer", allow_delegation=True, max_iter=5)
crew = Crew(agents=[analyst, writer], tasks=[])
