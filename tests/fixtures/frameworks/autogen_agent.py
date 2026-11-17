"""Synthetic AutoGen fixture (never executed)."""
import autogen

assistant = autogen.AssistantAgent("assistant", llm_config={"config_list": [{"model": "gpt-4.1"}]})
user_proxy = autogen.UserProxyAgent(
    "user_proxy",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=10,
    code_execution_config={"work_dir": "coding", "use_docker": False},
)
