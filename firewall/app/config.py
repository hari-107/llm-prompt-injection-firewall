from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class FirewallMode(str, Enum):
    block = "block"
    flag = "flag"
    allow = "allow"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    upstream_base_url: str = "https://api.openai.com/v1"
    upstream_api_key: str = ""
    firewall_mode: FirewallMode = FirewallMode.block
    block_threshold: float = 0.7
    detection_log: str = "detections.jsonl"

    @property
    def inspect_only(self) -> bool:
        """No upstream key -> we scan and log but cannot forward to a real LLM."""
        return not self.upstream_api_key


settings = Settings()
