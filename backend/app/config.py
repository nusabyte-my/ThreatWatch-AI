import json
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://threatwatch:threatwatch_secret@localhost:5432/threatwatch"
    secret_key: str = "changeme"
    model_path: str = "./ml/model.pkl"
    debug: bool = False
    allowed_origins_raw: str = Field(
        "http://localhost:3000,"
        "http://127.0.0.1:3000,"
        "http://localhost:5080,"
        "http://127.0.0.1:5080,"
        "http://localhost:8100,"
        "http://127.0.0.1:8100,"
        "null",
        validation_alias="ALLOWED_ORIGINS",
    )
    allowed_origin_regex: str = Field(
        r"^(moz-extension|chrome-extension)://.*$",
        validation_alias="ALLOWED_ORIGIN_REGEX",
    )
    allowed_hosts_raw: str = Field(
        "localhost,127.0.0.1,testserver",
        validation_alias="ALLOWED_HOSTS",
    )
    api_key: str = "changeme_api_key"
    max_request_bytes: int = 3 * 1024 * 1024
    auth_enabled: bool = True
    auth_token_ttl_minutes: int = 480
    auth_users_json: str = '[{"username":"admin","password":"changeme_admin_password","role":"admin"}]'

    # Agent pipeline
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    agent_pipeline_enabled: bool = True
    agent_primary_model: str = "gpt-4o-mini"   # default mini — switch to gpt-4o for demo
    agent_llm_timeout: int = 15
    agent_max_tokens: int = 512
    ollama_base_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "gemma4:e2b"
    ollama_timeout: int = 75

    # Optional URL reputation enrichment
    google_safe_browsing_key: str = ""
    google_safe_browsing_timeout: int = 5

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins_raw.split(",") if origin.strip()]

    @property
    def allowed_hosts(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts_raw.split(",") if host.strip()]

    @property
    def auth_users(self) -> list[dict]:
        raw = (self.auth_users_json or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        users: list[dict] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username", "")).strip().lower()
            password = str(item.get("password", ""))
            role = str(item.get("role", "viewer")).strip().lower()
            if username and password and role in {"admin", "analyst", "viewer"}:
                users.append({"username": username, "password": password, "role": role})
        return users

    class Config:
        env_file = ".env"


settings = Settings()
