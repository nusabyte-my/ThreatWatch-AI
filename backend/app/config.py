from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://threatwatch:threatwatch_secret@localhost:5432/threatwatch"
    secret_key: str = "changeme"
    model_path: str = "./ml/model.pkl"
    debug: bool = False
    allowed_origins: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    api_key: str = "changeme_api_key"

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    class Config:
        env_file = ".env"


settings = Settings()
