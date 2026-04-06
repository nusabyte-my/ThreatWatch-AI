from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://threatwatch:threatwatch_secret@localhost:5432/threatwatch"
    secret_key: str = "changeme"
    model_path: str = "./ml/model.pkl"
    debug: bool = False

    class Config:
        env_file = ".env"


settings = Settings()
