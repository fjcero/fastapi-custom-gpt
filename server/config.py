from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str
    app_secret_key: str
    admin_email: str

    supabase_project_id: str
    supabase_project_url: str
    supabase_db_name: str
    supabase_db_pass: str
    supabase_api_public: str
    # supabase_api_secret: str
    supabase_salt: str

    auth0_domain: str
    auth0_client_id: str
    auth0_client_secret: str
    auth0_api: str
    auth0_api_id: str
    auth0_api_audience: str

    openai_redirect_uri: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings():
    settings = Settings()
    return settings
