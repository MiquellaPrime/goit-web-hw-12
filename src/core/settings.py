from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseSettingsWithConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class DBSettings(BaseSettingsWithConfig):
    model_config = SettingsConfigDict(env_prefix="db_")

    host:   str
    port:   int
    user:   str
    passwd: str
    name:   str

    @property
    def postgres_dsn(self) -> str:
        return f"postgresql+psycopg2://{self.user}:{self.passwd}@{self.host}:{self.port}"


class JWTSettings(BaseSettingsWithConfig):
    model_config = SettingsConfigDict(env_prefix="jwt_")

    algorithm:  str
    secret_key: str

    access_token_expire_minutes: int = 15
    refresh_token_expire_days:   int = 30


class Settings(BaseSettingsWithConfig):
    db: DBSettings = DBSettings()
    jwt: JWTSettings = JWTSettings()


settings = Settings()
