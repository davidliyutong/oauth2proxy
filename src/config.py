import os
from typing import List, Optional

import httpx
import shortuuid
from jsonpath_ng import parse

from pydantic import BaseModel, model_validator

from src.datamodels import UserFilter

class ServerConfig(BaseModel):
    debug: bool = False

    api_num_workers: int = 4
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_access_log: bool = False

    oidc_name: str = "clpl"
    oidc_base_url: str = "https://authentik.example.com"
    oidc_authorization_url: str = ""
    oidc_token_url: str = ""
    oidc_user_info_url: str = ""
    oidc_logout_url: str = ""
    oidc_jwks_url: str = ""
    oidc_frontend_login_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    oidc_scope: List[str] = ["openid"]
    oidc_scope_delimiter: str = "+"
    oidc_response_type: str = "code"
    oidc_grant_type: str = "authorization_code"
    oidc_user_filter: str = "{}"  # {"$and": [{"organize.id": "26000"}]}
    oidc_user_info_path: str = "$"  # entities[0]
    oidc_username_path: str = "preferred_username"  # account
    oidc_email_path: str = "email"

    oidc_login_expire_second: int = 3600
    oidc_jwt_secret: str = "CHANGE_ME"
    oidc_jwt_algorithm: str = "HS256"

    @classmethod
    def load_config(cls, env: Optional[dict] = None):
        if env is None:
            env = os.environ
        oidc_scope_delimiter = env.get("OIDC_SCOPE_DELIMITER", "+")
        return cls(
            debug=env.get("DEBUG", "false").lower() == "true",
            api_num_workers=int(env.get("API_NUM_WORKERS", "4")),
            api_host=env.get("API_HOST", "0.0.0.0"),
            api_port=int(env.get("API_PORT", "8080")),
            api_access_log=env.get("API_ACCESS_LOG", "false").lower() == "true",
            oidc_name=env.get("OIDC_NAME", "clpl"),
            oidc_base_url=env.get("OIDC_BASE_URL", "https://authentik.example.com"),
            oidc_authorization_url=env.get("OIDC_AUTHORIZATION_URL", ""),
            oidc_token_url=env.get("OIDC_TOKEN_URL", ""),
            oidc_user_info_url=env.get("OIDC_USER_INFO_URL", ""),
            oidc_logout_url=env.get("OIDC_LOGOUT_URL", ""),
            oidc_jwks_url=env.get("OIDC_JWKS_URL", ""),
            oidc_frontend_login_url=env.get("OIDC_FRONTEND_LOGIN_URL", ""),
            oidc_client_id=env.get("OIDC_CLIENT_ID", ""),
            oidc_client_secret=env.get("OIDC_CLIENT_SECRET", ""),
            oidc_redirect_url=env.get("OIDC_REDIRECT_URL", ""),
            oidc_scope=env.get("OIDC_SCOPE", "openid").split(oidc_scope_delimiter),
            oidc_scope_delimiter=oidc_scope_delimiter,
            oidc_response_type=env.get("OIDC_RESPONSE_TYPE", "code"),
            oidc_grant_type=env.get("OIDC_GRANT_TYPE", "authorization_code"),
            oidc_user_filter=env.get("OIDC_USER_FILTER", "{}"),
            oidc_user_info_path=env.get("OIDC_USER_INFO_PATH", "$"),
            oidc_username_path=env.get("OIDC_USERNAME_PATH", "preferred_username"),
            oidc_email_path=env.get("OIDC_EMAIL_PATH", "email"),
            oidc_login_expire_second=int(env.get("OIDC_LOGIN_EXPIRE_SECOND", "3600")),
            oidc_jwt_secret=env.get("OIDC_JWT_SECRET", "CHANGE_ME"),
            oidc_jwt_algorithm=env.get("OIDC_JWT_ALGORITHM", "HS256")
        )

    @classmethod
    def default_config_string(cls):
        x = cls().model_dump()
        items = []
        for k, v in x.items():
            items.append(f"{k.upper()}={v}")
        return "\n".join(items)


class OAuth2Config(BaseModel):
    """
    OAuth2 config, contains all parameters needed for OAuth2
    """
    _client: httpx.AsyncClient = None
    _user_filter_instance: UserFilter = None
    _username_expr: parse = None
    _email_expr: parse = None

    name: str
    base_url: str
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    user_info_url: Optional[str] = None
    logout_url: Optional[str] = None
    jwks_url: Optional[str] = None
    frontend_login_url: Optional[str] = None
    client_id: str
    client_secret: str
    redirect_url: str
    scope: List[str] = ["openid"]
    scope_delimiter: str = "+"
    state: str = shortuuid.uuid()
    response_type: str = "code"
    grant_type: str = "authorization_code"
    user_filter: str = "{}"
    user_info_path: str = "$"
    username_path: str = "preferred_username"
    email_path: str = "email"
    login_expire_second: int = 3600
    jwt_secret: str = "CHANGE_ME"
    jwt_algorithm: str = "HS256"

    @classmethod
    def from_server_config(cls, cfg: ServerConfig):
        """
        Create OAuth2Config from APIServerConfig
        """
        return cls(
            name=cfg.oidc_name,
            base_url=cfg.oidc_base_url,
            authorization_url=cfg.oidc_authorization_url,
            token_url=cfg.oidc_token_url,
            user_info_url=cfg.oidc_user_info_url,
            logout_url=cfg.oidc_logout_url,
            jwks_url=cfg.oidc_jwks_url,
            frontend_login_url=cfg.oidc_frontend_login_url,
            client_id=cfg.oidc_client_id,
            client_secret=cfg.oidc_client_secret,
            redirect_url=cfg.oidc_redirect_url,
            scope=cfg.oidc_scope,
            scope_delimiter=cfg.oidc_scope_delimiter,
            response_type=cfg.oidc_response_type,
            grant_type=cfg.oidc_grant_type,
            user_filter=cfg.oidc_user_filter,
            user_info_path=cfg.oidc_user_info_path,
            username_path=cfg.oidc_username_path,
            email_path=cfg.oidc_email_path,
            login_expire_second=cfg.oidc_login_expire_second,
            jwt_secret=cfg.oidc_jwt_secret,
            jwt_algorithm=cfg.oidc_jwt_algorithm
        )

    @model_validator(mode="after")
    def set_urls(self):
        """
        This validator completes urls
        """
        if self.authorization_url is None or self.authorization_url == "":
            self.authorization_url = f"{self.base_url}/authorize/"

        if self.token_url is None or self.token_url == "":
            self.token_url = f"{self.base_url}/token/"

        if self.user_info_url is None or self.user_info_url == "":
            self.user_info_url = f"{self.base_url}/userinfo/"

        if self.logout_url is None or self.logout_url == "":
            self.logout_url = f"{self.base_url}/{self.name}/end-session/"

        if self.jwks_url is None or self.jwks_url == "":
            self.jwks_url = f"{self.base_url}/{self.name}/jwks/"

        if self.frontend_login_url is None or self.frontend_login_url == "":
            self.frontend_login_url = f"{self.base_url}/login"

    @property
    def authorization_redirect_url(self):
        """
        Get authorization redirect url, with parameters
        """
        return (f"{self.authorization_url}?"
                f"response_type={self.response_type}&"
                f"redirect_uri={self.redirect_url}&"
                f"state={self.state}&"
                f"client_id={self.client_id}&"
                f"scope={self.scope_delimiter.join(self.scope)}")

    def get_frontend_redirect_url(self, token: str) -> str:
        """
        Get frontend redirect url, with parameters
        """
        return (f"{self.frontend_login_url}?"
                f"{CONFIG_AUTH_COOKIES_NAME}={token}")


    def get_user_filter_instance(self):
        """
        Get UserFilter
        """
        if self._user_filter_instance is None:
            self._user_filter_instance = UserFilter(mongo_like_filter_str=self.user_filter)
        return self._user_filter_instance

    def get_user_expr_instance(self):
        """
        Get User expression
        """
        if self._username_expr is None:
            self._username_expr = parse(self.username_path)
        return self._username_expr

    def get_email_expr_instance(self):
        """
        Get email expression
        """
        if self._email_expr is None:
            self._email_expr = parse(self.email_path)
        return self._email_expr


CONFIG_AUTH_COOKIES_NAME = "clpl_auth_token"
CONFIG_COOKIE_EXPIRE_SECOND = 7 * 24 * 3600
CONFIG_PROXY_ORIGIN_URL_HEADER = "x-original-url"