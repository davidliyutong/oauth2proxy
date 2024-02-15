import http
import json
import datetime
from typing import Tuple, Optional
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from jsonpath_ng import parse
from loguru import logger
from sanic import Blueprint
from sanic.response import json as json_response
from sanic.response import redirect as redirect_response
from sanic_ext import openapi

import src.errors as errors
import src.config as config
from src.config import OAuth2Config
from src.datamodels import UserFilter, ResponseBaseModel, OAuthToken
from src.utils import random_password, get_authorized_token_response, get_unauthorized_token_response, parse_bearer

bp = Blueprint("auth_oidc", url_prefix="/auth/oidc", version=1)


class AsyncOauthClient:
    """
    AsyncOauthClient is a client for OAuth2 that uses httpx to accomplish operations
    """

    def __init__(self, cfg: OAuth2Config):
        self._cfg = cfg
        self._client = httpx.AsyncClient()
        self._oauth_token = None  # cached oauth token
        self._public_keys = None  # cached public keys

        self._user_info_expr = parse(self._cfg.user_info_path)

    async def fetch_token(self, code: str) -> Tuple[Optional[OAuthToken], Optional[Exception]]:
        """
        Fetch token with authorization code from token endpoint
        """
        _headers = {
            "accept": "application/json"
        }

        # call endpoint
        res = await self._client.post(
            self._cfg.token_url,
            headers=_headers,
            auth=(self._cfg.client_id, self._cfg.client_secret),
            data={
                "grant_type": self._cfg.grant_type,
                "client_id": self._cfg.client_id,
                "client_secret": self._cfg.client_secret,
                "code": code,
                "redirect_uri": self._cfg.redirect_url
            }
        )

        # parse token
        if res.status_code == http.HTTPStatus.OK:
            oauth_token = OAuthToken(**res.json())
            self._oauth_token = oauth_token
            return oauth_token, None
        else:
            return None, Exception("Authorization Error")

    async def fetch_user(self, oauth_token: OAuthToken = None) -> Tuple[Optional[dict], Optional[Exception]]:
        """
        Fetch user info with access token from user info endpoint, use the cached oauth_token if not provided
        """
        if oauth_token is None:
            oauth_token = self._oauth_token

        # Get user info from Authentik using the access token
        _headers = {"Authorization": f"Bearer {oauth_token.access_token}"}
        res = await self._client.get(self._cfg.user_info_url, headers=_headers)
        try:
            res.raise_for_status()
        except Exception as e:
            return None, e
        user_payload = res.json()
        logger.debug(f"user_payload(raw): {user_payload}")
        user_info = self._user_info_expr.find(user_payload)[0].value

        return user_info, None

    async def fetch_public_keys(self) -> Tuple[Optional[dict], Optional[Exception]]:
        """
        Fetch public keys from jwks endpoint
        """
        # call endpoint
        res = await self._client.get(self._cfg.jwks_url)
        try:
            res.raise_for_status()
        except Exception as e:
            return None, e

        # decode jwks response
        public_keys = {}
        jwks = res.json()
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.get_algorithm_by_name('RSAAlgorithm').from_jwk(json.dumps(jwk))

        self._public_keys = public_keys
        return public_keys, None

    async def validate_token(self, token: str) -> Tuple[Optional[dict], Optional[Exception]]:
        if self._public_keys is None:
            await self.fetch_public_keys()

        try:
            kid = jwt.get_unverified_header(token)['kid']
            key = self._public_keys[kid]
            payload = jwt.decode(token, key=key, algorithms=['RS256'])
        except Exception as e:
            return None, e

        return payload, None

    async def generate_jwt_token(self,
                                 username: str,
                                 expire: Optional[datetime.timedelta] = None) -> Tuple[str, Optional[Exception]]:
        """
        Generate jwt token for user, using global secret, used in OIDC login
        """
        if expire is None:
            expire = datetime.timedelta(seconds=3600)

        # generate jwt
        now = datetime.datetime.utcnow()
        payload = {
            'username': username,
            'exp': now + expire,
            'iat': now,
        }
        secret = self._cfg.jwt_secret
        access_token = jwt.encode(payload, secret, algorithm=self._cfg.jwt_algorithm)

        return access_token, None

    async def validate_user(self, user_info: dict) -> Tuple[Optional[str], Optional[Exception]]:
        """
        This function checks if the user exists, if not, create user
        """
        _f: UserFilter = self._cfg.get_user_filter_instance()
        if all([
            _f.filter(user_info),
        ]):
            # try parse username and email
            try:
                username_expr = self._cfg.get_user_expr_instance()
                username = username_expr.find(user_info)[0].value
            except Exception as e:
                logger.error(f"failed to parse username: {e}")
                return None, errors.user_failed_to_parse

            access_token, err = await self.generate_jwt_token(username)
            return access_token, err
        else:
            return None, errors.user_not_allowed


@bp.get("/login", name="login", version=1)
@openapi.definition(
    response=[
        openapi.definitions.Response(
            status=302,
            description="redirect to authorization url"
        )
    ]
)
async def oidc_login(request):
    """
    This handler redirect user to IdP login page
    """
    logger.debug(f"{request.method} {request.path} invoked")
    c: OAuth2Config = request.app.ctx.oauth2_cfg
    return redirect_response(c.authorization_redirect_url)


@bp.get("/authorize", name="authorize", version=1)
@openapi.definition(
    response=[
        openapi.definitions.Response(
            status=302,
            description="redirect to authorization url"
        ),
        openapi.definitions.Response(
            status=400,
            description="Authorization Error"
        )
    ]
)
async def oidc_authorize(request):
    """
    This endpoint is called by identity provider after user login, will redirect to frontend login page with cookies
    """
    logger.debug(f"{request.method} {request.path} invoked")
    c: AsyncOauthClient = request.app.ctx.oauth2_client
    cfg: OAuth2Config = request.app.ctx.oauth2_cfg

    # fetch token with authorization code
    oauth_token, err = await c.fetch_token(request.args.get("code"))
    # oauth_token, err = await c.refresh_token(oauth_token)
    if err is not None:
        return json_response(
            ResponseBaseModel(
                status=http.HTTPStatus.BAD_REQUEST,
                message=str(err),
            ).model_dump(), status=http.HTTPStatus.BAD_REQUEST
        )

    # fetch user info with access token
    user_info, err = await c.fetch_user(oauth_token)
    if err is not None:
        return json_response(
            ResponseBaseModel(
                status=http.HTTPStatus.BAD_REQUEST,
                message=str(err),
            ).model_dump(), status=http.HTTPStatus.BAD_REQUEST
        )

    # try to decode id_token
    logger.debug(f"id_payload: {oauth_token.id_payload}")

    # create or login
    access_token, err = await c.validate_user(user_info)

    if err is not None:

        return json_response(
            ResponseBaseModel(
                status=http.HTTPStatus.BAD_REQUEST,
                message=str(err),
                description="Authorization Error"
            ).model_dump(), status=http.HTTPStatus.BAD_REQUEST
        )

    else:
        # attention: this refresh token is generated according to :
        # https://sanic-jwt.readthedocs.io/en/latest/pages/refreshtokens.html
        refresh_token = random_password(24)
        return redirect_response(
            cfg.get_frontend_redirect_url(
                token=access_token,
            )
        )
        # return json_response({"jwt": access_token}, http.HTTPStatus.OK)


@bp.get("/validate", name="validate", version=1)
@openapi.definition(
    response=[
        openapi.definitions.Response(
            status=200
        ),
        openapi.definitions.Response(
            status=401
        ),
    ],
    secured={"token": []}
)
async def oidc_validate(request):
    """
    This function validates the token in:
    - header.Authorization
    - urlParam.oauth2proxy_auth_token

    If the validation succeed, return 200 OK and set cookie oauth2proxy_auth_token=${JWT}
    """
    logger.debug(f"{request.method} {request.path} invoked")
    # try to get from cookies
    cfg: OAuth2Config = request.app.ctx.oauth2_cfg

    cookies_token = request.cookies.get(config.CONFIG_AUTH_COOKIES_NAME, None)
    if cookies_token is None:
        # cookie does not exists, fallback to header
        logger.debug(f"validation_err: no cookies found, fallback to header")
        token, err = parse_bearer(request.headers.get('Authorization'))
        if err is not None:
            # header does not exists, fallback to query
            logger.debug(f"validation_err: {str(err)}, fallback to query")

            # attention: the proxy must pass the x-original-url header that contains original url
            origin_url = request.headers.get(config.CONFIG_PROXY_ORIGIN_URL_HEADER)
            if origin_url is None:
                logger.debug(f"validation_err: misconfigured proxy, no {config.CONFIG_PROXY_ORIGIN_URL_HEADER}")
                return get_unauthorized_token_response()
            else:
                result = parse_qs(urlparse(origin_url).query)
                token = result.get(config.CONFIG_AUTH_COOKIES_NAME, [None])[0]
                if token is None:
                    logger.debug(f"validation_err: {config.CONFIG_AUTH_COOKIES_NAME} not found in query")
                    return get_unauthorized_token_response()
    else:
        # succeed
        token = cookies_token

    # decode the jwt and check the signature
    try:
        _ = jwt.decode(
            token,
            cfg.jwt_secret,
            algorithms=cfg.jwt_algorithm
        )
    except Exception as e:
        logger.debug(f"validation_err: {str(e)}")
        return get_unauthorized_token_response()

    if cookies_token is None:
        return get_authorized_token_response(token=token)
    else:
        return get_authorized_token_response()
