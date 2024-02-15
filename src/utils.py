import base64
import http
import logging
import secrets
import sys
from functools import wraps
from typing import Optional, Tuple

from loguru import logger
from sanic import json as json_response

from src import errors
from src.datamodels import ResponseBaseModel
from src.config import CONFIG_AUTH_COOKIES_NAME, CONFIG_COOKIE_EXPIRE_SECOND


def singleton(cls):
    """
    Singleton decorator. Make sure only one instance of cls is created.

    :param cls: cls
    :return: instance
    """
    _instances = {}

    @wraps(cls)
    def instance(*args, **kw):
        if cls not in _instances:
            _instances[cls] = cls(*args, **kw)
        return _instances[cls]

    return instance


def random_password(length: int = 16) -> str:
    """
    Generate random password
    """
    return base64.encodebytes(secrets.token_bytes(length))[:length].decode('utf-8')


def get_authorized_token_response(token: str=None, max_age=None):
    """
    This function returns an authorized response for token/validation endpoint
    """
    r = json_response(
        body=ResponseBaseModel(
            description='',
            message='AUTHORIZED',
            status=http.HTTPStatus.OK
        ).model_dump(),
        headers={
            'WWW-Authenticate': "Bearer"
        },
        status=http.HTTPStatus.OK
    )
    if token is not None:
        if max_age is None:
            max_age = CONFIG_COOKIE_EXPIRE_SECOND
        r.add_cookie(
            CONFIG_AUTH_COOKIES_NAME,
            token,
            max_age=max_age
        )
    return r


def get_unauthorized_token_response():
    """
    This function returns an unauthorized response for token/validation endpoint
    It also deletes a the cookie config.CONFIG_AUTH_COOKIES_NAME
    """
    r = json_response(
        body=ResponseBaseModel(
            description='',
            message='UNAUTHORIZED',
            status=http.HTTPStatus.UNAUTHORIZED
        ).model_dump(),
        status=http.HTTPStatus.UNAUTHORIZED
    )
    r.delete_cookie(CONFIG_AUTH_COOKIES_NAME)
    return r


def parse_bearer(bearer_str: Optional[str]) -> Tuple[Optional[str], Optional[Exception]]:
    """
    Parse bearer auth header
    """
    if bearer_str is None or len(bearer_str) == 0:
        return None, errors.header_missing
    authorization_header_split = bearer_str.split(' ')
    if len(authorization_header_split) != 2 or authorization_header_split[0] != 'Bearer':
        return None, errors.header_malformed

    return authorization_header_split[1], None
