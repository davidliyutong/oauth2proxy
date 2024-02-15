import json
from typing import Optional

import jwt
import mongoquery
from pydantic import BaseModel


class UserFilter:
    """
    User filter, use mongodb like filter string to filter allowed users
    """
    mongo_like_filter_str: Optional[str] = None  # e.g. {"username": "admin"}
    _mongo_like_filter: mongoquery.Query

    def __init__(self, mongo_like_filter_str: str = None):
        """
        Init user filter
        """
        self.mongo_like_filter_str = mongo_like_filter_str
        if self.mongo_like_filter_str is not None:
            self._mongo_like_filter = mongoquery.Query(json.loads(self.mongo_like_filter_str))
        else:
            self._mongo_like_filter = mongoquery.Query({})

    def filter(self, user_info: dict) -> bool:
        return self._mongo_like_filter.match(user_info)


class ResponseBaseModel(BaseModel):
    """
    Base model for response
    """
    description: str = ""  # description of the response
    status: int  # status code of the response
    message: str  # message of the response


class OIDCStatusResponse(BaseModel):
    name: str
    path: str


class OAuthToken(BaseModel):
    """
    OAuth token model
    """
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    id_token: Optional[str] = None

    @property
    def id_payload(self) -> Optional[dict]:
        """
        Decode id_token, skip signature verification
        """
        if self.id_token is not None and self.id_token != "":
            return jwt.decode(self.id_token, options={"verify_signature": False})
        else:
            return None
