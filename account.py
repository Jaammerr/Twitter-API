import asyncio
import hashlib
import mimetypes
import platform
import re
import secrets
from pathlib import Path

import httpx

from copy import deepcopy
from datetime import datetime
from string import ascii_letters
from typing import Coroutine, List, Any, LiteralString
from uuid import uuid1, getnode

from curl_cffi import requests
from curl_cffi.requests.cookies import Cookies
from curl_cffi.requests.headers import Headers
from curl_cffi.requests.errors import RequestsError
from tqdm import tqdm

from .constants import *
from .errors import TwitterAccountSuspended, RateLimitError, IncorrectData
from .util import *



if platform.system() != "Windows":
    try:
        import uvloop

        uvloop.install()
    except ImportError as e:
        ...
    except:
        ...



class TwitterAccount:
    def __init__(self):
        self._session: requests.Session = requests.Session()

        self.gql_api = "https://twitter.com/i/api/graphql"
        self.v1_api = "https://api.twitter.com/1.1"
        self.v2_api = "https://twitter.com/i/api/2"

    @classmethod
    def run(
            cls,
            auth_token: str = None,
            cookies: dict[str, str] = None,
            proxy: str = None,
            setup_session: bool = True,
    ) -> "TwitterAccount":
        """

        :param auth_token: auth token from your account
        :param cookies: dict with cookies, required if auth_token is not set, dict must contain auth_token
        :param proxy: ip:port:username:password | http://username:password@ip:port
        :param setup_session: setup session if cookies are not fully or if using auth_token. Recommended to set to True.
        :return: TwitterAccount instance
        """
        account = cls()
        account._session = account.__get_session(proxy)

        if not (auth_token, cookies):
            if cookies and not cookies.get("auth_token"):
                raise IncorrectData(
                    "Missing required parameters. You must provide auth_token in cookies."
                )

            raise IncorrectData(
                "Missing required parameters. You must provide either auth_token or cookies."
            )

        if setup_session:
            if auth_token:
                account.session.cookies.update({"auth_token": auth_token})
                account.__setup_session()
            else:
                account.session.cookies.update(cookies)

        else:
            if not account.session.cookies.get(
                    "auth_token"
            ) and not account.session.cookies.get("ct0"):
                account.session.cookies.update({"auth_token": auth_token})
                account.__setup_session()
            else:
                account.session.cookies.update(cookies)

        return account

    @staticmethod
    def __get_session(proxy: str = None) -> requests.Session:
        session = requests.Session(timeout=30, verify=False)
        if proxy:
            if proxy.startswith("http://"):
                session.proxies = {"http": proxy, "https": proxy}

            else:
                proxy_values = proxy.split(":")
                if len(proxy_values) != 4:
                    raise IncorrectData("Proxy must be in format: ip:port:username:password or http://username:password@ip:port")

                ip, port, username, password = proxy_values
                proxy_str = f"http://{username}:{password}@{ip}:{port}"
                session.proxies = {"http": proxy_str, "https": proxy_str}

        return session

    @property
    def get_auth_data(self) -> dict:
        """
        :return: dict with auth_token, cookies, proxy
        """
        return {
            "auth_token": self.auth_token,
            "cookies": dict(self.cookies),
            "proxy": self.proxy,
        }

    def gql(
            self,
            method: str,
            operation: tuple,
            variables: dict,
            features: dict = Operation.default_features,
    ) -> dict:
        qid, op = operation
        _params = {
            "queryId": qid,
            "features": features,
            "variables": Operation.default_variables | variables,
        }
        if method == "POST":
            _data = {"json": _params}
        else:
            _data = {"params": {k: orjson.dumps(v).decode() for k, v in _params.items()}}

        r = self.session.request(
            method=method,
            url=f"{self.gql_api}/{qid}/{op}",
            headers=get_headers(self.session),
            allow_redirects=True,
            **_data,
        )

        return self._verify_response(r)

    def v1(self, path: str, _params: dict) -> dict:
        headers = get_headers(self.session)
        headers["content-type"] = "application/x-www-form-urlencoded"

        r = self.session.post(
            f"{self.v1_api}/{path}", headers=headers, data=_params, allow_redirects=True
        )
        return self._verify_response(r)

    @staticmethod
    def _verify_response(r: Response) -> dict:
        try:
            rate_limit_remaining = r.headers.get("x-rate-limit-remaining")
            if rate_limit_remaining and int(rate_limit_remaining) in (0, 1):
                reset_ts = int(r.headers.get("x-rate-limit-reset"))
                raise RateLimitError(
                    f"Rate limit reached. Reset in {reset_ts - int(time.time())} seconds. "
                )
                # current_ts = int(time.time())
                # difference = reset_ts - current_ts
                # asyncio.sleep(difference)

            _data = r.json()
        except ValueError:
            raise TwitterError(
                {
                    "error_message": f"Failed to parse response: {r.text}. "
                                     "If you are using proxy, make sure it is not blocked by Twitter."
                }
            )

        if "errors" in _data:
            error_message = (
                _data["errors"][0].get("message") if _data["errors"] else _data["errors"]
            )

            error_code = _data["errors"][0].get("code") if _data["errors"] else None

            if isinstance(error_message, str) and error_message.lower().startswith(
                    "to protect our users from spam and other"
            ):
                raise TwitterAccountSuspended(error_message)

            raise TwitterError(
                {
                    "error_code": error_code,
                    "error_message": error_message,
                }
            )

        try:
            r.raise_for_status()
        except RequestsError as http_error:
            raise TwitterError(
                {
                    "error_message": str(http_error),
                }
            )

        return _data

    @property
    def proxy(self) -> str:
        return self._session.proxies.get("http", None)

    @property
    def session(self):
        return self._session

    @property
    def cookies(self) -> Cookies:
        return self._session.cookies

    @property
    def headers(self) -> Headers:
        return self._session.headers

    @property
    def auth_token(self) -> str:
        return self._session.cookies.get("auth_token", "")

    @property
    def ct0(self) -> str:
        return self._session.cookies.get("ct0", "")

    def request_ct0(self) -> str:
        url = "https://twitter.com/i/api/2/oauth2/authorize"
        r = self.session.get(url, allow_redirects=True)

        if "ct0" in r.cookies:
            return r.cookies.get("ct0")
        else:
            raise TwitterError(
                {
                    "error_message": "Failed to get ct0 token. "
                                     "Make sure you are using correct cookies."
                }
            )

    def request_guest_token(
            self, session: requests.Session, csrf_token: str = None
    ) -> str:
        if not (csrf_token, self.session.cookies.get("ct0", "")):
            raise TwitterError(
                {
                    "error_message": "Failed to get guest token. "
                                     "Make sure you are using correct cookies."
                }
            )

        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
            "x-csrf-token": (
                csrf_token if csrf_token else self.session.cookies.get("ct0")
            ),
        }
        r = session.post(
            f"{self.v1_api}/guest/activate.json",
            headers=headers,
            allow_redirects=True,
        )

        _data = self._verify_response(r)
        return _data["guest_token"]

    def __setup_session(self):
        session = requests.Session(
            proxies=self.session.proxies if self.session.proxies else None,
            timeout=30,
            verify=False,
        )

        generated_csrf_token = secrets.token_hex(16)
        guest_token = self.request_guest_token(session, generated_csrf_token)

        cookies = {"ct0": generated_csrf_token, "gt": guest_token}
        headers = {"x-guest-token": guest_token, "x-csrf-token": generated_csrf_token}

        self._session.headers.update(headers)
        self._session.cookies.update(cookies)
        csrf_token = self.request_ct0()

        self._session.headers["x-csrf-token"] = csrf_token
        self._session.cookies.delete("ct0")
        self._session.cookies.update({"ct0": csrf_token})
        self._session.headers = get_headers(self.session)

        self.verify_credentials()

    def bind_account_v1(self, url: str) -> dict[str, LiteralString | Any]:
        """

        :param url: HTTP URL from target site
        :return: dict with oauth_token, oauth_verifier, url
        """

        def get_oauth_token() -> str:
            _response = requests.get(url, allow_redirects=True)
            raise_for_status(_response)

            token = re.search(
                r'<input id="oauth_token" name="oauth_token" type="hidden" value="([^"]+)"',
                _response.text,
            )
            if token:
                return token.group(1)

            token = _response.text.split("oauth_token=")
            if len(token) > 1:
                return token[1]

            raise TwitterError(
                {
                    "error_message": "Failed to get oauth token. "
                                     "Make sure you are using correct URL."
                }
            )

        def get_authenticity_token(_oauth_token: str) -> dict[str, LiteralString | Any] | str:
            _params = {
                "oauth_token": _oauth_token,
            }
            _response = self.session.get(
                "https://api.twitter.com/oauth/authenticate", params=_params
            )
            raise_for_status(_response)

            token = re.search(
                r'<input name="authenticity_token" type="hidden" value="([^"]+)"',
                _response.text,
            )
            if token:
                return token.group(1)

            bond_url = re.search(
                r'<a class="maintain-context" href="([^"]+)', _response.text
            )
            if bond_url:
                bond_url = bond_url.group(1).replace("&amp;", "&")
                _oauth_token, _oauth_verifier = bond_url.split("oauth_token=")[1].split(
                    "&oauth_verifier="
                )

                return {
                    "url": bond_url,
                    "oauth_token": _oauth_token,
                    "oauth_verifier": _oauth_verifier,
                }

            raise TwitterError(
                {
                    "error_message": "Failed to get authenticity token. "
                                     "Make sure you are using correct cookies or url."
                }
            )

        def get_confirm_url(_oauth_token: str, _authenticity_token: str) -> str:
            _data = {
                "authenticity_token": _authenticity_token,
                "redirect_after_login": f"https://api.twitter.com/oauth/authorize?oauth_token={_oauth_token}",
                "oauth_token": _oauth_token,
            }

            response = self.session.post(
                "https://api.twitter.com/oauth/authorize",
                data=_data,
                allow_redirects=True,
            )
            raise_for_status(response)

            _confirm_url = re.search(
                r'<a class="maintain-context" href="([^"]+)', response.text
            )
            if _confirm_url:
                return _confirm_url.group(1).replace("&amp;", "&")

            raise TwitterError(
                {
                    "error_message": "Failed to get confirm url. "
                                     "Make sure you are using correct cookies or url."
                }
            )

        def process_confirm_url(_url: str) -> dict[str, LiteralString | Any]:
            response = self.session.get(_url, allow_redirects=True)
            raise_for_status(response)

            if "status=error" in response.url:
                raise TwitterError(
                    {
                        "error_message": "Failed to bind account. "
                                         "Make sure you are using correct cookies or url."
                    }
                )

            _oauth_token, _oauth_verifier = response.url.split("oauth_token=")[1].split(
                "&oauth_verifier="
            )
            return {
                "url": response.url,
                "oauth_token": _oauth_token,
                "oauth_verifier": _oauth_verifier,
            }

        oauth_token = get_oauth_token()
        authenticity_token = get_authenticity_token(oauth_token)

        if isinstance(authenticity_token, dict):
            return authenticity_token

        confirm_url = get_confirm_url(oauth_token, authenticity_token)
        return process_confirm_url(confirm_url)

    def bind_account_v2(self, bind_params: dict[str, str]) -> str:
        """

        example:
        bind_params = {"code_challenge": "test_project", "code_challenge_method": "plain", "client_id": "infoUjhndkd45fgld29aTW96eGM6MTpjaQ", "redirect_uri": "https://www.test.com/test_project", "response_type": "code", "scope": "tweet.read users.read follows.read offline.access", "state": "test_project"}

        :param bind_params: dict with code_challenge, client_id, redirect_uri, state
        :return: str with approved code
        """

        REQUIRED_PARAMS = ("code_challenge", "client_id", "redirect_uri", "state")
        if not all(param in bind_params for param in REQUIRED_PARAMS):
            raise IncorrectData(
                {
                    "error_message": "Missing required parameters. "
                                     "Make sure you are using correct parameters."
                                     "Required parameters: code_challenge, client_id, redirect_uri, state."
                }
            )

        if "code_challenge_method" not in bind_params:
            bind_params["code_challenge_method"] = "plain"
        if "response_type" not in bind_params:
            bind_params["response_type"] = "code"
        if "scope" not in bind_params:
            bind_params["scope"] = "tweet.read users.read follows.read offline.access"

        def get_auth_code() -> str:
            response = self.session.get(
                "https://twitter.com/i/api/2/oauth2/authorize",
                params=bind_params,
            )
            raise_for_status(response)
            self.session.headers.update(
                {"x-csrf-token": self.session.cookies.get("ct0", domain=".twitter.com")}
            )
            return response.json()["auth_code"]

        def approve_auth_code(_auth_code: str) -> str:
            _params = {
                "approval": "true",
                "code": _auth_code,
            }

            response = self.session.post(
                "https://twitter.com/i/api/2/oauth2/authorize",
                params=_params,
                allow_redirects=True,
            )
            raise_for_status(response)

            code = response.json()["redirect_uri"].split("code=")[1]
            return code

        auth_code = get_auth_code()
        approved_code = approve_auth_code(auth_code)
        return approved_code

    def create_poll(self, text: str, choices: list[str], poll_duration: int) -> dict:
        if poll_duration > 10080:
            raise TwitterError(
                {
                    "error_message": "Poll duration is too long. Max duration is 10080."
                }
            )

        options = {
            "twitter:card": "poll4choice_text_only",
            "twitter:api:api:endpoint": "1",
            "twitter:long:duration_minutes": poll_duration,  # max: 10080
        }
        for i, c in enumerate(choices):
            options[f"twitter:string:choice{i + 1}_label"] = c

        headers = get_headers(self.session)
        headers["content-type"] = "application/x-www-form-urlencoded"
        url = "https://caps.twitter.com/v2/cards/create.json"

        r = self.session.post(
            url,
            headers=headers,
            params={"card_data": orjson.dumps(options).decode()},
            allow_redirects=True,
        )
        card_uri = (self._verify_response(r))["card_uri"]

        _data = self.tweet(text, poll_params={"card_uri": card_uri})
        return _data

    def verify_credentials(self) -> dict:
        r = self.session.get(
            f"{self.v1_api}/account/verify_credentials.json", allow_redirects=True
        )
        return self._verify_response(r)

    def email_phone_info(self) -> dict:
        """
        example: {'emails': [{'email': 'testest123@gmx.com', 'email_verified': True}], 'phone_numbers': []}
        :return: dict with list of emails and dict with list of phone numbers
        """
        r = self.session.get(
            f"{self.v1_api}/users/email_phone_info.json", allow_redirects=True
        )
        return self._verify_response(r)

    def settings_info(self) -> dict:
        """
        :return: dict with account settings
        """

        r = self.session.get(
            f"{self.v1_api}/account/settings.json", allow_redirects=True
        )
        return self._verify_response(r)

    def screen_name(self) -> str:
        """
        :return: profile screen name
        """

        _data = self.verify_credentials()
        return _data["screen_name"]

    def user_id(self) -> int:
        """
        :return: profile user id
        """

        _data = self.verify_credentials()
        return _data["id"]

    def name(self) -> str:
        """
        :return: profile name
        """

        _data = self.verify_credentials()
        return _data["name"]

    def location(self) -> str:
        """
        :return: profile location
        """

        _data = self.verify_credentials()
        return _data["location"]

    def description(self) -> str:
        """
        :return: profile description
        """

        _data = self.verify_credentials()
        return _data["description"]

    def followers_count(self) -> int:
        _data = self.verify_credentials()
        return _data["followers_count"]

    def friends_count(self) -> int:
        _data = self.verify_credentials()
        return _data["friends_count"]

    def registration_date(self) -> str:
        _data = self.verify_credentials()
        return _data["created_at"]

    def suspended(self) -> bool:
        _data = self.verify_credentials()
        return _data["suspended"]

    def dm(self, text: str, receivers: list[int], media: str = "") -> dict:
        variables = {
            "message": {},
            "requestId": str(uuid1(getnode())),
            "target": {"participant_ids": receivers},
        }
        if media:
            media_id = self.upload_media(media, is_dm=True)
            variables["message"]["media"] = {"id": media_id, "text": text}
        else:
            variables["message"]["text"] = {"text": text}

        res = self.gql("POST", Operation.useSendMessageMutation, variables)
        if find_key(res, "dm_validation_failure_type"):
            raise TwitterError(
                {
                    "error_message": "Failed to send message. Sender does not have privilege to dm receiver(s)",
                    "error_code": 349,
                }
            )
        return res

    def custom_dm(self, text: str, receiver: int) -> dict:
        json_data = {
            "event": {
                "type": "message_create",
                "message_create": {
                    "target": {"recipient_id": f"{receiver}"},
                    "message_data": {"text": f"{text}"},
                },
            }
        }

        r = self.session.post(
            f"{self.v1_api}/direct_messages/events/new.json",
            json=json_data,
        )
        return self._verify_response(r)

    def delete_tweet(self, tweet_id: int | str) -> dict:
        variables = {"tweet_id": tweet_id, "dark_request": False}
        return self.gql("POST", Operation.DeleteTweet, variables)

    def tweet(
            self, text: str, media: List[dict] = None, **kwargs
    ) -> dict | Coroutine[Any, Any, dict]:
        """

        media example: [{"media_id": 10349834, "tagged_users": ["user1", "user2"]}]

        :param text: Tweet text
        :param media: List of media entities
        :param kwargs: reply_params, quote_params, poll_params, draft, schedule

        """
        variables = {
            "tweet_text": text,
            "dark_request": False,
            "media": {
                "media_entities": [],
                "possibly_sensitive": False,
            },
            "semantic_annotation_ids": [],
        }

        if reply_params := kwargs.get("reply_params", {}):
            variables |= reply_params
        if quote_params := kwargs.get("quote_params", {}):
            variables |= quote_params
        if poll_params := kwargs.get("poll_params", {}):
            variables |= poll_params

        draft = kwargs.get("draft")
        schedule = kwargs.get("schedule")

        if draft or schedule:
            variables = {
                "post_tweet_request": {
                    "auto_populate_reply_metadata": False,
                    "status": text,
                    "exclude_reply_user_ids": [],
                    "media_ids": [],
                },
            }
            if media:
                for m in media:
                    # media_id = self.upload_media(m["media"])
                    variables["post_tweet_request"]["media_ids"].append(m["media_id"])

            if schedule:
                variables["execute_at"] = (
                    datetime.strptime(schedule, "%Y-%m-%d %H:%M").timestamp()
                    if isinstance(schedule, str)
                    else schedule
                )
                return self.gql("POST", Operation.CreateScheduledTweet, variables)

            return self.gql("POST", Operation.CreateDraftTweet, variables)

        # regular tweet
        if media:
            for m in media:

                tagged_users_id = []
                for tagged_user in m["tagged_users"]:
                    user_id = self.get_user_id(tagged_user)
                    tagged_users_id.append(user_id)

                variables["media"]["media_entities"].append(
                    {"media_id": m["media_id"], "tagged_users": tagged_users_id}
                )

        return self.gql("POST", Operation.CreateTweet, variables)

    def schedule_tweet(
            self, text: str, date: int | str, media: List[dict] = None
    ) -> dict:
        """

        media example: [{"media_id": 10349834, "tagged_users": ["user1", "user2"]}]

        :param text: Tweet text
        :param date: Scheduled date
        :param media: List of media entities
        """

        variables = {
            "post_tweet_request": {
                "auto_populate_reply_metadata": False,
                "status": text,
                "exclude_reply_user_ids": [],
                "media_ids": [],
            },
            "execute_at": (
                datetime.strptime(date, "%Y-%m-%d %H:%M").timestamp()
                if isinstance(date, str)
                else date
            ),
        }
        if media:
            for m in media:

                tagged_users_id = []
                for tagged_user in m["tagged_users"]:
                    user_id = self.get_user_id(tagged_user)
                    tagged_users_id.append(user_id)

                variables["media"]["media_entities"].append(
                    {"media_id": m["media_id"], "tagged_users": tagged_users_id}
                )

        return self.gql("POST", Operation.CreateScheduledTweet, variables)

    def schedule_reply(
            self, text: str, date: int | str, tweet_id: int, media: List[dict] = None
    ) -> dict:
        """

        media example: [{"media_id": 10349834}]

        :param text: Scheduled tweet text
        :param date: Scheduled date
        :param tweet_id: Tweet id to reply
        :param media: List of media entities
        """
        variables = {
            "post_tweet_request": {
                "auto_populate_reply_metadata": True,
                "in_reply_to_status_id": tweet_id,
                "status": text,
                "exclude_reply_user_ids": [],
                "media_ids": [],
            },
            "execute_at": (
                datetime.strptime(date, "%Y-%m-%d %H:%M").timestamp()
                if isinstance(date, str)
                else date
            ),
        }
        if media:
            for m in media:
                variables["post_tweet_request"]["media_ids"].append(m["media_id"])

        return self.gql("POST", Operation.CreateScheduledTweet, variables)

    def unschedule_tweet(self, tweet_id: int | str) -> dict:
        variables = {"scheduled_tweet_id": tweet_id}
        return self.gql("POST", Operation.DeleteScheduledTweet, variables)

    def untweet(self, tweet_id: int | str) -> dict:
        variables = {"tweet_id": tweet_id, "dark_request": False}
        return self.gql("POST", Operation.DeleteTweet, variables)

    def reply(
            self, text: str, tweet_id: int | str, media: List[dict] = None
    ) -> dict:
        """

        media example: [{"media_id": 10349834, "tagged_users": ["user1", "user2"]}]

        :param text: Reply text
        :param tweet_id: Tweet id to reply
        :param media: List of media entities
        """

        variables = {
            "tweet_text": text,
            "reply": {
                "in_reply_to_tweet_id": tweet_id,
                "exclude_reply_user_ids": [],
            },
            "batch_compose": "BatchSubsequent",
            "dark_request": False,
            "media": {
                "media_entities": [],
                "possibly_sensitive": False,
            },
            "semantic_annotation_ids": [],
        }

        if media:
            for m in media:

                tagged_users_id = []
                for tagged_user in m["tagged_users"]:
                    user_id = self.get_user_id(tagged_user)
                    tagged_users_id.append(user_id)

                variables["media"]["media_entities"].append(
                    {"media_id": m["media_id"], "tagged_users": tagged_users_id}
                )

        return self.gql("POST", Operation.CreateTweet, variables)

    def quote(self, text: str, tweet_id: int, media: List[dict] = None) -> dict:
        """

        media example: [{"media_id": 10349834, "tagged_users": ["user1", "user2"]}]

        :param text: Quote text
        :param tweet_id: Tweet id to quote
        :param media: List of media entities
        """
        variables = {
            "tweet_text": text,
            "attachment_url": f"https://twitter.com/i/status/{tweet_id}",
            "dark_request": False,
            "media": {
                "media_entities": [],
                "possibly_sensitive": False,
            },
            "semantic_annotation_ids": [],
        }

        if media:
            for m in media:

                tagged_users_id = []
                for tagged_user in m["tagged_users"]:
                    user_id = self.get_user_id(tagged_user)
                    tagged_users_id.append(user_id)

                variables["media"]["media_entities"].append(
                    {"media_id": m["media_id"], "tagged_users": tagged_users_id}
                )

        return self.gql("POST", Operation.CreateTweet, variables)

    def retweet(self, tweet_id: int) -> dict:
        variables = {"tweet_id": tweet_id, "dark_request": False}
        return self.gql("POST", Operation.CreateRetweet, variables)

    def unretweet(self, tweet_id: int) -> dict:
        variables = {"source_tweet_id": tweet_id, "dark_request": False}
        return self.gql("POST", Operation.DeleteRetweet, variables)

    @staticmethod
    def __get_cursor_value(_data: dict, target_cursor_type: str, target_entry_type: str):
        if target_entry_type != "threaded_conversation_with_injections_v2":
            for instruction in (
                    _data.get("data", {}).get(target_entry_type, {}).get("timeline", {}).get("instructions", [])
            ):
                for entry in instruction.get("entries", []):
                    content = entry.get("content", {})
                    cursor_type = content.get("cursorType")
                    if (
                            content.get("entryType") == "TimelineTimelineCursor"
                            and cursor_type == target_cursor_type
                    ):
                        return content.get("value")

        else:
            for instruction in (
                    _data.get("data", {}).get(target_entry_type, {}).get("instructions", [])
            ):
                for entry in instruction.get("entries", []):
                    content = entry.get("content", {})
                    cursor_type = content.get("cursorType")
                    if (
                            content.get("entryType") == "TimelineTimelineCursor"
                            and cursor_type == target_cursor_type
                    ):
                        return content.get("value")

        return None

    def tweet_likes(
            self, tweet_id: int, limit: int = 0
    ) -> dict[str, list[dict]]:
        """

        example: {'users': [{'id': '823236372769239041', 'name': 'David Novisov/ Andrey Gololobov', 'screen_name': 'sabcoin', 'profile_image_url': 'https://pbs.twimg.com/profile_images/1678314980859338752/6kzhp7Lc_normal.jpg', 'favourites_count': 2844, 'followers_count': 490, 'friends_count': 4997, 'location': 'Israel', 'description': 'Investor in cryptocurrencies and stock markets, speculator and degen. I believe in a Higher Power and trend.', 'created_at': 'Sun Jan 22 18:30:21 +0000 2017'}]}

        :return: list of users who liked the tweet
        """
        variables = {"tweetId": tweet_id, "count": 100}
        users_data = []

        while True:
            _data = self.gql("GET", Operation.Favoriters, variables)

            for instruction in (
                    _data.get("data", {}).get("favoriters_timeline", {}).get("timeline", {}).get("instructions", [])
            ):
                try:
                    for entry in instruction["entries"]:
                        try:
                            result = entry["content"]["itemContent"]["user_results"][
                                "result"
                            ]
                            screen_name = result["legacy"]["screen_name"]
                            if screen_name not in (
                                    user["screen_name"] for user in users_data
                            ):
                                users_data.append(
                                    self.get_user_data_from_user_results(result)
                                )

                        except (KeyError, TypeError, IndexError):
                            continue

                except KeyError:
                    return {"users": users_data[:limit] if limit > 0 else users_data}

            cursor_value = self.__get_cursor_value(
                _data, "Bottom", "favoriters_timeline"
            )
            if not cursor_value or (0 < limit <= len(users_data)):
                return {"users": users_data[:limit] if limit > 0 else users_data}

            variables["cursor"] = cursor_value

    def tweet_retweeters(
            self, tweet_id: int, limit: int = 0
    ) -> dict[str, list[Any]]:
        """

        example: {'users': [{'id': '177934673071603712', 'name': 'Abas', 'screen_name': 'aloe4', 'profile_image_url': 'https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png', 'favourites_count': 497, 'followers_count': 34, 'friends_count': 436, 'location': '', 'description': '', 'created_at': 'Mon Apr 15 08:32:17 +0000 2024'}]}

        :return: list of users who retweeted the tweet
        """
        variables = {"tweetId": tweet_id, "count": 100}
        tweets_data = []

        while True:
            _data = self.gql("GET", Operation.Retweeters, variables)

            for instruction in _data["data"]["retweeters_timeline"]["timeline"][
                "instructions"
            ]:
                try:
                    for entry in instruction["entries"]:
                        try:
                            result = entry["content"]["itemContent"]["user_results"][
                                "result"
                            ]
                            screen_name = result["legacy"]["screen_name"]
                            if screen_name not in (
                                    user["screen_name"] for user in tweets_data
                            ):
                                tweets_data.append(
                                    self.get_user_data_from_user_results(result)
                                )
                        except (KeyError, TypeError, IndexError):
                            continue

                except KeyError:
                    return {"users": tweets_data[:limit] if limit > 0 else tweets_data}

            cursor_value = self.__get_cursor_value(
                _data, "Bottom", "retweeters_timeline"
            )

            if not cursor_value or (0 < limit <= len(tweets_data)):
                return {"users": tweets_data[:limit] if limit > 0 else tweets_data}

            variables["cursor"] = cursor_value

    @staticmethod
    def get_user_data_from_user_results(_data: dict) -> dict:
        legacy = _data.get("legacy", {})

        return {
            "id": _data.get("rest_id"),
            "name": legacy.get("name"),
            "screen_name": legacy.get("screen_name"),
            "profile_image_url": legacy.get("profile_image_url_https"),
            "favourites_count": legacy.get("favourites_count"),
            "followers_count": legacy.get("followers_count"),
            "friends_count": legacy.get("friends_count"),
            "location": legacy.get("location"),
            "description": legacy.get("description"),
            "created_at": legacy.get("created_at"),
        }

    def tweet_replies(
            self, tweet_id: int, limit: int = 0
    ) -> dict[str, list[dict[str, dict | Any]]]:
        """

        example: {'replies': [{'reply_text': "123456", 'user_data': {'id': '145016145917347329', 'name': 'test 🍀', 'screen_name': 'test', 'profile_image_url': 'https://pbs.twimg.com/profile_images/434343434343434/zdV_9QjJ_normal.jpg', 'favourites_count': 14439, 'followers_count': 31196, 'friends_count': 142, 'location': '', 'description': 'description',
        'created_at': 'Mon Oct 18 18:05:57 +0000 2021'}}]}

        :return: list of replies to the tweet
        """
        variables = {"focalTweetId": tweet_id}
        replies_data = []

        while True:
            _data = self.gql("GET", Operation.TweetDetail, variables)

            for entry in _data["data"]["threaded_conversation_with_injections_v2"][
                "instructions"
            ][0]["entries"]:
                try:
                    result = entry["content"]["items"][0]["item"]["itemContent"][
                        "tweet_results"
                    ]["result"]
                    reply_text = result["legacy"]["full_text"]
                    user_results = result["core"]["user_results"]["result"]

                    if reply_text not in (
                            reply["reply_text"] for reply in replies_data
                    ):
                        replies_data.append(
                            {
                                "reply_text": reply_text,
                                "user_data": self.get_user_data_from_user_results(
                                    user_results
                                ),
                            }
                        )
                except (KeyError, TypeError, IndexError):
                    continue

            entries = _data["data"]["threaded_conversation_with_injections_v2"][
                "instructions"
            ][0]["entries"]
            if not entries[-1]["entryId"].startswith("cursor-bottom") or (
                    0 < limit <= len(replies_data)
            ):
                return {"replies": replies_data[:limit] if limit > 0 else replies_data}

            for entry in entries:
                if entry["entryId"].startswith("cursor-bottom"):
                    cursor_value = entry["content"]["itemContent"]["value"]
                    variables["cursor"] = cursor_value
                    break

    def user_followers(self, username: str, limit: int = 200) -> list[str]:
        variables = {"screen_name": username, "count": 200}
        _users = []

        while True:
            r = self.session.get(f"{self.v1_api}/followers/list.json", params=variables)
            if r.status_code == 503:
                asyncio.sleep(3)
                continue

            else:
                _data = self._verify_response(r)
                new_users = [user["screen_name"] for user in _data["users"]]
                _users.extend(new_users)

                next_cursor = int(_data.get("next_cursor"))
                if next_cursor == 0 or (0 < limit <= len(_users)):
                    return _users[:limit] if limit > 0 else _users

                variables["cursor"] = _data["next_cursor_str"]

    def user_followings(self, username: str, limit: int = 200) -> list[str]:
        variables = {"screen_name": username, "count": 200}
        _users = []

        while True:
            r = self.session.get(f"{self.v1_api}/friends/list.json", params=variables)
            if r.status_code == 503:
                asyncio.sleep(5)
                continue

            else:
                _data = self._verify_response(r)
                new_users = [user["screen_name"] for user in _data["users"]]
                _users.extend(new_users)

                next_cursor = int(_data.get("next_cursor"))
                if next_cursor == 0 or (0 < limit <= len(_users)):
                    return _users[:limit] if limit > 0 else _users

                variables["cursor"] = _data["next_cursor_str"]

    def user_last_tweets(
            self, username: str
    ) -> list[dict[str, str | Any]]:
        user_id = self.get_user_id(username)
        json_data = self.gql("GET", Operation.UserTweets, {"userId": user_id})

        try:
            tweets_data = []
            timeline = json_data["data"]["user"]["result"]["timeline_v2"]["timeline"]

            for tweet in timeline["instructions"]:
                entries = tweet.get("entries", [])
                for entry in entries:
                    if entry["entryId"].startswith("tweet"):
                        tweet_link = f"https://twitter.com/{username}/status/{entry['entryId'].split('-')[-1]}"
                    else:
                        continue

                    tweet_results = (
                        entry.get("content", {})
                        .get("itemContent", {})
                        .get("tweet_results", {})
                        .get("result", {})
                        .get("legacy")
                    )
                    if tweet_results and tweet_results.get("full_text"):
                        full_text = tweet_results["full_text"]
                        created_at = tweet_results.get("created_at", "")
                        is_quote_status = tweet_results.get("is_quote_status", "")
                        lang = tweet_results.get("lang", "")

                        tweets_data.append(
                            {
                                "tweet_link": tweet_link,
                                "full_text": full_text,
                                "created_at": created_at,
                                "is_quote_status": is_quote_status,
                                "lang": lang,
                            }
                        )

            return tweets_data

        except Exception as error:
            raise TwitterError({"error_message": f"Failed to get user tweets: {error}"})

    def like(self, tweet_id: int) -> dict:
        variables = {"tweet_id": tweet_id}
        return self.gql("POST", Operation.FavoriteTweet, variables)

    def unlike(self, tweet_id: int) -> dict:
        variables = {"tweet_id": tweet_id}
        return self.gql("POST", Operation.UnfavoriteTweet, variables)

    def bookmark(self, tweet_id: int) -> dict:
        variables = {"tweet_id": tweet_id}
        return self.gql("POST", Operation.CreateBookmark, variables)

    def unbookmark(self, tweet_id: int) -> dict:
        variables = {"tweet_id": tweet_id}
        return self.gql("POST", Operation.DeleteBookmark, variables)

    def create_list(self, name: str, description: str, private: bool) -> dict:
        variables = {
            "isPrivate": private,
            "name": name,
            "description": description,
        }
        return self.gql("POST", Operation.CreateList, variables)

    def update_list(
            self, list_id: int, name: str, description: str, private: bool
    ) -> dict:
        variables = {
            "listId": list_id,
            "isPrivate": private,
            "name": name,
            "description": description,
        }
        return self.gql("POST", Operation.UpdateList, variables)

    def update_pinned_lists(self, list_ids: list[int]) -> dict:
        return self.gql("POST", Operation.ListsPinMany, {"listIds": list_ids})

    def pin_list(self, list_id: int) -> dict:
        return self.gql("POST", Operation.ListPinOne, {"listId": list_id})

    def unpin_list(self, list_id: int) -> dict:
        return self.gql("POST", Operation.ListUnpinOne, {"listId": list_id})

    def add_list_member(self, list_id: int, user_id: int) -> dict:
        return self.gql(
            "POST", Operation.ListAddMember, {"listId": list_id, "userId": user_id}
        )

    def remove_list_member(self, list_id: int, user_id: int) -> dict:
        return self.gql(
            "POST", Operation.ListRemoveMember, {"listId": list_id, "userId": user_id}
        )

    def delete_list(self, list_id: int) -> dict:
        return self.gql("POST", Operation.DeleteList, {"listId": list_id})

    def update_list_banner(self, list_id: int, media: str) -> dict:
        media_id = self.upload_media(media)
        variables = {"listId": list_id, "mediaId": media_id}
        return self.gql("POST", Operation.EditListBanner, variables)

    def delete_list_banner(self, list_id: int) -> dict:
        return self.gql("POST", Operation.DeleteListBanner, {"listId": list_id})

    def follow_topic(self, topic_id: int) -> dict:
        return self.gql("POST", Operation.TopicFollow, {"topicId": str(topic_id)})

    def unfollow_topic(self, topic_id: int) -> dict:
        return self.gql("POST", Operation.TopicUnfollow, {"topicId": str(topic_id)})

    def pin(self, tweet_id: int) -> dict:
        return self.v1(
            "account/pin_tweet.json", {"tweet_mode": "extended", "id": tweet_id}
        )

    def unpin(self, tweet_id: int) -> dict:
        return self.v1(
            "account/unpin_tweet.json", {"tweet_mode": "extended", "id": tweet_id}
        )

    def get_user_id(self, username: str) -> int:
        headers = get_headers(self.session)
        headers["content-type"] = "application/x-www-form-urlencoded"

        r = self.session.get(
            f"{self.v1_api}/users/show.json",
            headers=headers,
            params={"screen_name": username},
        )

        json_data = self._verify_response(r)
        return json_data["id"]

    def get_user_info(self, username: str) -> dict:
        headers = get_headers(self.session)
        headers["content-type"] = "application/x-www-form-urlencoded"

        r = self.session.get(
            f"{self.v1_api}/users/show.json",
            headers=headers,
            params={"screen_name": username},
        )

        return self._verify_response(r)

    def follow(self, user_id: int) -> dict:
        settings = deepcopy(follow_settings)
        settings |= {"user_id": user_id}
        return self.v1("friendships/create.json", settings)

    def unfollow(self, user_id: int) -> dict:
        settings = deepcopy(follow_settings)
        settings |= {"user_id": user_id}
        return self.v1("friendships/destroy.json", settings)

    def mute(self, user_id: int) -> dict:
        return self.v1("mutes/users/create.json", {"user_id": user_id})

    def unmute(self, user_id: int) -> dict:
        return self.v1("mutes/users/destroy.json", {"user_id": user_id})

    def enable_follower_notifications(self, user_id: int) -> dict:
        settings = deepcopy(follower_notification_settings)
        settings |= {"id": user_id, "device": "true"}
        return self.v1("friendships/update.json", settings)

    def disable_follower_notifications(self, user_id: int) -> dict:
        settings = deepcopy(follower_notification_settings)
        settings |= {"id": user_id, "device": "false"}
        return self.v1("friendships/update.json", settings)

    def block(self, user_id: int) -> dict:
        return self.v1("blocks/create.json", {"user_id": user_id})

    def unblock(self, user_id: int) -> dict:
        return self.v1("blocks/destroy.json", {"user_id": user_id})

    def update_profile_image(self, media: str) -> dict:
        media_id = self.upload_media(media)
        _params = {"media_id": media_id}

        r = self.session.post(
            f"{self.v1_api}/account/update_profile_image.json",
            headers=get_headers(self.session),
            params=_params,
        )
        return self._verify_response(r)

    def update_profile_banner(self, media: str) -> dict:
        media_id = self.upload_media(media)
        _params = {"media_id": media_id}

        r = self.session.post(
            f"{self.v1_api}/account/update_profile_banner.json",
            headers=get_headers(self.session),
            params=_params,
        )
        return self._verify_response(r)

    def update_profile_info(self, _params: dict) -> dict:
        headers = get_headers(self.session)
        r = self.session.post(
            f"{self.v1_api}/account/update_profile.json", headers=headers, params=_params
        )

        return self._verify_response(r)

    def update_search_settings(self, settings: dict) -> dict:
        try:
            twid = int(self.session.cookies.get("twid").split("=")[-1].strip('"'))
            headers = get_headers(self.session)

            r = self.session.post(
                url=f"{self.v1_api}/strato/column/User/{twid}/search/searchSafety",
                headers=headers,
                json=settings,
            )
            return self._verify_response(r)

        except Exception as error:
            raise TwitterError({"error_message": f"Failed to update search settings: {error}"})

    def update_settings(self, settings: dict) -> dict:
        return self.v1("account/settings.json", settings)

    def update_username(self, username: str):
        return self.update_settings({"screen_name": username})

    def change_password(self, old: str, new: str) -> dict:
        _params = {
            "current_password": old,
            "password": new,
            "password_confirmation": new,
        }
        headers = get_headers(self.session)
        headers["content-type"] = "application/x-www-form-urlencoded"

        r = self.session.post(
            f"{self.v1_api}/account/change_password.json",
            headers=headers,
            data=_params,
            allow_redirects=True,
        )
        return self._verify_response(r)

    def home_timeline(self, limit: int) -> list[dict]:
        return self._paginate(
            "POST", Operation.HomeTimeline, Operation.default_variables, limit
        )

    def home_latest_timeline(self, limit: int) -> list[dict]:
        return self._paginate(
            "POST",
            Operation.HomeLatestTimeline,
            Operation.default_variables,
            limit,
        )

    def bookmarks(self, limit: int) -> list[dict]:
        return self._paginate("GET", Operation.Bookmarks, {}, limit)

    def _paginate(
            self, method: str, operation: tuple, variables: dict, limit: int
    ) -> list[dict]:
        initial_data = self.gql(method, operation, variables)
        res = [initial_data]
        ids = set(find_key(initial_data, "rest_id"))
        dups = 0
        DUP_LIMIT = 3

        cursor = get_cursor(initial_data)
        while (dups < DUP_LIMIT) and cursor:
            prev_len = len(ids)
            if prev_len >= limit:
                return res

            variables["cursor"] = cursor
            _data = self.gql(method, operation, variables)

            cursor = get_cursor(_data)
            ids |= set(find_key(_data, "rest_id"))

            if prev_len == len(ids):
                dups += 1

            res.append(_data)
        return res

    def upload_media(self, filename: str, is_dm: bool = False) -> int | None:

        def check_media(category: str, size: int) -> None:
            fmt = lambda x: f"{(x / 1e6):.2f} MB"
            msg = (
                lambda x: f"cannot upload {fmt(size)} {category}, max size is {fmt(x)}"
            )
            if category == "image" and size > MAX_IMAGE_SIZE:
                raise Exception(msg(MAX_IMAGE_SIZE))
            if category == "gif" and size > MAX_GIF_SIZE:
                raise Exception(msg(MAX_GIF_SIZE))
            if category == "video" and size > MAX_VIDEO_SIZE:
                raise Exception(msg(MAX_VIDEO_SIZE))

        url = "https://upload.twitter.com/i/media/upload.json"
        file = Path(filename)
        total_bytes = file.stat().st_size
        headers = get_headers(self.session)

        upload_type = "dm" if is_dm else "tweet"
        media_type = mimetypes.guess_type(file)[0]
        media_category = (
            f"{upload_type}_gif"
            if "gif" in media_type
            else f'{upload_type}_{media_type.split("/")[0]}'
        )

        check_media(media_category, total_bytes)

        _params = {
            "command": "INIT",
            "media_type": media_type,
            "total_bytes": total_bytes,
            "media_category": media_category,
        }
        r = self.session.post(
            url=url, headers=headers, params=_params, allow_redirects=True
        )

        _data = self._verify_response(r)
        media_id = _data["media_id"]

        desc = f"uploading: {file.name}"
        with tqdm(
                total=total_bytes, desc=desc, unit="B", unit_scale=True, unit_divisor=1024
        ) as pbar:
            with open(file, "rb") as fp:
                i = 0
                while chunk := fp.read(UPLOAD_CHUNK_SIZE):
                    _params = {
                        "command": "APPEND",
                        "media_id": media_id,
                        "segment_index": i,
                    }
                    try:
                        pad = bytes(
                            "".join(random.choices(ascii_letters, k=16)),
                            encoding="utf-8",
                        )
                        _data = b"".join(
                            [
                                b"------WebKitFormBoundary",
                                pad,
                                b'\r\nContent-Disposition: form-data; name="media"; filename="blob"',
                                b"\r\nContent-Type: application/octet-stream",
                                b"\r\n\r\n",
                                chunk,
                                b"\r\n------WebKitFormBoundary",
                                pad,
                                b"--\r\n",
                            ]
                        )
                        _headers = {
                            b"content-type": b"multipart/form-data; boundary=----WebKitFormBoundary"
                                             + pad
                        }
                        self.session.post(
                            url=url,
                            headers=headers | _headers,
                            params=_params,
                            content=_data,
                            allow_redirects=True,
                        )

                    except:
                        try:
                            files = {"media": chunk}
                            self.session.post(
                                url=url, headers=headers, params=_params, files=files
                            )
                        except:
                            return

                    i += 1
                    pbar.update(fp.tell() - pbar.n)

        _params = {"command": "FINALIZE", "media_id": media_id, "allow_async": "true"}
        if is_dm:
            _params |= {"original_md5": hashlib.md5(file.read_bytes()).hexdigest()}

        r = self.session.post(
            url=url, headers=headers, params=_params, allow_redirects=True
        )
        _data = self._verify_response(r)

        processing_info = _data.get("processing_info")
        while processing_info:
            state = processing_info["state"]
            if error := processing_info.get("error"):
                return
            if state == MEDIA_UPLOAD_SUCCEED:
                break
            if state == MEDIA_UPLOAD_FAIL:
                return
            check_after_secs = processing_info.get(
                "check_after_secs", random.randint(1, 5)
            )

            time.sleep(check_after_secs)
            _params = {"command": "STATUS", "media_id": media_id}

            r = self.session.get(
                url=url, headers=headers, params=_params, allow_redirects=True
            )
            _data = self._verify_response(r)
            processing_info = _data.get("processing_info")

        return media_id

    def dm_inbox(self) -> dict:
        r = self.session.get(
            f"{self.v1_api}/dm/inbox_initial_state.json",
            headers=get_headers(self.session),
            params=dm_params,
        )
        return self._verify_response(r)

    def dm_delete(self, conversation_id: str = None, message_id: str = None) -> dict:
        if not all((conversation_id, message_id)):
            raise IncorrectData("Provide either conversation_id or message_id")

        self.session.headers.update(headers=get_headers(self.session))
        results = {"conversation": None, "message": None}
        if conversation_id:
            results["conversation"] = self.session.post(
                f"{self.v1_api}/dm/conversation/{conversation_id}/delete.json",
            )  # not json response

        if message_id:
            # delete single message
            _id, op = Operation.DMMessageDeleteMutation
            results["message"] = self.session.post(
                f"{self.gql_api}/{_id}/{op}",
                json={"queryId": _id, "variables": {"messageId": message_id}},
            )

        return results

    def dm_search(self, query: str) -> dict:
        """
        Search DMs by keyword

        @param query: search term
        @return: search results as dict
        """

        def get(_cursor=None):
            if _cursor:
                params_["variables"]["cursor"] = _cursor.pop()

            _id, op = Operation.DmAllSearchSlice
            r = self.session.get(
                f"{self.gql_api}/{_id}/{op}",
                params=build_params(params_),
            )

            _data = r.json()
            _cursor = find_key(_data, "next_cursor")
            return _data, _cursor

        self.session.headers.update(headers=get_headers(self.session))
        variables = deepcopy(Operation.default_variables)
        variables["count"] = 50  # strict limit, errors thrown if exceeded
        variables["query"] = query

        params_ = {"variables": variables, "features": Operation.default_features}
        res, cursor = get()
        data_ = [res]

        while cursor:
            res, cursor = get(cursor)
            data_.append(res)

        return {"query": query, "data": data_}

    def scheduled_tweets(self, ascending: bool = True) -> dict:
        variables = {"ascending": ascending}
        return self.gql("GET", Operation.FetchScheduledTweets, variables)

    def delete_scheduled_tweet(self, tweet_id: int) -> dict:
        variables = {"scheduled_tweet_id": tweet_id}
        return self.gql("POST", Operation.DeleteScheduledTweet, variables)

    def clear_scheduled_tweets(self) -> None:
        user_id = int(re.findall('"u=(\d+)"', self.session.cookies.get("twid"))[0])
        drafts = self.gql("GET", Operation.FetchScheduledTweets, {"ascending": True})
        for _id in set(find_key(drafts, "rest_id")):
            if _id != user_id:
                self.gql(
                    "POST", Operation.DeleteScheduledTweet, {"scheduled_tweet_id": _id}
                )

    def draft_tweets(self, ascending: bool = True) -> dict:
        variables = {"ascending": ascending}
        return self.gql("GET", Operation.FetchDraftTweets, variables)

    def delete_draft_tweet(self, tweet_id: int) -> dict:
        variables = {"draft_tweet_id": tweet_id}
        return self.gql("POST", Operation.DeleteDraftTweet, variables)

    def clear_draft_tweets(self) -> None:
        user_id = int(re.findall('"u=(\d+)"', self.session.cookies.get("twid"))[0])
        drafts = self.gql("GET", Operation.FetchDraftTweets, {"ascending": True})
        for _id in set(find_key(drafts, "rest_id")):
            if _id != user_id:
                self.gql("POST", Operation.DeleteDraftTweet, {"draft_tweet_id": _id})

    def notifications(self, _params: dict = None) -> dict:
        r = self.session.get(
            f"{self.v2_api}/notifications/all.json",
            headers=get_headers(self.session),
            params=_params or live_notification_params,
        )
        return self._verify_response(r)

    def recommendations(self, _params: dict = None) -> dict:
        r = self.session.get(
            f"{self.v1_api}/users/recommendations.json",
            headers=get_headers(self.session),
            params=_params or recommendations_params,
        )
        return self._verify_response(r)

    def fleetline(self, _params: dict = None) -> dict:
        r = self.session.get(
            "https://twitter.com/i/api/fleets/v1/fleetline",
            headers=get_headers(self.session),
            params=_params or {},
        )
        return self._verify_response(r)

    def save_cookies(self, fname: str):
        """Save cookies to file"""
        cookies = self.cookies
        Path(f'{fname}.cookies').write_bytes(
            orjson.dumps(dict(cookies))
        )
