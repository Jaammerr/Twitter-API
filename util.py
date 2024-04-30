import random
import string
import time

import curl_cffi.requests
import orjson

from logging import Logger
from curl_cffi.requests import Response, Session

from .constants import GREEN, MAGENTA, RED, RESET
from .errors import TwitterError


def build_params(params: dict) -> dict:
    return {k: orjson.dumps(v).decode() for k, v in params.items()}


def get_cursor(data: list | dict) -> str:
    entries = find_key(data, "entries")
    if entries:
        for entry in entries.pop():
            entry_id = entry.get("entryId", "")
            if ("cursor-bottom" in entry_id) or ("cursor-showmorethreads" in entry_id):
                content = entry["content"]
                if itemContent := content.get("itemContent"):
                    return itemContent["value"]  # v2 cursor
                return content["value"]  # v1 cursor


def get_headers(session: Session, **kwargs) -> dict:
    """
    Get the headers required for authenticated requests
    """
    cookies = session.cookies
    headers = kwargs | {
        "authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
        # "cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
        "referer": "https://twitter.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "x-csrf-token": cookies.get("ct0", ""),
        # "x-guest-token": cookies.get("guest_token", ""),
        "x-twitter-auth-type": "OAuth2Session" if cookies.get("auth_token") else "",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
    }
    return dict(sorted({k.lower(): v for k, v in headers.items()}.items()))


def find_key(obj: any, key: str) -> list:
    """
    Find all values of a given key within a nested dict or list of dicts

    Most data of interest is nested, and sometimes defined by different schemas.
    It is not worth our time to enumerate all absolute paths to a given key, then update
    the paths in our parsing functions every time Twitter changes their API.
    Instead, we recursively search for the key here, then run post-processing functions on the results.

    @param obj: dictionary or list of dictionaries
    @param key: key to search for
    @return: list of values
    """

    def helper(obj: any, key: str, L: list) -> list:
        if not obj:
            return L

        if isinstance(obj, list):
            for e in obj:
                L.extend(helper(e, key, []))
            return L

        if isinstance(obj, dict) and obj.get(key):
            L.append(obj[key])

        if isinstance(obj, dict) and obj:
            for k in obj:
                L.extend(helper(obj[k], key, []))
        return L

    return helper(obj, key, [])


def log(logger: Logger, level: int, r: Response):
    def stat(r, txt, data):
        if level >= 1:
            logger.debug(f"{r.url.path}")
        if level >= 2:
            logger.debug(f"{r.url}")
        if level >= 3:
            logger.debug(f"{txt}")
        if level >= 4:
            logger.debug(f"{data}")

        try:
            limits = {k: v for k, v in r.headers.items() if "x-rate-limit" in k}
            current_time = int(time.time())
            wait = int(r.headers.get("x-rate-limit-reset", current_time)) - current_time
            remaining = limits.get("x-rate-limit-remaining")
            limit = limits.get("x-rate-limit-limit")
            logger.debug(f"remaining: {MAGENTA}{remaining}/{limit}{RESET} requests")
            logger.debug(f"reset:     {MAGENTA}{(wait / 60):.2f}{RESET} minutes")
        except Exception as e:
            logger.error(f"Rate limit info unavailable: {e}")

    try:
        status = r.status_code
        (
            txt,
            data,
        ) = (
            r.text,
            r.json(),
        )
        if "json" in r.headers.get("content-type", ""):
            if data.get("errors") and not find_key(data, "instructions"):
                logger.error(f"[{RED}error{RESET}] {status} {data}")
            else:
                logger.debug(fmt_status(status))
                stat(r, txt, data)
        else:
            logger.debug(fmt_status(status))
            stat(r, txt, {})
    except Exception as e:
        logger.error(f"Failed to log: {e}")


def fmt_status(status: int) -> str:
    color = None
    if 200 <= status < 300:
        color = GREEN
    elif 300 <= status < 400:
        color = MAGENTA
    elif 400 <= status < 600:
        color = RED
    return f"[{color}{status}{RESET}]"



def get_random_string(len_: int) -> str:
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(len_)
    )


def get_random_number(len_: int) -> str:
    return "".join(random.choice(string.digits) for _ in range(len_))


def generate_random_string() -> str:
    return "".join([random.choice(string.ascii_letters + "-_") for _ in range(352)])


def raise_for_status(response: Response):
    http_error_msg = ""
    if 400 <= response.status_code < 500:
        http_error_msg = f"{response.status_code} Client Error for url {response.url}"

    elif 500 <= response.status_code < 600:
        http_error_msg = f"{response.status_code} Server Error for url: {response.url}"

    if http_error_msg:
        raise TwitterError({"error_message": http_error_msg})
