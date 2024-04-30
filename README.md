# Twitter API

## Installation

```bash 
pip install Jam-Twitter-API
```

## Usage

```python
from account import TwitterAccount
from errors import *

# Create a TwitterAccount object
# Set up a session using auth_token or cookies (it will auto create needed headers and cookies)
try:
    account = TwitterAccount.run(
        auth_token="0idfidfgdfgidfgijodfgjoidfgijo43",
        proxy="http://user:pass@host:port",
        setup_session=True,
    )

    account = TwitterAccount.run(
        cookies={"auth_token": "0idfidfgdfgidfgijodfgjoidfgijo43", "ct0": "0idfidfgdfgidfgijodfgjoidfgijo43"},
        proxy="http://user:pass@host:port",
        setup_session=True,
    )

except TwitterAccountSuspended as error:
    # Raise when account is suspended
    print(f"Account is suspended: {error}")

except TwitterError as error:
    # Raise when Twitter error occurs
    print(f"Twitter error occurred: {error.error_message} | {error.error_code}")

except IncorrectData as error:
    # Raise when validation error occurs
    print(f"Incorrect data provided: {error}")

except RateLimitError as error:
    # Raise when rate limit exceeded
    print(f"Rate limit exceeded: {error}")

# A small part of the available methods:
user_tweets = account.user_last_tweets("elonmusk")
user_followers = account.user_followers("elonmusk")
user_following = account.user_followings("elonmusk")

user_info = account.get_user_info("elonmusk")
user_id = account.get_user_id("elonmusk")
follow = account.follow(1000)
unfollow = account.unfollow(1000)

bind_account_to_site_v1 = account.bind_account_v1("url")
bind_account_to_site_v2 = account.bind_account_v2({
    "code_challenge": "test",
    "code_challenge_method": "plain",
    "client_id": "enpfUjhndkdrdHhld29adfg6eGM6MTpjaQ",
    "redirect_uri": "https://www.test.io",
    "response_type": "code",
    "scope": "tweet.read users.read follows.read offline.access",
    "state": "test",
})

tweet_replies = account.tweet_replies(1000000000)
tweet_retweets = account.tweet_retweeters(1000000000)
tweet_likes = account.tweet_likes(1000000000)

tweet = account.tweet("hello world")
untweet = account.untweet(1000000000)

quote = account.quote("hello world", 10000)
retweet = account.retweet(1000000000)

reply = account.reply("hello world", 1000000000)
like = account.like(1000000000)
unlike = account.unlike(1000000000)

update_image = account.update_profile_image("path/to/image.jpg")
update_banner = account.update_profile_banner("path/to/image.jpg")
update_profile_info = account.update_profile_info({"location": "San Francisco"})
```
