import json
import sys
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from starlette.middleware.sessions import SessionMiddleware

from server.config import get_settings
from server.verify_token import VerifyToken

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     app.requests_client = httpx.AsyncClient()
#     yield
#     await app.requests_client.aclose()


# app = FastAPI(lifespan=lifespan)
app = FastAPI()
auth = VerifyToken()
app.add_middleware(SessionMiddleware, secret_key="secret-key")

settings = get_settings()


oauth = OAuth()
oauth.register(
    name="auth0",
    client_id=settings.auth0_client_id,
    client_secret=settings.auth0_client_secret,
    client_kwargs={
        "scope": "openid profile email offline_access read:all write:all"
    },

    authorize_url=f"https://{settings.auth0_domain}/authorize",
    authorize_params={
        "audience": settings.auth0_api_audience,
    },
    # api_base_url=f'https://{settings.auth0_domain}',
    # access_token_url=f"https://{settings.auth0_domain}/oauth/token",

    server_metadata_url=(
        f'https://{settings.auth0_domain}/.well-known/openid-configuration'
    ),
    # jwks_uri=f'https://{settings.auth0_domain}/.well-known/jwks.json',
)

token_auth_scheme = HTTPBearer()

# client = OAuth2Session(
#     settings.auth0_client_id,
#     settings.auth0_client_secret,
#     scope="read:all write:all",
# )

# oauth2_scheme = OAuth2AuthorizationCodeBearer(tokenUrl="token", authorizationUrl="authorize")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# oauth2_scheme = OAuth2AuthorizationCodeBearer(
#     authorizationUrl=f"https://{settings.auth0_domain}/authorize",
#     tokenUrl=f"https://{settings.auth0_domain}/oauth/token",
#     refreshUrl=f"https://{settings.auth0_domain}/oauth/token",
#     scopes={
#         "openid": "auth with openid",
#         "email": "Access to the mail",
#         "profile": "access user information",
#         "read:all": "Read all contents",
#         "write:all": "Modify all contents",
#     },
# )


# origins = ["*"]
# app.add_middleware(
#     CORS,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


async def get_user(request: Request):
    user = request.session.get('user')
    if user:
        return user
    raise HTTPException(status_code=401, detail="Not authenticated")


@app.get("/")
def root(request: Request):
    user = request.session.get('user')
    if user:
        return {
            "Hello": "World",
            "user": user,
            "auth": request.session.get('auth'),
            "raw_auth": request.session.get('raw_auth')
        }
    else:
        return {"Hello": "World"}


# @app.get("/authorize")
# async def logintest(request: Request):
#     # print("AUTHORIZE", request.query_params, request.headers)
#     # redirect_uri = "http://127.0.0.1:8000/authorize/callback"
#     # redirect_uri = "https://eagle-major-notably.ngrok-free.app/authorize/callback"
#     auth_url = await get_authorize_url(
#         response_type="code",
#         redirect_uri=redirect_uri,
#         scope="read:all write:all",  # openid profile email offline_access
#         state=request.query_params.get('state'),
#     )
#     print(auth_url)
#     # return await oauth.auth0.authorize_redirect(request, redirect_uri)
#     return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@app.get("/authorize")
async def authorize(request: Request):
    print("AUTHORIZE", request.query_params)
    # openai_redirect_uri = request.query_params.get('redirect_uri')
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    scope = "read:all write:all openid email profile offline_access"
    redirect_uri = "https://eagle-major-notably.ngrok-free.app/authorize"

    if code and state:
        callback_params = {"code": code, "state": state}
        openai_redirect_uri = "https://chat.openai.com/aip/g-248e136e506eb5cfd9b5bf6be172b6eda68557b4/oauth/callback"
        callback_url = f"{openai_redirect_uri}?{urlencode(callback_params)}"
        print("callback", callback_url)

        # async with httpx.AsyncClient() as client:
        #     res = await client.post(
        #         "https://eagle-major-notably.ngrok-free.app/token",
        #         data={"code": code, "state": state},
        #         # headers={"Content-Type": "application/json"},
        #     )

        #     return json.loads(res.text)

        return RedirectResponse(callback_url)
    else:
        # Construct the OAuth URL with the state parameter and an auth/callback url
        params = {
            "response_type": "code",
            "client_id": settings.auth0_client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "audience": settings.auth0_api_audience,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        authorization_url = f"https://{settings.auth0_domain}/authorize"
        return RedirectResponse(f"{authorization_url}?{urlencode(params)}")


@app.post("/token")
async def token(request: Request, payload: Any = Body(None)):
    redirect_uri = "https://eagle-major-notably.ngrok-free.app/authorize"
    # print(request.url_for("/token"), request.url_for("/token"))

    try:
        params = await request.form()
        print("TOKEN", request.query_params, request.headers, payload, params)
        code = params.get('code')

        print(f"token endpoint: request data = {params}")

        token_url = f"https://{settings.auth0_domain}/oauth/token"
        data = {
            "code": code,
            "client_id": settings.auth0_client_id,
            "client_secret": settings.auth0_client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            res = await client.post(
                token_url,
                data=data,
            )

            token_response = json.loads(res.text)

        # Check if the response from Google is successful
        # if response.status_code != 200:
        #     print("Error during token exchange with Google:", response.status_code, response.text)
        #     raise HTTPException(status_code=500, detail="Token exchange failed")

        # token_response = {}
        # response.json()
        # print(token_response)

        # Check if the necessary tokens are present in the response
        # if "access_token" not in token_response or "refresh_token" not in token_response:
        #     print("Missing tokens in Google's response:", token_response)
        #     raise HTTPException(status_code=500, detail="Missing tokens in response")

        # Return the formatted token response
        return {
            "access_token": token_response.get("access_token"),
            "token_type": "bearer",
            "refresh_token": token_response.get("refresh_token"),
            "expires_in": token_response.get("expires_in")
        }

    # except RequestException as e:
    #     print("Request exception during token exchange:", e, file=sys.stderr)
    #     raise HTTPException(status_code=500, detail="Token exchange request failed")

    except Exception as e:
        print("Unexpected error in /token endpoint:", e, file=sys.stderr)
        raise HTTPException(status_code=500, detail="Unexpected error in token exchange")


@app.get('/secure')
def secure_endpoint(auth_result: str = Security(auth.verify, scopes=["read:all"])):
    return {"message": "This is a secure endpoint.", "auth": auth_result}


@app.get("/query")
def query(request: Request, token: str = Depends(token_auth_scheme)):
    print("QUERY", token.credentials)
    return {
        "location": {"city": "New York", "state": "NY", "country": "USA"},
        "current_weather": {
            "temperature": {"fahrenheit": 75, "celsius": 24},
            "condition": "Partly Cloudy",
            "humidity": 60,
            "wind": {"speed_mph": 5, "direction": "NE"},
            "precipitation": "0%",
            "visibility_miles": 10,
            "forecast": [
                {
                    "day": "Today",
                    "high": {"fahrenheit": 75, "celsius": 24},
                    "low": {"fahrenheit": 55, "celsius": 13},
                    "condition": "Increasing cloudiness with a chance "
                                 "of rain by evening",
                },
                {
                    "day": "Tomorrow",
                    "high": {"fahrenheit": 70, "celsius": 21},
                    "low": {"fahrenheit": 50, "celsius": 10},
                    "condition": "Rainy",
                },
            ],
        },
    }
