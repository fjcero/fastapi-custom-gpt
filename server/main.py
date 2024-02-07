from typing import Annotated, Any
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import (Body, Depends, FastAPI, Form, HTTPException, Request, Security, requests,
                     status)
from fastapi.responses import RedirectResponse
from fastapi.security import (HTTPBearer, OAuth2AuthorizationCodeBearer,
                              OAuth2PasswordBearer, OAuth2PasswordRequestForm)
from fastapi_auth0 import Auth0, Auth0User
import httpx
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="secret-key")

settings = get_settings()


auth = Auth0(
    domain=settings.auth0_domain,
    api_audience=settings.auth0_api_audience,
    scopes={"read:all": "write:all"},
)

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

# client = OAuth2Session(
#     settings.auth0_client_id,
#     settings.auth0_client_secret,
#     scope="read:all write:all",
# )

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"https://{settings.auth0_domain}/authorize",
    tokenUrl=f"https://{settings.auth0_domain}/oauth/token",
    refreshUrl=f"https://{settings.auth0_domain}/oauth/token",
    scopes={
        "openid": "auth with openid",
        "email": "Access to the mail",
        "profile": "access user information",
        "read:all": "Read all contents",
        "write:all": "Modify all contents",
    },
)


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
    state = request.query_params.get('state')
    scope = "read:all openid email profile read:all write:all offline_access"
    redirect_uri = "https://eagle-major-notably.ngrok-free.app/authorize/callback"

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


@app.get("/authorize/callback")
async def authorize_callback(request: Request):
    openai_redirect_uri = "https://chat.openai.com/aip/g-471ccbf64bbc25808e27b5bd1c897e7c529097a3/oauth/callback"
    code = request.query_params.get('code')
    state = request.query_params.get('state')
    # Redirect to OpenAI's callback URL with code and state

    params = {"code": code, "state": state}

    redirect_uri = request.query_params.get('redirect_uri')

    print(f"Intermediate redirect with params = {params} and redirect = {redirect_uri}")

    # return RedirectResponse(f"{openai_redirect_uri}?{urlencode(params)}")
    return RedirectResponse(f"/token?code={code}&state={state}")


@app.get("/token")
async def token(request: Request):
    # print("TOKEN", request.query_params, request.headers, payload)
    # return {
    #     "access_token": "example_token",
    #     "token_type": "bearer",
    #     "refresh_token": "example_token",
    #     "expires_in": 59,
    # }
    redirect_uri = "https://eagle-major-notably.ngrok-free.app/authorize/callback"

    try:
        # request_data = await request.form()
        params = request.query_params
        code = params.get('code')

        print(f"token endpoint: request data = {params}")

        token_url = f"https://{settings.auth0_domain}/oauth/token"
        data = {
            "code": code,
            "client_id": settings.auth0_client_id,
            "client_secret": settings.auth0_client_secret,
            "redirect_uri": redirect_uri,  # Use the same redirect_uri as in /authorize
            "grant_type": "authorization_code",
        }

        response = httpx.post(token_url, data=data)

        # Check if the response from Google is successful
        # if response.status_code != 200:
        #     print("Error during token exchange with Google:", response.status_code, response.text)
        #     raise HTTPException(status_code=500, detail="Token exchange failed")

        token_response = response.json()
        print(token_response)

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


async def authtest(request: Request):
    print("AUTHORIZE/CALLBACK", request.query_params)
    # code=4GYQoHNv4Xr79Iw_7fxMGPHHIlq9iIvUJEX1PTmBWk_7E&state=123
    token = get_token(
        code=request.query_params['code'],
        # redirect_uri="https://chat.openai.com/aip/g-471ccbf64bbc25808e27b5bd1c897e7c529097a3/oauth/callback"
    )

    # try:
    #     access_token = await oauth.auth0.authorize_access_token(request)
    # except OAuthError as error:
    #     print("ERROR", error)
    #     return RedirectResponse(url='/')

    # user_data = await oauth.auth0.parse_id_token(access_token)
    # payload = jwt.decode(token, settings., algorithms=[ALGORITHM])
    print(token)

    # request.session['user'] = {
    #     "name": access_token['userinfo']['name'],
    #     "email": access_token['userinfo']['email'],
    # }
    # request.session['auth'] = access_token['access_token']
    # request.session['raw_auth'] = access_token

    # print(request.session)
    return {
        "access_token": "example_token",
        "token_type": "bearer",
        "refresh_token": "example_token",
        "expires_in": 59,
    }

    # return RedirectResponse(url=f'https://chat.openai.com/aip/g-471ccbf64bbc25808e27b5bd1c897e7c529097a3/oauth/callback?state={request.query_params.get('state')}')


@app.get('/secure')
# def secure_endpoint(user=Security(oauth2_scheme)):
def secure_endpoint(user=Security(get_user)):
    return {"message": "This is a secure endpoint.", "user": user}


# @app.post("/token")
# async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(
#             status_code=400,
#             detail="Incorrect username or password",
#         )
#     user = UserInDB(**user_dict)
#     hashed_password = fake_hash_password(form_data.password)
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(
#             status_code=400,
#             detail="Incorrect username or password"
#         )

#     return {"access_token": user.username, "token_type": "bearer"}


# @app.get("/secure", dependencies=[Depends(auth.implicit_scheme)])
# def get_secure(user: Auth0User = Security(auth.get_user, scopes=["read:all"])):
#     return {"message": f"{user}"}


@app.get("/query")
def query(request: Request, payload: Any = Body(None)):
    print("QUERY", request.query_params, request.headers, payload)
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


async def get_authorize_url(
    response_type: str,
    redirect_uri: str,
    scope: str,
    state: str,
):
    query_string = urlencode(dict(
        audience=settings.auth0_api_audience,
        scope=scope,
        response_type=response_type,
        client_id=settings.auth0_client_id,
        redirect_uri=redirect_uri,
        state=state,
    ))

    url = f"https://{settings.auth0_domain}/authorize?{query_string}"

    return url


def get_token(code: str, redirect_uri: str | None = None):
    url = f"https://{settings.auth0_domain}/oauth/token"

    r = httpx.post(url=url, data=dict(
        grant_type="authorization_code",
        client_id=settings.auth0_client_id,
        client_secret=settings.auth0_client_secret,
        code=code,
        redirect_uri="https://eagle-major-notably.ngrok-free.app/authorize/callback",
    ))
    print(r.json())
