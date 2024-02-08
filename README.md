# FastAPI + OAuth 2.0 + GPT custom action

- [x] Setup FastAPI (`server`)
- [x] Setup Auth0 
- [x] Integrate with Auth0 as OAuth 2.0 Server
- [x] Authenticate GPT using OAuth `authorization_code` flow
- [x] Verify JWT to process `access_token`
- [x] Create a protected endpoint for talking with ChatGPT
- [ ] Identify users for endpoint usage and allow access to different resources
- [ ] Integrate agent with Vector DB
- [ ] Deploy to AWS Lambda (`mangum`)
- [ ] Setup SolidJS (`web`)
- [ ] Integrate with Supabase as DB?

![gpt-custom-action-demo](/public/gpt-custom-action-demo.jpg "How custom actions authenticate")

## Requirements

```sh
# brew install poetry
poetry install
```

## Dev Env

```sh
poetry run dev
```

## Docs

- [OpenAPI](http://locahost:8000/docs)
- [Redoc](http://locahost:8000/redoc)


## Deploy

### Regenerate requirements.txt for deployment
```
poetry export --without-hashes --format=requirements.txt > requirements.txt
```