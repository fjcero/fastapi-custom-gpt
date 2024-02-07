# FastAPI + OAuth 2.0 + GPT custom action

- [ ] Setup server (`server`)
- [ ] Use Supabase as DB
- [ ] Setup frontend (`web`)
- [ ] OAuth 2.0 Server
- [ ] Deploy to AWS Lambda (`mangum`)

## Requirements

```sh
# brew install poetry
poetry install
```

## Dev 

```sh
poetry run dev
```

## Docs

- OpenAPI: locahost:8000/docs
- Redoc: locahost:8000/redoc


## Regenerate requirements.txt
```
poetry export --without-hashes --format=requirements.txt > requirements.txt
```