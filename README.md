# Prerequisite

1. Python 3.12 or above
2. [Poetry](https://python-poetry.org/docs/#installation)
3. Azure Cli
4. [PostgreSQL](https://www.postgresql.org/download/) - it is recommended to run a local PostgreSQL server with [disable passwordless](https://serverfault.com/questions/1083133/pg-hba-conf-psql-local-login-without-password)
5. Azure OpenAI API

# Run the backend locally

1. Install Python dependencies

```
poetry install
```

2. Copy .env.sample to .env

```
cp .env.sample .env
```

3. Update the .env file. Refer to  for the details.


4. Run the Backend app

```
poetry shell
uvicorn aiexpert.main:app --reload
```

Note that if you got error that some module cannot be found, it may be because of your existing ```uvicorn```

To solve the problem, you can explicitly specify the path of ```uvicorn``` under the virtual environment created by poetry. For example,

```
> poetry env info

Virtualenv
Python:         3.12.7
Implementation: CPython
Path:           /Users/leo.yung/Library/Caches/pypoetry/virtualenvs/xxxxx-Bv9AeWMz-py3.12
Executable:     /Users/leo.yung/Library/Caches/pypoetry/virtualenvs/xxxxx-Bv9AeWMz-py3.12/bin/python
Valid:          True

> /Users/leo.yung/Library/Caches/pypoetry/virtualenvs/xxxxx-Bv9AeWMz-py3.12/bin/uvicorn aiexpert.main:app --reload
```

You can specify the port number using ```--port <<port_number>>```, for example,

```
uvicorn aiexpert.main:app --reload --port 8000
```
