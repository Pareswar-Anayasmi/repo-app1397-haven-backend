ARG WORKDIR="/app"
ARG PYTHON_VERSION="3.12.8"
ARG LINUX_CODE_NAME="bookworm"

FROM python:${PYTHON_VERSION}-${LINUX_CODE_NAME} AS builder
ARG WORKDIR
WORKDIR ${WORKDIR}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

RUN pip install poetry==1.8.5

COPY pyproject.toml poetry.lock ./

RUN --mount=type=cache,target=/tmp/poetry_cache poetry install --only main --no-root --no-directory


FROM python:${PYTHON_VERSION}-slim-${LINUX_CODE_NAME} as runtime


ARG WORKDIR

WORKDIR ${WORKDIR}

ENV VIRTUAL_ENV=${WORKDIR}/.venv \
    PATH="${WORKDIR}/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

RUN adduser --disabled-password --gecos "" --home ${WORKDIR} -u 1000 appuser

RUN chown -R appuser:appuser ${WORKDIR}

USER 1000

COPY ./aiexpert ./aiexpert

ENTRYPOINT ["uvicorn", "aiexpert.main:app",  "--host", "0.0.0.0"]