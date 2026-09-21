FROM python:3.12-slim

# uv for dependency management.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install locked dependencies first (better layer caching).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# App source.
COPY src ./src
COPY gunicorn.conf.py ./
RUN uv sync --frozen --no-dev

# npcapextract placement is deferred (SPEC v2 design §8.3); it is expected on
# PATH at runtime (installed here or provided via the recorder integration).

# Socket dir shared with Caddy.
RUN mkdir -p /run/api

ENV PATH="/app/.venv/bin:${PATH}"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "sycope_recorder.main:app"]
