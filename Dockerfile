FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir \
    "fastapi>=0.116,<1" "uvicorn[standard]>=0.35,<1" \
    "pydantic-settings>=2.10,<3" "PyJWT>=2.10,<3" \
    "pwdlib[argon2]>=0.2,<1" "python-multipart>=0.0.20,<1"

COPY app ./app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
