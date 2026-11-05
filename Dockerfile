FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    groupadd -g 10001 wasl && useradd -u 10001 -g wasl --create-home wasl && \
    mkdir -p /app/uploads && chown -R wasl:wasl /app/uploads
COPY --chown=wasl:wasl app/ /app/app/
COPY --chown=wasl:wasl scripts/ /app/scripts/
USER wasl
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]
