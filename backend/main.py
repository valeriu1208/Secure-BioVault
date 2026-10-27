from fastapi import FastAPI

app = FastAPI(title="Secure BioVault API")


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Secure BioVault API is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
