from fastapi import FastAPI

app = FastAPI(
    title="AI-Powered Autonomous Threat Hunting Platform",
    version="0.1.0",
    description="MSc project prototype for AI-assisted SOC threat hunting."
)


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "project": "AI-Powered Autonomous Threat Hunting Platform"
    }
