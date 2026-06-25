#!/usr/bin/env python3
"""
KillChainAgent — Orchestrateur agentic de kill chain ATT&CK.
FastAPI backend.
"""

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import Request
import uvicorn

from models import MissionRequest, MissionResponse
from agents.supervisor import SupervisorAgent

app = FastAPI(title="KillChainAgent", version="0.1.0")

templates = Jinja2Templates(directory="../frontend/templates")

missions_store = {}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.post("/missions", response_model=MissionResponse)
async def create_mission(mission: MissionRequest):
    supervisor = SupervisorAgent(target=mission.target)
    result = supervisor.plan()
    missions_store[result["id"]] = result
    return MissionResponse(
        id=result["id"],
        target=mission.target,
        status="planned",
        killchain=result["killchain"]
    )


@app.get("/missions")
async def list_missions():
    return {"missions": list(missions_store.values())}


@app.get("/missions/{mission_id}")
async def get_mission(mission_id: str, request: Request):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse("mission.html", {
            "request": request,
            "mission_id": mission_id,
        })
    return missions_store.get(mission_id, {"error": "Mission not found"})


@app.post("/missions/{mission_id}/execute")
async def execute_mission(mission_id: str):
    mission = missions_store.get(mission_id)
    if not mission:
        return {"error": "Mission not found"}

    supervisor = SupervisorAgent(target=mission["target"])
    supervisor.mission_id = mission_id

    results = supervisor.execute()

    mission["killchain"] = results
    mission["status"] = "completed"
    return {
        "mission_id": mission_id,
        "status": "completed",
        "steps": len(results),
        "killchain": results,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "agents": ["supervisor", "recon", "exploit", "privesc", "persist", "report"]}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
