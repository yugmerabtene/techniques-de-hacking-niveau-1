#!/usr/bin/env python3
"""
KillChainAgent — Orchestrateur agentic de kill chain ATT&CK.
FastAPI backend.

Ce module est le point d'entrée principal de l'API REST.
Il définit les routes HTTP (endpoints) pour l'interface web (dashboard),
la gestion des missions (création, liste, détail, exécution)
et le monitoring (health check).

Routes :
    GET  /                              — Tableau de bord HTML
    POST /missions                      — Créer une nouvelle mission
    GET  /missions                      — Lister toutes les missions
    GET  /missions/{mission_id}         — Détail d'une mission (HTML ou JSON)
    POST /missions/{mission_id}/execute — Exécuter une mission planifiée
    GET  /health                        — Vérifier l'état de l'API
"""

import os

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import Request
import uvicorn

from models import MissionRequest, MissionResponse
from agents.supervisor import SupervisorAgent

# --- Initialisation de l'application et des templates ---

app = FastAPI(title="KillChainAgent", version="0.1.0")

# Moteur de templates Jinja2 pointant vers le dossier frontend
# Chemin relatif au fichier courant pour supporter les imports depuis les tests
_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "templates")
templates = Jinja2Templates(directory=_TEMPLATES_DIR)

# Stockage en mémoire des missions (clé = mission_id, valeur = dict mission)
missions_store = {}


# ---------------------------------------------------------------------------
# Routes de l'interface utilisateur
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    GET / — Tableau de bord principal.

    Retourne la page HTML du dashboard permettant de visualiser
    et gérer l'ensemble des missions.

    Args:
        request (Request): Requête HTTP entrante (injectée par FastAPI).

    Returns:
        TemplateResponse: Rendu du template Jinja2 `dashboard.html`.
    """
    return templates.TemplateResponse(request, "dashboard.html")


# ---------------------------------------------------------------------------
# Routes de gestion des missions
# ---------------------------------------------------------------------------

@app.post("/missions", response_model=MissionResponse)
async def create_mission(mission: MissionRequest):
    """
    POST /missions — Créer une nouvelle mission.

    Reçoit une cible, instancie le supervisor agent, planifie
    la kill chain et stocke le résultat en mémoire.

    Args:
        mission (MissionRequest): Payload JSON contenant la cible et les ports.

    Returns:
        MissionResponse: Objet contenant l'ID de mission, la cible,
        le statut et la kill chain planifiée.
    """
    # Instanciation de l'agent superviseur avec la cible fournie
    supervisor = SupervisorAgent(target=mission.target)
    # Planification de la kill chain (étapes ordonnancées)
    result = supervisor.plan()
    # Ajout du statut initial avant stockage
    result["status"] = "planned"
    # Stockage en mémoire pour les appels ultérieurs
    missions_store[result["id"]] = result
    return MissionResponse(
        id=result["id"],
        target=mission.target,
        status="planned",
        killchain=result["killchain"]
    )


@app.get("/missions")
async def list_missions():
    """
    GET /missions — Lister toutes les missions.

    Retourne la liste complète des missions stockées en mémoire.

    Returns:
        dict: Dictionnaire contenant la clé "missions" avec la liste
        de toutes les missions (incluant leur kill chain et statut).
    """
    return {"missions": list(missions_store.values())}


@app.get("/missions/{mission_id}")
async def get_mission(mission_id: str, request: Request):
    """
    GET /missions/{mission_id} — Détail d'une mission.

    Retourne les détails d'une mission spécifique.
    Négociation de contenu : si le client accepte text/html,
    retourne une page HTML ; sinon retourne du JSON.

    Args:
        mission_id (str): Identifiant unique de la mission.
        request (Request): Requête HTTP entrante (injectée par FastAPI).

    Returns:
        TemplateResponse | dict: Soit le template HTML `mission.html`,
        soit le dictionnaire de la mission, soit une erreur 404.
    """
    # Négociation de contenu basée sur le header Accept
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        # Rendu HTML pour navigation dans le navigateur
        return templates.TemplateResponse(request, "mission.html", {
            "mission_id": mission_id,
        })
    # Fallback JSON pour les clients API
    return missions_store.get(mission_id, {"error": "Mission not found"})


@app.post("/missions/{mission_id}/execute")
async def execute_mission(mission_id: str):
    """
    POST /missions/{mission_id}/execute — Exécuter une mission planifiée.

    Lance l'exécution réelle des étapes de la kill chain pour une mission
    déjà planifiée. Le supervisor agent exécute chaque étape et met à jour
    le statut et la kill chain de la mission.

    Args:
        mission_id (str): Identifiant unique de la mission à exécuter.

    Returns:
        dict: Résultat de l'exécution contenant le mission_id, le statut,
        le nombre d'étapes exécutées et la kill chain mise à jour.
        Retourne une erreur si la mission n'existe pas.
    """
    # Récupération de la mission depuis le store mémoire
    mission = missions_store.get(mission_id)
    if not mission:
        return {"error": "Mission not found"}

    # Ré-instanciation du supervisor pour l'exécution
    supervisor = SupervisorAgent(target=mission["target"])
    supervisor.mission_id = mission_id

    # Exécution séquentielle des étapes de la kill chain
    results = supervisor.execute()

    # Mise à jour de la mission avec les résultats d'exécution
    mission["killchain"] = results
    mission["status"] = "completed"
    return {
        "mission_id": mission_id,
        "status": "completed",
        "steps": len(results),
        "killchain": results,
    }


# ---------------------------------------------------------------------------
# Route de monitoring
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """
    GET /health — Health check de l'API.

    Vérifie que l'API est opérationnelle et retourne la liste
    des agents disponibles.

    Returns:
        dict: Statut "ok" et la liste des agents du système.
    """
    return {"status": "ok", "agents": ["supervisor", "recon", "exploit", "privesc", "persist", "report"]}


# Point d'entrée pour l'exécution directe du script
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
