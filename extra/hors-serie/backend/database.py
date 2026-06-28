"""SQLite database for KillChainAgent missions.

Ce module gère la persistance des missions dans une base SQLite locale.
Il fournit les opérations CRUD de base : création, lecture, listage
des missions et de leur kill chain associée.

Schéma de la table `missions` :
    id          TEXT PRIMARY KEY  — Identifiant unique de la mission
    target      TEXT NOT NULL     — Cible de la mission (IP ou hostname)
    status      TEXT              — Statut : planned, completed, etc.
    killchain   TEXT              — Kill chain sérialisée en JSON
    created_at  TEXT              — Date de création au format ISO 8601
"""

import sqlite3
import json
from datetime import datetime


class Database:
    """Gestionnaire de base de données SQLite pour les missions KillChainAgent."""

    def __init__(self, path: str = "killchain.db"):
        """
        Initialise la connexion à la base de données SQLite.

        Crée le fichier de base si inexistant et initialise le schéma.

        Args:
            path (str): Chemin du fichier de base SQLite.
                        Défaut: "killchain.db".
        """
        self.conn = sqlite3.connect(path)
        self._init_db()

    def _init_db(self):
        """
        Crée la table `missions` si elle n'existe pas déjà.

        Requête SQL :
            CREATE TABLE IF NOT EXISTS missions avec les colonnes :
            - id (TEXT PRIMARY KEY) : identifiant unique de la mission
            - target (TEXT NOT NULL) : cible de la mission
            - status (TEXT DEFAULT 'planned') : statut d'avancement
            - killchain (TEXT) : étapes de la kill chain en JSON
            - created_at (TEXT) : horodatage ISO 8601 de création
        """
        # Création de la table avec les colonnes nécessaires
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS missions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT DEFAULT 'planned',
                killchain TEXT,
                created_at TEXT
            )
        """)
        self.conn.commit()

    def save_mission(self, mission_id: str, target: str, killchain: list):
        """
        Sauvegarde ou met à jour une mission dans la base.

        Utilise INSERT OR REPLACE pour créer ou écraser une mission
        existante portant le même identifiant.

        Args:
            mission_id (str): Identifiant unique de la mission.
            target (str): Cible de la mission (IP ou hostname).
            killchain (list): Liste des étapes de la kill chain.
        """
        # INSERT OR REPLACE : insère une nouvelle ligne ou remplace si l'ID existe déjà
        # La kill chain est sérialisée en JSON pour stockage dans la colonne TEXT
        # L'horodatage est généré côté Python au format ISO 8601
        self.conn.execute(
            "INSERT OR REPLACE INTO missions VALUES (?, ?, ?, ?, ?)",
            (mission_id, target, "completed",
             json.dumps(killchain),
             datetime.now().isoformat())
        )
        self.conn.commit()

    def get_mission(self, mission_id: str) -> dict:
        """
        Récupère une mission par son identifiant.

        Args:
            mission_id (str): Identifiant unique de la mission.

        Returns:
            dict | None: Dictionnaire contenant les champs de la mission
            (id, target, status, killchain, created_at) ou None si
            la mission n'existe pas.
        """
        # Requête paramétrée de recherche par clé primaire
        row = self.conn.execute(
            "SELECT * FROM missions WHERE id = ?", (mission_id,)
        ).fetchone()
        if row:
            # Reconstruction du dictionnaire avec désérialisation du JSON stocké
            return {"id": row[0], "target": row[1], "status": row[2],
                    "killchain": json.loads(row[3]), "created_at": row[4]}
        return None

    def list_missions(self) -> list:
        """
        Liste toutes les missions enregistrées dans la base.

        Returns:
            list[dict]: Liste de dictionnaires contenant pour chaque mission
            les champs id, target, status et created_at.
            La colonne killchain est volontairement exclue pour alléger la réponse.
        """
        # Sélection de toutes les missions sans la kill chain (colonne potentiellement lourde)
        rows = self.conn.execute("SELECT id, target, status, created_at FROM missions").fetchall()
        return [{"id": r[0], "target": r[1], "status": r[2], "created_at": r[3]} for r in rows]
