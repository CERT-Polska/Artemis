from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException

from artemis.db import DB

router = APIRouter()
db = DB()


@router.get("/task/{task_id}")
def get_task(task_id: str) -> Dict:
    if result := db.get_task_by_id(task_id):
        return result
    raise HTTPException(status_code=404, detail="Task not found")


@router.get("/analysis")
def list_analysis() -> List[Dict]:
    return db.list_analysis()


@router.get("/analysis/{root_id}")
def get_analysis(root_id: str) -> Dict:
    if result := db.get_analysis_by_id(root_id):
        return result
    raise HTTPException(status_code=404, detail="Analysis not found")


@router.get("/analysis/{root_id}/children")
def get_children(root_id: str, status: Optional[str] = None) -> List[Dict]:
    if not db.get_analysis_by_id(root_id):
        raise HTTPException(status_code=404, detail="Analysis not found")
    return db.get_task_results_by_analysis_id(root_id, status)
