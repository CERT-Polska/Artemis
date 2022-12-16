from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from artemis.db import DB, TaskFilter

router = APIRouter()
db = DB()


@router.get("/task/{task_id}")
def get_task(task_id: str) -> Dict[str, Any]:
    if result := db.get_task_by_id(task_id):
        return result
    raise HTTPException(status_code=404, detail="Task not found")


@router.get("/analysis")
def list_analysis() -> List[Dict[str, Any]]:
    return db.list_analysis()


@router.get("/analysis/{root_id}")
def get_analysis(root_id: str) -> Dict[str, Any]:
    if result := db.get_analysis_by_id(root_id):
        return result
    raise HTTPException(status_code=404, detail="Analysis not found")


@router.get("/analysis/{root_id}/children")
def get_children(root_id: str, task_filter: Optional[TaskFilter] = None) -> List[Dict[str, Any]]:
    if not db.get_analysis_by_id(root_id):
        raise HTTPException(status_code=404, detail="Analysis not found")
    return db.get_task_results_by_analysis_id(root_id, task_filter)


@router.get("/task-results")
def get_task_results(task_filter: Optional[TaskFilter] = None) -> List[Dict[str, Any]]:
    return db.get_task_results(task_filter)
