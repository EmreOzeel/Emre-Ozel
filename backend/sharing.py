"""
Sharing scope helpers for team-aware resources (role presets, saved queries,
investigation notes, path-analysis feedback).

Three scopes are supported:

- ``private`` — visible only to the owner (``owner_user_id`` / ``created_by``)
- ``team``    — visible to every user in the same team as the owner
- ``global``  — visible to every authenticated user; only admins may create,
  edit or delete.

Visibility vs. permission:

- ``visible_filter`` returns a SQLAlchemy filter clause that restricts a query
  to items the given user is allowed to *see*.
- ``can_edit`` returns whether the given user is allowed to *modify* a row.

The helpers are deliberately model-agnostic: any SQLAlchemy model that exposes
``scope``, ``owner_user_id`` (or ``created_by``) and ``team_id`` columns can
use them.
"""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException
from sqlalchemy import or_

VALID_SCOPES = ("private", "team", "global")


def _owner_col(model):
    """Return the owner column for *model* (owner_user_id preferred)."""
    if hasattr(model, "owner_user_id"):
        return model.owner_user_id
    return model.created_by


def validate_scope(scope: str) -> None:
    """Raise 422 if *scope* is not one of the supported values."""
    if scope not in VALID_SCOPES:
        raise HTTPException(422, f"scope must be one of {VALID_SCOPES}")


def check_can_create(scope: str, current_user) -> None:
    """Enforce creation permissions for a given scope.

    - ``private`` — always allowed.
    - ``team``    — user must belong to a team.
    - ``global``  — user must be admin.
    """
    validate_scope(scope)
    if scope == "team" and not getattr(current_user, "team_id", None):
        raise HTTPException(
            403, "User must belong to a team to create team-scoped items"
        )
    if scope == "global" and not getattr(current_user, "is_admin", False):
        raise HTTPException(403, "Only admins may create global items")


def visible_filter(model, current_user):
    """Return a SQLAlchemy OR-clause matching rows *current_user* may see.

    A row is visible if any of:

    - it is private and owned by the user, or
    - it is team-scoped and its ``team_id`` matches the user's team, or
    - it is global.

    Admin users see everything.
    """
    if getattr(current_user, "is_admin", False):
        # Admins always see every row regardless of scope
        return model.scope.in_(VALID_SCOPES)

    owner_col = _owner_col(model)
    clauses = [
        (model.scope == "private") & (owner_col == current_user.id),
        model.scope == "global",
    ]
    team_id = getattr(current_user, "team_id", None)
    if team_id is not None:
        clauses.append(
            (model.scope == "team") & (model.team_id == team_id)
        )
    return or_(*clauses)


def can_view(row, current_user) -> bool:
    """Is *current_user* allowed to read *row*?"""
    if getattr(current_user, "is_admin", False):
        return True
    if row.scope == "global":
        return True
    owner_id = getattr(row, "owner_user_id", None) or getattr(row, "created_by", None)
    if row.scope == "private":
        return owner_id == current_user.id
    if row.scope == "team":
        team_id = getattr(current_user, "team_id", None)
        return team_id is not None and row.team_id == team_id
    return False


def can_edit(row, current_user) -> bool:
    """Is *current_user* allowed to edit/delete *row*?

    Rules:
    - Admins can edit anything.
    - Global rows: admins only.
    - Team rows: only the original author can edit (others have read-only access).
    - Private rows: only the owner.
    """
    if getattr(current_user, "is_admin", False):
        return True
    if row.scope == "global":
        return False
    owner_id = getattr(row, "owner_user_id", None) or getattr(row, "created_by", None)
    return owner_id == current_user.id


def enforce_view(row, current_user) -> None:
    """Raise 404 / 403 if *current_user* cannot view *row*."""
    if row is None:
        raise HTTPException(404, "Not found")
    if not can_view(row, current_user):
        raise HTTPException(403, "Not authorized to access this item")


def enforce_edit(row, current_user) -> None:
    """Raise 404 / 403 if *current_user* cannot edit *row*."""
    if row is None:
        raise HTTPException(404, "Not found")
    if not can_view(row, current_user):
        raise HTTPException(403, "Not authorized to access this item")
    if not can_edit(row, current_user):
        raise HTTPException(403, "Read-only: you cannot modify shared items you do not own")


def resolve_team_id(scope: str, current_user) -> Optional[int]:
    """Return the ``team_id`` a new row should be created with.

    - ``team`` → current user's team (required).
    - everything else → None.
    """
    if scope == "team":
        team_id = getattr(current_user, "team_id", None)
        if team_id is None:
            raise HTTPException(
                403, "User must belong to a team to create team-scoped items"
            )
        return team_id
    return None
