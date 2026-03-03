"""
WebSocket consumers for real-time notifications.
ProjectLockConsumer handles lock state broadcasts for a specific project.
"""

import json

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils import timezone


class ProjectLockConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for project lock notifications.

    Clients connect to: ws/projects/<project_id>/lock/
    Query param:        ?token=<JWT access token>

    Events sent to client:
        lock.status   → current lock holder on connect
        lock.acquired → another user acquired the lock
        lock.released → lock was released (project now available)
        lock.expired  → lock timed out (project now available)
        heartbeat.ok  → heartbeat acknowledged
        error         → authentication / permission error
    """

    async def connect(self) -> None:
        self.project_id: str = self.scope["url_route"]["kwargs"]["project_id"]
        self.group_name: str = f"project_lock_{self.project_id}"

        # Authenticate via JWT token in query string
        user = await self._get_authenticated_user()
        if user is None:
            await self.close(code=4001)
            return

        self.user = user

        # Verify project ownership (IDOR protection)
        has_access = await self._verify_project_access()
        if not has_access:
            await self.close(code=4003)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # Send current lock status on connect
        await self._send_current_lock_status()

    async def disconnect(self, close_code: int) -> None:
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

        # If the disconnecting user holds the lock, release it and notify others
        if hasattr(self, "user") and hasattr(self, "project_id"):
            released = await self._release_lock_if_held()
            if released:
                await self.channel_layer.group_send(
                    self.group_name,
                    {
                        "type": "lock.released",
                        "released_by": self.user.full_name,
                        "project_id": self.project_id,
                    },
                )

    async def receive(self, text_data: str) -> None:
        """Handle messages from the client."""
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            await self.send_json({"type": "error", "detail": "Invalid JSON."})
            return

        msg_type = data.get("type")

        if msg_type == "heartbeat":
            await self._handle_heartbeat()
        elif msg_type == "lock.acquire":
            await self._handle_lock_acquire()
        elif msg_type == "lock.release":
            await self._handle_lock_release()
        else:
            await self.send_json({"type": "error", "detail": f"Unknown message type: {msg_type}"})

    # ------------------------------------------------------------------
    # Group message handlers (called by channel layer)
    # ------------------------------------------------------------------

    async def lock_acquired(self, event: dict) -> None:
        """Broadcast to all clients in the group when a lock is acquired."""
        await self.send_json({
            "type": "lock.acquired",
            "locked_by": event["locked_by"],
            "locked_at": event["locked_at"],
            "project_id": event["project_id"],
        })

    async def lock_released(self, event: dict) -> None:
        """Broadcast to all clients in the group when a lock is released."""
        await self.send_json({
            "type": "lock.released",
            "released_by": event["released_by"],
            "project_id": event["project_id"],
            "message": f"Project is now available (released by {event['released_by']}).",
        })

    async def lock_expired(self, event: dict) -> None:
        """Broadcast to all clients when a lock expires."""
        await self.send_json({
            "type": "lock.expired",
            "project_id": event["project_id"],
            "message": "Project lock expired. Project is now available.",
        })

    async def import_complete(self, event: dict) -> None:
        """Broadcast to all clients when a scan import finishes parsing."""
        await self.send_json({
            "type": "import.complete",
            "scan_import_id": event["scan_import_id"],
            "tool": event["tool"],
            "filename": event["filename"],
            "vulnerability_count": event["vulnerability_count"],
        })

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def send_json(self, data: dict) -> None:
        await self.send(text_data=json.dumps(data, default=str))

    async def _get_authenticated_user(self):
        """Validate JWT token from query string and return User or None."""
        from rest_framework_simplejwt.tokens import AccessToken
        from rest_framework_simplejwt.exceptions import TokenError
        from django.contrib.auth import get_user_model

        User = get_user_model()

        query_string = self.scope.get("query_string", b"").decode()
        params = dict(p.split("=") for p in query_string.split("&") if "=" in p)
        token_str = params.get("token", "")

        if not token_str:
            return None

        try:
            token = AccessToken(token_str)
            user_id = token["user_id"]
            user = await sync_to_async(User.objects.select_related("organization").get)(pk=user_id)
            return user
        except (TokenError, User.DoesNotExist, KeyError):
            return None

    async def _verify_project_access(self) -> bool:
        """Check the user belongs to the project's organization (IDOR protection)."""
        from apps.projects.models import Project

        try:
            project = await sync_to_async(
                Project.objects.select_related("organization").get
            )(pk=self.project_id)
            return project.organization_id == self.user.organization_id
        except Project.DoesNotExist:
            return False

    async def _send_current_lock_status(self) -> None:
        """Send the current lock status to the newly connected client."""
        from apps.projects.models import Project

        try:
            project = await sync_to_async(
                Project.objects.select_related("lock", "lock__locked_by").get
            )(pk=self.project_id)

            try:
                lock = project.lock
                if lock.is_expired():
                    await sync_to_async(lock.delete)()
                    await self.send_json({"type": "lock.status", "locked": False})
                else:
                    await self.send_json({
                        "type": "lock.status",
                        "locked": True,
                        "locked_by": lock.locked_by.full_name if lock.locked_by else None,
                        "locked_at": str(lock.locked_at),
                        "is_you": lock.locked_by_id == self.user.pk,
                    })
            except Exception:
                await self.send_json({"type": "lock.status", "locked": False})

        except Exception:
            await self.send_json({"type": "error", "detail": "Could not fetch lock status."})

    async def _handle_heartbeat(self) -> None:
        """Refresh the lock heartbeat if this user holds the lock."""
        from apps.projects.models import ProjectLock

        try:
            lock = await sync_to_async(ProjectLock.objects.get)(project_id=self.project_id)
            if lock.locked_by_id == self.user.pk:
                await sync_to_async(lock.refresh)()
                await self.send_json({"type": "heartbeat.ok", "last_heartbeat": str(lock.last_heartbeat)})
            else:
                await self.send_json({"type": "error", "detail": "You do not hold this lock."})
        except ProjectLock.DoesNotExist:
            await self.send_json({"type": "error", "detail": "No lock to refresh."})

    async def _handle_lock_acquire(self) -> None:
        """Attempt to acquire the project lock for this user."""
        from apps.projects.models import Project, ProjectLock

        try:
            project = await sync_to_async(Project.objects.get)(pk=self.project_id)
        except Project.DoesNotExist:
            await self.send_json({"type": "error", "detail": "Project not found."})
            return

        try:
            lock = await sync_to_async(lambda: project.lock)()
            if not lock.is_expired() and lock.locked_by_id != self.user.pk:
                locked_by_name = await sync_to_async(lambda: lock.locked_by.full_name if lock.locked_by else "unknown")()
                await self.send_json({
                    "type": "error",
                    "detail": f"Project is locked by {locked_by_name}.",
                    "locked_by": locked_by_name,
                })
                return
            # Take over (expired or same user)
            lock.locked_by = self.user
            lock.locked_at = timezone.now()
            lock.last_heartbeat = timezone.now()
            await sync_to_async(lock.save)()
        except Exception:
            lock = await sync_to_async(ProjectLock.objects.create)(
                project=project, locked_by=self.user
            )

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "lock.acquired",
                "locked_by": self.user.full_name,
                "locked_at": str(lock.locked_at),
                "project_id": self.project_id,
            },
        )

    async def _handle_lock_release(self) -> None:
        """Release the project lock held by this user."""
        released = await self._release_lock_if_held()
        if released:
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "lock.released",
                    "released_by": self.user.full_name,
                    "project_id": self.project_id,
                },
            )
        else:
            await self.send_json({"type": "error", "detail": "You do not hold this lock."})

    async def _release_lock_if_held(self) -> bool:
        """Delete the lock if held by this user. Returns True if released."""
        from apps.projects.models import ProjectLock

        try:
            lock = await sync_to_async(ProjectLock.objects.get)(project_id=self.project_id)
            if lock.locked_by_id == self.user.pk:
                await sync_to_async(lock.delete)()
                return True
        except ProjectLock.DoesNotExist:
            pass
        return False
