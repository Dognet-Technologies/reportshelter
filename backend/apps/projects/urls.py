from django.urls import path

from .views import (
    ProjectDetailView,
    ProjectListCreateView,
    ProjectLockAcquireView,
    ProjectLockHeartbeatView,
    ProjectLockReleaseView,
    ScreenshotDetailView,
    ScreenshotListCreateView,
    SubProjectDetailView,
    SubProjectListCreateView,
)

app_name = "projects"

urlpatterns = [
    # Projects
    path("", ProjectListCreateView.as_view(), name="project-list"),
    path("<int:pk>/", ProjectDetailView.as_view(), name="project-detail"),
    # Lock
    path("<int:pk>/lock/acquire/", ProjectLockAcquireView.as_view(), name="lock-acquire"),
    path("<int:pk>/lock/heartbeat/", ProjectLockHeartbeatView.as_view(), name="lock-heartbeat"),
    path("<int:pk>/lock/release/", ProjectLockReleaseView.as_view(), name="lock-release"),
    # SubProjects
    path("<int:project_pk>/subprojects/", SubProjectListCreateView.as_view(), name="subproject-list"),
    path("<int:project_pk>/subprojects/<int:pk>/", SubProjectDetailView.as_view(), name="subproject-detail"),
    # Screenshots
    path(
        "<int:project_pk>/subprojects/<int:subproject_pk>/screenshots/",
        ScreenshotListCreateView.as_view(),
        name="screenshot-list",
    ),
    path("screenshots/<int:pk>/", ScreenshotDetailView.as_view(), name="screenshot-detail"),
]
