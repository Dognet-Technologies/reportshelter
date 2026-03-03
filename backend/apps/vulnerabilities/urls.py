from django.urls import path

from .views import (
    ProjectTimelineView,
    ScanImportDetailView,
    ScanImportUploadView,
    VulnerabilityDetailView,
    VulnerabilityDiffView,
    VulnerabilityListCreateView,
)

app_name = "vulnerabilities"

urlpatterns = [
    path("", VulnerabilityListCreateView.as_view(), name="vuln-list"),
    path("<int:pk>/", VulnerabilityDetailView.as_view(), name="vuln-detail"),
    path("import/<int:subproject_pk>/", ScanImportUploadView.as_view(), name="scan-import"),
    path("imports/<int:pk>/", ScanImportDetailView.as_view(), name="scan-import-detail"),
    path("diff/", VulnerabilityDiffView.as_view(), name="vuln-diff"),
    path("timeline/<int:project_pk>/", ProjectTimelineView.as_view(), name="project-timeline"),
]
