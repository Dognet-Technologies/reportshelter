from django.urls import path

from .views import (
    ReportExportDetailView,
    ReportExportDownloadView,
    ReportExportListView,
    ReportGenerateView,
)

app_name = "reports"

urlpatterns = [
    path("generate/", ReportGenerateView.as_view(), name="generate"),
    path("exports/", ReportExportListView.as_view(), name="export-list"),
    path("exports/<int:pk>/", ReportExportDetailView.as_view(), name="export-detail"),
    path("exports/<int:pk>/download/", ReportExportDownloadView.as_view(), name="export-download"),
]
