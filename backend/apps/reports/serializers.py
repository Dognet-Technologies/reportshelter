"""
Serializers for the reports app.
"""

from rest_framework import serializers

from .models import ReportExport


class ReportExportSerializer(serializers.ModelSerializer):
    """Serializer for ReportExport status and download."""

    file_url = serializers.SerializerMethodField()

    class Meta:
        model = ReportExport
        fields = [
            "id",
            "subproject",
            "format",
            "status",
            "file_url",
            "error_message",
            "options",
            "generated_by",
            "created_at",
            "completed_at",
        ]
        read_only_fields = [
            "id", "status", "file_url", "error_message",
            "generated_by", "created_at", "completed_at",
        ]

    def get_file_url(self, obj: ReportExport) -> str | None:
        if obj.file:
            request = self.context.get("request")
            if request:
                return request.build_absolute_uri(obj.file.url)
            return obj.file.url
        return None


class ReportGenerateSerializer(serializers.Serializer):
    """Serializer for initiating a report generation request."""

    subproject = serializers.IntegerField()
    format = serializers.ChoiceField(choices=ReportExport.Format.choices, default=ReportExport.Format.PDF)
    vuln_status = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by vulnerability status (e.g. ['open', 'retest'])",
    )
    risk_levels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by risk level (e.g. ['critical', 'high'])",
    )
