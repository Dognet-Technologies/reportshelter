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
            "report_name",
            "options",
            "generated_by",
            "created_at",
            "completed_at",
        ]
        read_only_fields = [
            "id", "status", "file_url", "error_message",
            "report_name", "generated_by", "created_at", "completed_at",
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

    # Vulnerability filters
    # Frontend sends "statuses"; accept both names for compatibility.
    statuses = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by vulnerability status (e.g. ['open', 'retest'])",
    )
    vuln_status = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Alias for statuses (legacy).",
    )
    risk_levels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Filter by risk level (e.g. ['critical', 'high'])",
    )

    # Report configuration
    report_type = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Report type ID (e.g. 'pentest', 'va', 'executive').",
    )
    sections = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Ordered list of section IDs to include in the report.",
    )
    audience = serializers.CharField(
        required=False,
        allow_blank=True,
        default="technical",
        help_text="Target audience: 'executive', 'management', or 'technical'.",
    )

    # Per-report visual overrides (from SubProjectPage StylePanel)
    style = serializers.DictField(
        child=serializers.CharField(allow_blank=True),
        required=False,
        help_text=(
            "Visual overrides: primaryColor, secondaryColor, font, watermark, "
            "borderRadius, titleSize, evidenceStyle."
        ),
    )

    # Extra metadata (from SubProjectPage ExtraInfoPanel)
    extra = serializers.DictField(
        required=False,
        help_text=(
            "Extra metadata: classification, version, scope, engagement_type, "
            "methodologies, authors, references."
        ),
    )

    # Per-section custom intro text, keyed by section ID.
    section_overrides = serializers.DictField(
        required=False,
        help_text=(
            "Custom intro text per section, keyed by section ID. "
            "Each value is an object with a 'custom_text' key."
        ),
    )

    # Chart configuration (from SubProjectPage ChartsPanel)
    charts_enabled = serializers.DictField(
        child=serializers.BooleanField(),
        required=False,
        help_text="Which charts to generate, keyed by chart ID.",
    )
    charts_variants = serializers.DictField(
        child=serializers.CharField(),
        required=False,
        help_text="Chart variant selection per chart ID (e.g. 'Donut', 'Pie').",
    )
    charts_details = serializers.DictField(
        required=False,
        help_text=(
            "Per-chart detail config keyed by chart ID. "
            "Each value may contain: caption, x_axis_label, y_axis_label, "
            "show_legend, show_grid, mode_3d."
        ),
    )
