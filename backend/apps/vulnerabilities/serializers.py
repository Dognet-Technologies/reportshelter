"""
Serializers for the vulnerabilities app.
"""

from rest_framework import serializers

from .models import ScanImport, Vulnerability


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Full serializer for Vulnerability."""

    project_id = serializers.IntegerField(source="subproject.project_id", read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "subproject",
            "project_id",
            "scan_import",
            "title",
            "description",
            "remediation",
            "affected_host",
            "affected_port",
            "affected_service",
            "cve_id",
            "cvss_score",
            "cvss_vector",
            "epss_score",
            "risk_level",
            "risk_score",
            "vuln_status",
            "sources",
            "is_recurring",
            "evidence_code",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id", "subproject", "scan_import", "risk_score",
            "is_recurring", "sources", "created_at", "updated_at",
        ]

    def validate_cvss_score(self, value: float | None) -> float | None:
        if value is not None and not (0.0 <= value <= 10.0):
            raise serializers.ValidationError("CVSS score must be between 0.0 and 10.0.")
        return value

    def validate_epss_score(self, value: float | None) -> float | None:
        if value is not None and not (0.0 <= value <= 1.0):
            raise serializers.ValidationError("EPSS score must be between 0.0 and 1.0.")
        return value


class VulnerabilityListSerializer(serializers.ModelSerializer):
    """Compact serializer for vulnerability listings."""

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "title",
            "affected_host",
            "affected_port",
            "risk_level",
            "risk_score",
            "cvss_score",
            "epss_score",
            "vuln_status",
            "cve_id",
            "is_recurring",
            "sources",
        ]


class ScanImportSerializer(serializers.ModelSerializer):
    """Serializer for ScanImport status."""

    class Meta:
        model = ScanImport
        fields = [
            "id",
            "subproject",
            "tool",
            "original_filename",
            "status",
            "error_message",
            "vulnerability_count",
            "imported_by",
            "imported_at",
            "processed_at",
        ]
        read_only_fields = fields


class ScanImportUploadSerializer(serializers.Serializer):
    """Serializer for initiating a scan file upload."""

    file = serializers.FileField()
    tool = serializers.ChoiceField(choices=ScanImport.Tool.choices)
