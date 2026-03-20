/**
 * Authenticated file download utility.
 * Uses the axios client (which injects the JWT Bearer token) to fetch
 * the file as a blob, then triggers a browser download via a temporary
 * object URL — avoids the 401 that occurs with plain <a href> navigation.
 */
import { apiClient } from "./client";

export async function downloadReport(exportId: number, format: string): Promise<void> {
  const response = await apiClient.get(`/reports/exports/${exportId}/download/`, {
    responseType: "blob",
  });

  const mimeTypes: Record<string, string> = {
    pdf:  "application/pdf",
    html: "text/html",
    xml:  "application/xml",
  };

  const blob = new Blob([response.data], {
    type: mimeTypes[format.toLowerCase()] ?? "application/octet-stream",
  });

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `report_${exportId}.${format.toLowerCase()}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
