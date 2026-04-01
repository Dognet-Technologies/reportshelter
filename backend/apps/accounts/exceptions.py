"""Custom exception handler for DRF."""
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    """Wrap DRF exceptions in a consistent JSON envelope."""
    response = exception_handler(exc, context)
    if response is not None:
        response.data = {
            "success": False,
            "errors": response.data,
        }
    return response
