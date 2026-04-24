def error_response(message, code=400):
    return {
        "status": "error",
        "message": message,
        "code": code
    }
