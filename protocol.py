from utils.framing import FramingError


def response_from_result(req_id, result):
    response = dict(result)
    if req_id is not None:
        response["id"] = req_id
    return response


def error_response(req_id, status, message, code=None):
    if code is None:
        code = "SERVER_ERROR" if status >= 500 else "BAD_REQUEST"
    return {
        "v": 1,
        "id": req_id,
        "status": status,
        "code": code,
        "message": message,
        "data": {},
    }


def validate_request(request):
    if not isinstance(request, dict):
        raise FramingError("request must be a JSON object")
    if request.get("v") != 1:
        raise FramingError("unsupported protocol version")
    if not isinstance(request.get("id"), str) or not request["id"]:
        raise FramingError("request id is required")
    command = request.get("cmd")
    if not isinstance(command, str) or command not in {
        "REGISTER", "LOGIN", "LOGOUT", "LIST", "GET", "PUT",
    }:
        raise FramingError("unknown command")