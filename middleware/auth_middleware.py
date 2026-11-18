"""
middleware/auth_middleware.py  [PERSON B]

require_session() is called at the start of every protected controller
function. It turns a token into the user's identity. File services must use
the user_id from here, NEVER a user id taken from the request.
"""
from services import session_service
from services.errors import unauthenticated


def require_session(token, ip):
    """Return {session_id, user_id, username, role} or raise AppError(401)."""
    info = session_service.validate_token(token)
    if info is None:
        raise unauthenticated()
    return info
