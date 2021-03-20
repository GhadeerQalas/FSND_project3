import json
from os import abort

from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'fsnd-ghadeer-dev.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'https://127.0.0.1:5000'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header
'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    """
    :make sure from header
    :we must check on four cases:
       :Authorization header must be starting with "Bearer".
       :Token not found: should be contain two part
       :Authorization header must be two part
       :Authorization header must be not less than one part
    :return: token
    """
    auth = ""
    # it should raise an AuthError if no header is present
    if 'Authorization' not in request.headers:
        raise AuthError({'code': 'authorization_header_is_missing',
            'description': 'Authorization header is missing.'}, 401)
    else:
        auth = request.headers.get('Authorization') # it should attempt to get the header from the request

    parts = auth.split() # it should attempt to split bearer and the token
    # it should raise an AuthError if the header is malformed
    if parts[0].lower() != 'bearer':
        raise AuthError({'code': 'invalid_header_not_start_bearer',
            'description': 'Authorization header must be starting with "Bearer".'}, 401)
    # check if length of token equal 2 parts or one part
    elif len(parts) == 1:
        raise AuthError({'code': 'invalid_auth',
                         'description': 'Token not found: should be contain two part'}, 401)
    # it should attempt to split bearer and the token
    elif len(parts) > 2:
        raise AuthError({'code': 'invalid_auth',
            'description': 'Authorization header must be two part'}, 401)
    # it should attempt to split bearer and the token
    elif len(parts) < 1:
        raise AuthError({'code': 'invalid_auth',
            'description': 'Authorization header must be not less than one part'}, 401)

    token = parts[1]
    return token

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload
    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    # it should raise an AuthError if permissions are not included in the payload
    if 'permissions' not in payload:
        abort(400)

    # it should raise an AuthError if the requested permission string is not in the payload permissions array
    if permission not in payload['permissions']:
        raise AuthError({'code': 'unauthorized',
            'description': 'Permission Not found: not in the payload permissions array',}, 401)
    # return true otherwise
    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)
    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload
    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    """

    :param token: JWT
    :return: without return
    """
    url = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jsonUrl = json.loads(url.read())
    check_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in check_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed: there is no keys in header'}, 401)

    for key in jsonUrl['keys']:
        if key['kid'] == check_header['kid']:
            rsa_key = {'kty': key['kty'], 'kid': key['kid'], 'use': key['use'], 'n': key['n'], 'e': key['e']}
    if rsa_key:
        try:
            payload_jwt = jwt.decode(token, rsa_key, algorithms=ALGORITHMS, audience='coffeeshop', issuer='https://' + AUTH0_DOMAIN + '/')
            return payload_jwt

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired_Signature_Error',
                'description': 'Expired Signature Error.'}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({'code': 'invalid_claims',
                'description': 'Invalid claims. JWTClaimsError'}, 401)
        except Exception:
            raise AuthError({'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'}, 400)
    raise AuthError({'code': 'invalid_header',
                'description': 'Unable to find the key.'}, 400)

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(g):
        @wraps(g)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth_decorator