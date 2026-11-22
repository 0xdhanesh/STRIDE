import jwt, os
from fastapi import Header, HTTPException

JWKS = jwt.PyJWKClient(os.environ["AUTH0_ISSUER"] + ".well-known/jwks.json")

def require_user(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ")
    key = JWKS.get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], audience="billing-api")
    return User(claims)

def require_role(role):                      # custom RBAC on top of Auth0 claims
    def check(user=Depends(require_user)):
        if role not in user.roles:
            raise HTTPException(403)
        return user
    return check
