# Forge deploy-worker configuration.
# The dashboard uses this account to run build/deploy jobs on the box.
# (Readable by the web user because the app imports it at startup — which means
#  anyone who lands code execution as the web user can read it too. That is the
#  lateral-movement bug: real user creds sitting in a web-readable config.)

DEPLOY_USER = "deploy"
DEPLOY_PASSWORD = "F0rge-D3pl0y-2026!"

# TODO(ops): move secrets to a vault; the web user should not be able to read
# the deploy account's password.
