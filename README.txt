KILLIX admin + user system

Render variables:
ADMIN_USERNAME = admin
ADMIN_PASSWORD = YOUR_PRIVATE_PASSWORD
SESSION_SECRET = LONG_RANDOM_SECRET
DB_PATH = killix.db

IMPORTANT: SQLite file on Render Free is not durable across redeploy/restart. For real production users, attach persistent storage or migrate DB to a persistent managed database.

Routes:
/ = user login/register/account
/admin = real admin panel

Rules:
New account: +20 coin
Daily: +4 coin once per UTC calendar day
Referral: referrer receives +100 coin once when a new account registers with their valid referral code.
