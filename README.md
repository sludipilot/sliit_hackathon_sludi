SLUDI Integration – Developer Guide

1. Overview
This guide explains how to integrate SLUDI with your system using a Node.js backend and a React frontend. 
It includes:
•	Frontend & backend setup
•	Key management
•	OAuth2 / OIDC flows
•	Common pitfalls & debugging tips
________________________________________
2. Architecture Overview
flowchart LR
    FE[Frontend - React] -->|Authorization Code| BE[Backend - Node.js]
    BE -->|Signed JWT (client_assertion)| ES[eSignet Server]
    ES -->|Access Token| BE
    BE -->|User Info Request with Access Token| ES
    ES -->|User Info Response (JWT/JWE)| BE
    BE -->|Send JSON to Frontend| FE
Roles:
•	Frontend: Redirects users to SLUDI, receives authorization code, calls backend to fetch tokens & user info.
•	Backend: Holds private key, signs JWTs, exchanges code for access token, fetches user info, decrypts if JWE.
•	SLUDI: Validates signed JWT, returns access token and user information.
________________________________________


3. Key Management
3.1 Generate RSA Key Pair
Use Node.js jose library or OpenSSL:
# Generate private key
openssl genrsa -out private.pem 2048

# Generate public key
openssl rsa -in private.pem -pubout -out public.pem

3.2 Register Public Key
Send the public key when creating or updating the OIDC client on SLUDI:
{
  "clientId": "YOUR_CLIENT_ID",
  "clientName": "Test Portal",
  "publicKey": {
    "kty": "RSA",
    "alg": "RS256",
    "use": "sig",
    "n": "MODULUS_FROM_PUBLIC_KEY",
    "e": "AQAB"
  },
  "redirectUris": [
    "http://localhost:5000/userprofile/*"
  ],
  "grantTypes": ["authorization_code"],
  "clientAuthMethods": ["private_key_jwt"]
}
Note: Never send your private key to the frontend or to SLUDI. Keep it strictly in the backend.
3.3 Store Private Key Securely
•	Node.js backend: config.js or .env
•	Do not commit to source control
•	Optionally use secure vaults (HashiCorp Vault, AWS Secrets Manager)

// config.js
module.exports = {
  CLIENT_PRIVATE_KEY: require('./privateKey.json'),
  ESIGNET_SERVICE_URL: "http://localhost:8088/v1/esignet",
  ESIGNET_AUD_URL: "http://localhost:8088/v1/esignet/oauth/v2/token",
};
________________________________________
 
4. Frontend Setup
4.1 Environment Variables
window._env_ = {
  ESIGNET_UI_BASE_URL: "http://localhost:4000",
  MOCK_RELYING_PARTY_SERVER_URL: "http://localhost:8888",
  REDIRECT_URI_USER_PROFILE: "http://localhost:5000/userprofile",
  CLIENT_ID: "YOUR_CLIENT_ID",
  ACRS: "mosip:idp:acr:generated-code mosip:idp:acr:biometrics mosip:idp:acr:static-code",
  SCOPE_USER_PROFILE: "openid profile resident-service",
  DISPLAY: "page",
  PROMPT: "consent",
  GRANT_TYPE: "authorization_code"
};
4.2 Flow
1.	User clicks “Sign in with SLUDI”
2.	Frontend redirects to:
http://localhost:4000/authorize?
client_id=YOUR_CLIENT_ID&
redirect_uri=http://localhost:5000/userprofile&
response_type=code&
scope=openid profile resident-service&
acr_values=mosip:idp:acr:generated-code mosip:idp:acr:biometrics mosip:idp:acr:static-code
3.	eSignet returns authorization_code to your frontend redirect URI.
4.	Frontend calls backend (/fetchUserInfo) with authorization_code.
________________________________________
 
5. Backend Setup (Node.js)
5.1 Endpoints
// app.js
app.post("/fetchUserInfo", async (req, res) => {
  const tokenResponse = await post_GetToken(req.body.code);
  const userInfo = await get_GetUserInfo(tokenResponse.access_token);
  res.json(userInfo);
});
5.2 Token Request
const request = new URLSearchParams({
  code: code,
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI_USER_PROFILE,
  grant_type: "authorization_code",
  client_assertion_type: CLIENT_ASSERTION_TYPE,
  client_assertion: await generateSignedJwt(CLIENT_ID)
});
5.3 Generate Signed JWT
const privateKey = await jose.importJWK(CLIENT_PRIVATE_KEY, "RS256");
const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(privateKey);
 
5.4 Fetch User Info
const response = await axios.get(
  `${ESIGNET_SERVICE_URL}/oidc/userinfo`,
  { headers: { Authorization: `Bearer ${access_token}` } }
);
If eSignet sends JWE, decrypt using your JWE_USERINFO_PRIVATE_KEY.
________________________________________
6. Common Pitfalls
Issue	Cause	Fix
“Oops! It looks like there’s an issue with the URL”	Mismatch redirect URI	Ensure redirect_uri in frontend, backend, and eSignet client registration match exactly
TypeError: Buffer.from(...)	Passed Object instead of Base64 string	Store private key in JSON file and import correctly, do not base64 encode full object
Private key in frontend	Security breach	Never send private key to frontend
________________________________________
7. Best Practices
•	Keep private key offline / secure.
•	Only the backend signs JWTs.
•	Frontend handles only redirection & code.
•	Use localhost only for dev; update to real domain for production.

 
