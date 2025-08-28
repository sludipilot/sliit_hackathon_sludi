window._env_ = {
  ESIGNET_UI_BASE_URL: "https://sludiauth.icta.gov.lk",
  MOCK_RELYING_PARTY_SERVER_URL: "http://localhost:8888",
  REDIRECT_URI_USER_PROFILE: "http://localhost:5000/userprofile",
  REDIRECT_URI_REGISTRATION: "http://localhost:5000/registration",
  REDIRECT_URI: "http://localhost:5000/userprofile",
  CLIENT_ID: "IIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsx8Cc",//this key will be provided by ICTA for your group
  ACRS: "mosip:idp:acr:generated-code%20mosip:idp:acr:biometrics%20mosip:idp:acr:static-code",
  SCOPE_USER_PROFILE: "openid%20profile%20resident-service",
  SCOPE_REGISTRATION: "openid%20profile",
  CLAIMS_USER_PROFILE: "%7B%22userinfo%22:%7B%22given_name%22:%7B%22essential%22:true%7D,%22phone_number%22:%7B%22essential%22:false%7D,%22email%22:%7B%22essential%22:true%7D,%22picture%22:%7B%22essential%22:false%7D,%22gender%22:%7B%22essential%22:false%7D,%22birthdate%22:%7B%22essential%22:false%7D,%22address%22:%7B%22essential%22:false%7D%7D,%22id_token%22:%7B%7D%7D",
  CLAIMS_REGISTRATION: "%7B%22userinfo%22:%7B%22given_name%22:%7B%22essential%22:true%7D,%22phone_number%22:%7B%22essential%22:false%7D,%22email%22:%7B%22essential%22:true%7D,%22picture%22:%7B%22essential%22:false%7D,%22gender%22:%7B%22essential%22:false%7D,%22birthdate%22:%7B%22essential%22:false%7D,%22address%22:%7B%22essential%22:false%7D%7D,%22id_token%22:%7B%7D%7D",
  SIGN_IN_BUTTON_PLUGIN_URL: "https://sludiauth.icta.gov.lk/plugins/sign-in-button-plugin.js",
  DISPLAY: "page",
  PROMPT: "consent",
  GRANT_TYPE: "authorization_code",
  MAX_AGE: 21,
  CLAIMS_LOCALES: "en",
  DEFAULT_LANG: "en",
  FALLBACK_LANG: "%7B%22label%22%3A%22English%22%2C%22value%22%3A%22en%22%7D"
};

// window._env_ = {
//   ESIGNET_UI_BASE_URL: "http://localhost:4000",
//   MOCK_RELYING_PARTY_SERVER_URL: "http://localhost:8888",
//   REDIRECT_URI_USER_PROFILE: "http://localhost:5000/userprofile",
//   REDIRECT_URI_REGISTRATION: "http://localhost:5000/registration",
//   REDIRECT_URI: "http://localhost:5000/userprofile",
//   CLIENT_ID: "IIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlZlmX",//this key will be provided by ICTA for your group
//   ACRS: "mosip:idp:acr:generated-code%20mosip:idp:acr:biometrics%20mosip:idp:acr:static-code",
//   SCOPE_USER_PROFILE: "openid%20profile%20resident-service",
//   SCOPE_REGISTRATION: "openid%20profile",
//   CLAIMS_USER_PROFILE: "%7B%22userinfo%22:%7B%22given_name%22:%7B%22essential%22:true%7D,%22phone_number%22:%7B%22essential%22:false%7D,%22email%22:%7B%22essential%22:true%7D,%22picture%22:%7B%22essential%22:false%7D,%22gender%22:%7B%22essential%22:false%7D,%22birthdate%22:%7B%22essential%22:false%7D,%22address%22:%7B%22essential%22:false%7D%7D,%22id_token%22:%7B%7D%7D",
//   CLAIMS_REGISTRATION: "%7B%22userinfo%22:%7B%22given_name%22:%7B%22essential%22:true%7D,%22phone_number%22:%7B%22essential%22:false%7D,%22email%22:%7B%22essential%22:true%7D,%22picture%22:%7B%22essential%22:false%7D,%22gender%22:%7B%22essential%22:false%7D,%22birthdate%22:%7B%22essential%22:false%7D,%22address%22:%7B%22essential%22:false%7D%7D,%22id_token%22:%7B%7D%7D",
//   SIGN_IN_BUTTON_PLUGIN_URL: "http://localhost:4000/plugins/sign-in-button-plugin.js",
//   DISPLAY: "page",
//   PROMPT: "consent",
//   GRANT_TYPE: "authorization_code",
//   MAX_AGE: 21,
//   CLAIMS_LOCALES: "en",
//   DEFAULT_LANG: "en",
//   FALLBACK_LANG: "%7B%22label%22%3A%22English%22%2C%22value%22%3A%22en%22%7D"
// };