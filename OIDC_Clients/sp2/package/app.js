import express from "express";
import * as client from "openid-client";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import https from "https";
import session from "express-session";
import morgan from "morgan";
import dotenv from "dotenv";
import corn from "node-cron";
import jwt from "jsonwebtoken";
import axios from "axios";
import * as jose from "jose";
import cookieParser from "cookie-parser";
import cors from "cors";

dotenv.config();

/* ---------- SSL SETUP ---------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const privateKeyPath = path.join(
  __dirname,
  "Certificates/SSL_certificate/private.key"
);
const certificatePath = path.join(
  __dirname,
  "Certificates/SSL_certificate/certificate.crt"
);

const privateKeys = fs.readFileSync(privateKeyPath, "utf8");
const certificate = fs.readFileSync(certificatePath, "utf8");

const credentials = {
  key: privateKeys,
  cert: certificate,
  passphrase: process.env.SSL_PASSPHRASE,
};

const app = express();
const port = 3500; /* ----- SP II -----*/
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// OIDC Configuration - Client
const clientId = process.env.CLIENT_ID; // Client ID
const client_secret = process.env.CLIENT_SECRET; // Client secret
const redirect_uri = process.env.REDIRECT_URI; // Callback URL
const idp_url = new URL(process.env.IDP_URL || "https://localhost:4000"); // IDP URL

/* ---------- CRON JOB SETUP - SERVER TIMESTAMP ---------- */
corn.schedule("*/10 * * * *", () => {
  console.log(
    "Monitoring client: ",
    new Date(),
    " Minutes:  ",
    new Date().getMinutes()
  );
});

// Set up the view engine (EJS)
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Ignore self-signed certificate errors for dev (remove in production)
//process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // Remove in production

// Discover OIDC provider configuration

// Log the client_id and client_secret to ensure they are set correctly
console.warn("client_id:", clientId);
console.warn("client_secret:", client_secret);

let oidcClient, nonce, tokens;
try {
  oidcClient = await client.discovery(idp_url, clientId, client_secret);
  if (!oidcClient) {
    throw new Error("OIDC Client not configured.");
  }
  console.warn("/* ***************************************/");
  console.warn(`/*       IDP CONNECTION SUCCESSFUL       */`);
  console.warn("/* ***************************************/");
} catch (error) {
  console.error("/* ***************************************/");
  console.error(`IDP CONNECTION FAILED: ${error.message}  `);
  console.error("/* ***************************************/");
  throw error;
}
console.log("OIDC Client:", oidcClient.serverMetadata());

if (!oidcClient) {
  console.error("OIDC Client not configured.");
} else {
  console.warn("OIDC Client configured.");
}

// Generate PKCE code_verifier, code_challenge & state
const code_verifier = client.randomPKCECodeVerifier();
const code_challenge = await client.calculatePKCECodeChallenge(code_verifier);
const state = client.randomState();


const corsOptions = {
  origin: process.env.IDP_URL, // Allow requests from your IDP
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true, // Allow cookies and authentication headers
};

app.use(cors(corsOptions));

console.log("SP II - CORS", corsOptions);


// Session middleware
app.use(
  session({
    name: "clientSession-2",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "None",
      path: "/",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);


app.set("trust proxy", 1); // Nginx purpose!


/* ---------- ROUTES ---------- */
const ensureAuthenticated = (req, res, next) => {
  if (req.session?.tokens) {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    return next();
  }
  // Return index if unauthenticated
  return res.redirect("/");
};

const setNoCache = (req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache");
  return next();
};

app.get("/debug-cookies", (req, res) => {
  res.json({
    headers: req.headers.cookie,
    session: req.session,
  });
});


app.get("/", (req, res) => {
  // Redirect authenticated users to the welcome page
  if (req.session?.tokens) {
    return res.redirect("/welcome");
  }

  // If not authenticated, render the index page
  return res.render("index", { authenticated: false });
});

app.post("/login", async (req, res) => {
  if (!oidcClient) {
    return res.status(500).send("OIDC client not configured.");
  }

  try {
    // Generate the OIDC authorization URL with necessary parameters
    const parameters = {
      // client_id: clientId,
      redirect_uri: redirect_uri,
      scope: "openid email profile",
      code_challenge: code_challenge,
      code_challenge_method: "S256",
      // response_type: "code",
      // state: state,
    };

    // Add nonce if the IDP does not support PKCE
    if (!oidcClient.serverMetadata().supportsPKCE()) {
      nonce = client.randomNonce();
      parameters.nonce = nonce;
    }

    // Redirect the user to the IDP's authorization endpoint for OIDC flow
    const loginUrl = client.buildAuthorizationUrl(oidcClient, parameters);
    console.warn("Redirecting to OIDC login URL:", loginUrl.href);

    // Send the redirect response and stop further execution
    return res.redirect(loginUrl.href);
  } catch (error) {
    console.error("Error during IDP authentication:", error);
  }
});

app.get("/callback", async (req, res) => {
  if (!oidcClient) {
    return res.status(500).send("OIDC client not configured.");
  }

  try {
    let sub, access_token, currentUrl, tokens;
    currentUrl = new URL(
      `${req.protocol}://${req.get("host") + req.originalUrl}`
    );

    const passData = {
      pkceCodeVerifier: code_verifier,
      expectedNonce: nonce,
      idTokenExpected: true,
    };

    // For security, validate the state parameter
    if (passData?.expectedState !== undefined)
      if (passData?.expectedState !== state) {
        console.error("State mismatch:", passData?.expectedState, state);
        return res.status(400).send("State mismatch / Client session expired.");
      }

    console.warn("Entering to callback route");

    // Exchange authorization code for tokens
    tokens = await client.authorizationCodeGrant(
      oidcClient,
      currentUrl,
      passData
    );
    // Store the token set in the session
    req.session.tokens = tokens;

    // Fetch user info using the access token
    access_token = tokens.access_token;
    let claims = tokens.claims();

    // updating the session
    if (!req.session.claims) {
      req.session.claims = {}; // Initialize the claims object in the session
    }
    req.session.claims = { ...req.session.claims, ...claims };

    console.log("ID Token Claims", claims); // Log the claims
    sub = claims.sub;

    const userInfo = await client.fetchUserInfo(oidcClient, access_token, sub);
    console.log(`UserInfo Response: ${JSON.stringify(userInfo, null, 2)}`);
    req.session.email = userInfo?.email; // Passing claims(email) to the session
    req.session.name = userInfo?.name; // Passing claims(name) to the session
    // Redirect to a welcome page or the home route
    return res.redirect("/welcome");
  } catch (error) {
    console.error("Error during callback:", error);
  }
});

app.get("/welcome", ensureAuthenticated,  (req, res) => {
  if (!req.session.tokens) {
    return res.redirect("/");
  }

  console.log("Session after authentication:", req.session);

  return res.render("welcome", {
    authenticated: true,
    username: req?.session?.name,
    email: req?.session?.email,
  });
});

app.get("/profile", ensureAuthenticated, async (req, res) => {
  try {
    const profileUrl = `${process.env.IDP_URL}/profile`;
    console.warn("Profile URL:", profileUrl);
    console.log("AccessToken", req.session?.tokens?.access_token);
    const agent = new https.Agent({
      rejectUnauthorized: false, // Disable SSL certificate validation
    });

    const profileResponse = await axios.get(profileUrl, {
      withCredentials: true,
      httpsAgent: agent,
      headers: {
        Authorization: `Bearer ${req.session?.tokens?.access_token}`,
        Cookie: req.headers?.cookie,
      },
    });
    res.json(profileResponse.data);
  } catch (err) {
    console.error("Error fetching profile:", err);
    return res.status(500).send(err.message);
  }
});

// User-initiated logout
app.post("/logout", setNoCache, async (req, res) => {
  try {
    console.warn("User-initiated logout request received at SP");

    const logoutUrl = `${process.env.IDP_URL}/logout`;
    console.warn("Logout URL:", logoutUrl);

    console.log("logout session", req.session);
    const idTokenHint = req.session?.tokens?.id_token;
    console.log("Extracted id_token_hint:", idTokenHint);

    req.session.destroy(async (err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res.status(500).send("Failed to terminate session.");
      }

      if (req.cookies && Object.keys(req.cookies).length > 0) {
        console.warn("Clearing cookies at SP");
        Object.keys(req.cookies).forEach((cookie) => {
          res.clearCookie(cookie);
          console.log("Cleared cookie:", cookie);
        });
      } else {
        console.error("No cookies found to clear.");
      }

      console.log("SP session destroyed. Calling IDP logout...");

      try {
        // Call IDP Logout via Axios
        const response = await axios.post(
          logoutUrl,
          { id_token_hint: idTokenHint || "" }, // passing token_hint
          {
            headers: {
              "Content-Type": "application/json",
              Cookie: req.headers?.cookie || "",
            },
            withCredentials: true,
          }
        );

        console.log("IDP logout response:", response.data);

        if (response.data.redirect) {
          console.log("Redirecting user to:", response.data.redirect);
          return res.redirect(response.data.redirect);
        }

        res.status(200).send({ message: "Logout successful, but no redirect." });
      } catch (error) {
        console.error("Error calling IDP logout:", error.message);
        res.status(500).send("Error logging out from IDP.");
      }
    });
  } catch (error) {
    console.error("Error during SP logout:", error.message);
    res.status(400).send("Logout failed.");
  }
});

//  Backchannel logout route 
app.post("/backchannel-logout", setNoCache, async (req, res) => {
  try {
    console.warn("Backchannel logout request received at SP");

    const logoutToken = req.body?.logout_token;
    if (!logoutToken) {
      console.error("Invalid backchannel logout request - missing logout_token.");
      return res.status(400).send("Invalid backchannel logout request.");
    }

    console.log("?? Received Logout Token:", logoutToken);

    await handleLogoutTokenVerification(logoutToken, req, res);
  } catch (error) {
    console.error("Error during backchannel logout:", error.message);
    res.status(400).send("Backchannel logout failed.");
  }
});


// Function to verify logout token & clear session
async function handleLogoutTokenVerification(logoutToken, req, res) {
  try {
    console.log("Validating logoutToken received from IDP");

    // Decode token
    const decodedHeader = jwt.decode(logoutToken, { complete: true });
    console.log("Decoded Header:", decodedHeader);

    const jwksUri = `${process.env.IDP_URL}/jwks`;
    const { data: jwks } = await axios.get(jwksUri);

    const signingKey = jwks.keys.find(
      (key) => key.kid === decodedHeader?.header?.kid
    );

    if (!signingKey) {
      console.error("No signing key found!");
      throw new Error("Signing key not found in JWKS.");
    }

    let key;
    if (signingKey.x5c) {
      key = await jose.importX509(signingKey.x5c[0], "RS256");
    } else {
      key = await jose.importJWK(
        { kty: signingKey.kty, n: signingKey.n, e: signingKey.e },
        "RS256"
      );
    }

    // Verify JWT
    const decodedToken = await jose.jwtVerify(logoutToken, key);
    const { sub, events } = decodedToken.payload;

    if (!events || !events["http://schemas.openid.net/event/backchannel-logout"]) {
      console.error("Invalid logout token - missing Events!");
      throw new Error("Invalid logout token.");
    }

    console.log(`Logout initiated for user: ${sub}`);

    // ?? Find the session associated with the user by `email`
    req.sessionStore.all((err, sessions) => {
      if (err) {
        console.error("Error retrieving sessions:", err);
        return res.status(500).send("Failed to retrieve session.");
      }

      // Find session where `session.email === sub`
      const sessionEntry = Object.entries(sessions).find(([sessionId, session]) => {
        return session?.email === sub; // Match `email` from session data
      });

      if (!sessionEntry) {
        console.warn(`No active session found for user: ${sub}`);
        return res.status(200).send("No active session found.");
      }

      const sessionId = sessionEntry[0];
      console.log(`Found session for ${sub}: ${sessionId}`);

      // ?? Destroy the session
      req.sessionStore.destroy(sessionId, (err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return res.status(500).send("Failed to terminate session.");
        }

        console.log("Session successfully destroyed!");

        // No cookies can be cleared in a backchannel request since it is server-to-server
        return res.status(200).send("Logout successful.");
      });
    });

  } catch (error) {
    console.error("Error verifying logout token:", error.message);
    res.status(400).send("Invalid logout token.");
  }
}



/* ---------- SERVER SETUP ---------- */
//https.createServer(credentials, app).listen(port, "0.0.0.0", () => {
//  console.log(`Client is running on https://localhost:${port}`);
//  console.log(`Server running with machine IP: ${process.env.SP_URL}:`);
//});


/* ---------- SERVER SETUP WITHOUT SSL ---------- */
 app.listen(port, "0.0.0.0", () => {
 //  console.log(`Client is running on http://localhost:${port}`);
   console.log(`Server running with machine IP: ${process.env.SP_URL}`);
 });
