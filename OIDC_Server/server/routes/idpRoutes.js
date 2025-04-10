"use strict";
import jwt from "jsonwebtoken";
import { authenticate } from "../helpers/authenticate.js";
import configuration from "../config/idpConfig.js";
import logger from "../config/logger.js";
import { nanoid } from "nanoid";
import axios from "axios";
import { decryptData } from "../helpers/decryption.js";
import dotenv from "dotenv";
dotenv.config();

export const renderRoutes = (app, provider) => {
  // Helper function to set no-cache headers
  function setNoCache(req, res, next) {
    console.log("setNoCache!");
    res.set("cache-control", "no-store");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    next();
  }

  // Testing purpose to check session existence
  app.get("/check-session", (req, res) => {
    logger.info(`Session: ${JSON.stringify(req.session, null, 2)} `);
    res.send(req.session);
  });

  // Client - to call the client's redirect_uri
  app.get("/client", (req, res) => {
    res.send(`Interaction with ID ${req.params.uid}`);
    const clientPage = configuration?.clients?.redirect_uris;
    logger.warn("Client page: ", clientPage);
    res.render("client", { clientPage });
  });

  // Home page
  app.get("/", (req, res) => {
    res.render("index");
  });

  app.get("/auth", (req, res, next) => {
    const clientId = req.query.client_id;
    if (!req.session.sp) {
      req.session.sp = {};
    }
    if (clientId) {
      req.session.sp.latestClient = clientId; // ✅ Store latest SP authentication
      console.log(`🔄 Stored latest client authentication: ${clientId}`);
    }
    next(); // ✅ Proceed to OIDC processing
  });

  app.get("/interaction/:uid", setNoCache, async (req, res, next) => {
    try {
      logger.info("Entering to interaction/:uid ENDPOINT!");

      // Check if IDP session exists
      if (!req.session?.idp) {
        logger.warn(
          "No IDP session found! Proceeding with normal authentication."
        );
        return proceedWithInteraction(req, res);
      }

      // Extract stored values from IDP session
      const authenticatedClients = req.session?.authorizations || {}; // List of authenticated SPs
      const storedClientId = req.session?.idp?.params?.client_id; // The first authenticated SP
      const codeChallenge = req.session?.idp?.params?.code_challenge;
      const redirectUri = req.session?.idp?.params?.redirect_uri;

      logger.info(
        `🔍 Stored Client: ${storedClientId} | Authenticated Clients: ${Object.keys(
          authenticatedClients
        )}`
      );

      const currentClientId = req.session?.sp?.latestClient;

      // If user already authenticated for this SP, redirect them back
      if (authenticatedClients[currentClientId]) {
        logger.warn("User already authenticated! Redirecting to SP...");

        const authRedirectUrl =
          `${process.env.APP_LOGIN_URL}/auth?` +
          `redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=${process.env.SCOPES}` +
          `&code_challenge=${encodeURIComponent(codeChallenge)}` +
          `&code_challenge_method=S256` +
          `&client_id=${encodeURIComponent(storedClientId)}` +
          `&response_type=${process.env.RESPONSE_TYPE}`;

        logger.info(
          `🔄 Redirecting authenticated user to SP: ${authRedirectUrl}`
        );
        return res.redirect(authRedirectUrl);
      }

      // ✅ Step 5: If a new SP is detected, proceed with normal authentication flow
      logger.warn("New SP detected! Proceeding with normal authentication.");
      return proceedWithInteraction(req, res);
    } catch (err) {
      logger.error(`❌ Error in /interaction/:uid page: ${err}`);
      return next(err);
    }
  });

  // ✅ Helper function to proceed with normal interaction
  async function proceedWithInteraction(req, res) {
    try {
      logger.success("Consuming function:- proceedWithInteraction");
      const { uid, prompt, params, session } =
        await provider.interactionDetails(req, res);
      const client = await provider.Client.find(params?.client_id);
      return renderInteractionPage(
        req,
        res,
        client,
        uid,
        prompt,
        params,
        session
      );
    } catch (error) {
      logger.error(`❌ Unable to fetch interaction details: ${error.message}`);
      return res.status(400).send("Session invalid or expired.");
    }
  }

  // ✅ Helper function to render login/consent page
  function renderInteractionPage(
    req,
    res,
    client,
    uid,
    prompt,
    params,
    session
  ) {
    logger.success("Consuming function:- renderInteractionPage");

    logger.success(
      `IDP initial session: ${JSON.stringify(req.session, null, 2)}`
    );

    switch (prompt?.name) {
      case "login":
        logger.success("Rendering login page!");
        return res.render("index", {
          client,
          uid,
          details: prompt?.details,
          params,
          title: "Sign-in",
          session: session ? session : undefined,
        });
      case "consent":
        logger.success("Rendering consent page!");
        return res.render("interaction", {
          client,
          uid,
          details: prompt?.details,
          params,
          title: "Authorize",
          session: session ? session : undefined,
          scopes: prompt?.details?.scopes?.new,
        });
      default:
        logger.error(`Invalid prompt name: ${prompt.name}`);
        return undefined; // Default undefined
    }
  }

  // Interaction - login page
  app.post("/interaction/:uid/login", setNoCache, async (req, res, next) => {
    const { uid } = req.params;
    const { encryptedUsername, encryptedPassword } = req.body;

    if (!encryptedUsername || !encryptedPassword) {
      console.error("❌ ERROR: Missing encrypted data!");
      return res.status(400).json({ error: "Encrypted data missing!" });
    }

    try {
      logger.info(`Entering to interaction/${uid}/login ENDPOINT!`);

      // ✅ Properly await decryption
      const username = await decryptData(encryptedUsername);
      const password = await decryptData(encryptedPassword);

      console.log(`username: ${username}, password: ${password}`);

      if (!username || !password) {
        return res.status(400).json({
          error: "Decryption failed! Required both username and password data.",
        });
      }

      logger.success(
        `🔓 Decrypted Username: ${username} with 🔑 Decrypted Password: ${password}`
      );

      // Fetch interaction details
      const interactionDetails = await provider.interactionDetails(req, uid);
      if (!interactionDetails) {
        return res.status(400).render("index", {
          error: "Interaction session not found. Please try again.",
        });
      }

      // update the session

      if (!req.session.idp) {
        req.session.idp = {}; // Initialize session object for convenience
      }
      req.session.idp.iat = interactionDetails?.iat;
      req.session.idp.exp = interactionDetails?.exp;
      req.session.idp.returnTo = interactionDetails?.returnTo;
      req.session.idp.params = interactionDetails?.params;
      req.session.idp.cid = interactionDetails?.cid;
      req.session.idp.kind = interactionDetails?.kind;
      req.session.idp.jti = interactionDetails?.jti;

      logger.success(
        `Interaction details in login:
          ${JSON.stringify(interactionDetails, null, 2)}`
      );

      // Authenticate the user (e.g., using Active Directory)
      const authResult = await authenticate(username, password);
      if (!authResult) {
        return res
          .status(401)
          .render("index", { uid, error: "Invalid credentials" });
      }

      const accountId = username; // Use username as accountId

      // ✅ Store mapping `accountId → sessionID`
      sessionStore.set(accountId, req.sessionID);
      logger.success(`Stored session for ${accountId} -> ${req.sessionID}`);

      const {
        params, // OIDC parameters
      } = interactionDetails;

      // Create a new grant for the client
      const grant = new provider.Grant({
        accountId,
        clientId: params.client_id,
      });

      grant.addOIDCScope("openid email profile");
      grant.addOIDCClaims(["email", "name"]);

      // Save the grant
      const grantId = await grant.save();

      // Automatically complete the login and consent steps
      const result = {
        login: {
          accountId, // Associate the user with this session
        },
        consent: {
          grantId, // Approve consent programmatically
        },
      };

      logger.info(`Login result: ${JSON.stringify(result, null, 2)}`);

      // Update the session
      if (!req.session.idp.data) {
        req.session.idp.data = {}; // Initialize session object for convenience
      }
      req.session.idp.data.accountId = result?.login?.accountId;
      req.session.idp.data.grantId = result?.consent?.grantId;

      logger.success(
        `IDP interaction session: ${JSON.stringify(req.session, null, 2)}`
      );

      // Store authorized SPs in session
      if (!req.session.authorizations) {
        req.session.authorizations = {};
      }
      req.session.authorizations[params.client_id] = true; // Track the authorized client

      // Complete the interaction
      await provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: true,
      });
    } catch (err) {
      logger.error("Error during login interaction:", err);
      next(err);
    }
  });

  app.post("/interaction/:uid/confirm", setNoCache, async (req, res, next) => {
    const { uid } = req.params;
    console.log("UID: ", uid);
    try {
      logger.info(`Entering to interaction/${uid}/confirm ENDPOINT!`);
      const interactionDetails = await provider.interactionDetails(req, uid);

      logger.success(
        `Interaction details in confirm:
        ${JSON.stringify(interactionDetails, null, 2)}
      `
      );
      const {
        prompt: { name, details },
        params,
        session: { accountId },
      } = interactionDetails;

      let { grantId } = interactionDetails;
      let grant;

      if (grantId) {
        // Modify existing grant
        grant = await provider.Grant.find(grantId);
      } else {
        // New grant
        grant = new provider.Grant({
          accountId,
          clientId: params?.client_id,
        });
      }

      // Add missing scopes and claims to the grant
      if (details?.missingOIDCScope) {
        grant.addOIDCScope(details.missingOIDCScope.join(" "));
      }
      if (details?.missingOIDCClaims) {
        grant.addOIDCClaims(details.missingOIDCClaims);
      }
      if (details?.missingResourceScopes) {
        for (const [indicator, scopes] of Object.entries(
          details?.missingResourceScopes
        )) {
          grant.addResourceScope(indicator, scopes.join(" "));
        }
      }

      // Save the updated grant
      grantId = await grant.save();

      const consent = {};
      if (!interactionDetails?.grantId) {
        consent.grantId = grantId;
      }

      const result = { consent };

      logger.info(`Consent result: ${JSON.stringify(result, null, 2)}`);

      logger.success(
        `IDP interaction confirm session: ${JSON.stringify(
          req.session,
          null,
          2
        )}`
      );

      if (!req.session.authorizations) {
        req.session.authorizations = {};
      }
      req.session.authorizations[params.client_id] = true; // Track the authorized client

      // ✅ Store session for each SP
      sessionStore.set(accountId, req.sessionID);
      logger.success(`Stored session for  ${accountId} -> ${req.sessionID}`);

      // Complete the interaction with consent
      await provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: true,
      });
    } catch (err) {
      next(err);
    }
  });

  app.get("/interaction/:uid/abort", setNoCache, async (req, res, next) => {
    try {
      logger.info(`Entering to interaction/${uid}/abort ENDPOINT!`);
      const result = {
        error: "access_denied",
        error_description: "End-User aborted interaction",
      };

      // Notify client that the interaction was aborted
      await provider.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (err) {
      next(err);
    }
  });

  // To check current session
  app.get("/debug-session", (req, res) => {
    res.json({
      cookies: req.cookies,
      session: req.session,
    });
  });

  app.get("/profile", setNoCache, async (req, res, next) => {
    try {
      const session = req.session; // Fetch session data
      logger.success(`profile : ${JSON.stringify(session, null, 2)}`);
      return res.send({ status: "success", profile: session });
    } catch (err) {
      next(err);
    }
  });

  // Find the SP Account ID from sessionStore and use for BackChannel logout!
  async function findSessionByAccountId(accountId, req) {
    const sessionID = sessionStore.get(accountId);
    if (!sessionID) {
      console.error(`No session found for accountId: ${accountId}`);
      return null;
    }

    // Retrieve session from express-session store
    return new Promise((resolve, reject) => {
      req.sessionStore.get(sessionID, (err, session) => {
        if (err || !session) {
          console.error("Session retrieval failed:", err);
          return resolve(null);
        }
        resolve(session);
      });
    });
  }

  // User initiated logout
  app.post("/logout", setNoCache, async (req, res, next) => {
    try {
      logger.success("Logout request received at IDP");

      const idTokenHint = req.body?.id_token_hint;
      let accountId, clientName, postLogoutRedirectUri;
      let session = req.session;

      if (idTokenHint) {
        const decodedToken = jwt.decode(idTokenHint);
        console.log("Decoded token:", decodedToken);
        clientName = decodedToken?.aud;

        if (!clientName)
          return res.status(400).send("Missing aud in id_token_hint.");
        else console.log("Extracted clientId from id_token_hint:", clientName);

        const clientData = await provider.Client.find(clientName);
        if (!clientData) return res.status(404).send("Client not found.");
        else postLogoutRedirectUri = clientData?.postLogoutRedirectUris[0];

        if (!postLogoutRedirectUri) postLogoutRedirectUri = null;

        if (!decodedToken?.sub) {
          return res.status(400).send("Invalid id_token_hint.");
        }
        accountId = decodedToken.sub;
        console.log("Extracted accountId from id_token_hint:", accountId);

        // 🔹 Try retrieving session if missing
        if (!session || !session.authorizations) {
          logger.warn(
            "❌ No session found, reterving clients from sessionStore ⚠️"
          );
          session = await findSessionByAccountId(accountId, req);
          console.log("function ", session);
          if (!session) {
            logger.error("No active session found for backchannel logout.");
            return res
              .status(400)
              .send("No active session for backchannel logout.");
          }
        }
      } else if (session?.idp?.data?.accountId) {
        accountId = session.idp.data.accountId;
        console.log("Using accountId from session:", accountId);
      } else {
        return res
          .status(400)
          .send("No valid id_token_hint or active session found.");
      }

      //  Notify SPs about backchannel logout
      const clients = Object.keys(session.authorizations || {});
      console.log("Authorized clients:", clients);

      //  Notify SPs about backchannel logout
      for (const clientId of clients) {
        const client = await provider.Client.find(clientId);
        console.log(`Client loop: ${clientId}`, client);

        if (!client) {
          console.error(`❌ Client ${clientId} not found! Skipping...`);
          continue;
        }

        const backchannelLogoutUri = client?.backchannelLogoutUri;
        console.log(
          `Backchannel logout URI for ${clientId}:`,
          backchannelLogoutUri
        );

        if (backchannelLogoutUri) {
          logger.warn(
            `Sending logout request to SP (${clientId}) at ${backchannelLogoutUri}`
          );

          const logoutToken = new provider.IdToken(
            {
              iss: process.env.IDP_URL,
              sub: accountId,
              aud: client?.clientId,
              iat: Math.floor(Date.now() / 1000),
            },
            { client }
          );

          logoutToken.mask = { sub: null };
          if (client?.backchannelLogoutSessionRequired) {
            logoutToken.set("sid", session?.id);
          }

          logoutToken.set("events", {
            "http://schemas.openid.net/event/backchannel-logout": {},
          });
          logoutToken.set("exp", Math.floor(Date.now() / 1000) + 60);
          logoutToken.set("jti", nanoid());

          const issuedLogoutToken = await logoutToken.issue({ use: "logout" });
          console.log(
            `🔑 Generated logout token for ${clientId}:`,
            issuedLogoutToken
          );

          try {
            const response = await axios.post(
              backchannelLogoutUri,
              { logout_token: issuedLogoutToken },
              {
                headers: {
                  "Content-Type": "application/json",
                },
                withCredentials: true,
              }
            );

            logger.success(`✅ SP (${clientId}) successfully logged out`);
            console.log(
              `SP (${clientId}) Response:`,
              response.status,
              response.data
            );
          } catch (error) {
            console.error(
              `❌ Error sending backchannel logout to SP (${clientId}): ${error.message}`
            );
          }
        }
      }
      // ✅ Destroy only the IDP session
      req.sessionStore.all((err, sessions) => {
        if (err) {
          console.error("❌ Error retrieving sessions:", err);
          return res.status(500).send("Failed to retrieve session.");
        }

        // Find the IDP session where `accountId` matches
        const sessionEntry = Object.entries(sessions).find(
          ([sessionId, session]) => {
            return session?.idp?.data?.accountId === accountId;
          }
        );

        if (!sessionEntry) {
          console.warn(`⚠️ No active session found for user: ${accountId}`);
          return res.status(200).send("No active session found.");
        }

        const sessionId = sessionEntry[0];
        console.log(`✅ Found IDP session for ${accountId}: ${sessionId}`);

        // Destroy the IDP session
        req.sessionStore.destroy(sessionId, (err) => {
          if (err) {
            console.error("❌ Error destroying session:", err);
            return res.status(500).send("Failed to terminate session.");
          }

          console.log("✅ IDP session successfully destroyed!");

          // ✅ Clear cookies manually to remove traces of authentication
          if (req.cookies && Object.keys(req.cookies).length > 0) {
            Object.keys(req.cookies).forEach((cookie) => {
              res.clearCookie(cookie, {
                path: "/",
                secure: true,
                httpOnly: true,
                sameSite: "None",
              });
              console.log("✅ Cleared cookie:", cookie);
            });
          } else {
            console.warn("⚠️ No cookies found to clear.");
          }

          console.log("✅ IDP Session Successfully Destroyed.");

          const baseRedirectUrl = `${process.env.APP_LOGIN_URL}/session/end/`;
          const finalRedirectUrl = postLogoutRedirectUri
            ? `${baseRedirectUrl}?redirect_uri=${encodeURIComponent(
                postLogoutRedirectUri
              )}`
            : baseRedirectUrl;
          return res.status(200).json({
            redirect: finalRedirectUrl,
          });
        });
      });
    } catch (err) {
      console.error("Error during IDP logout:", err.message);
      next(err);
    }
  });
};
