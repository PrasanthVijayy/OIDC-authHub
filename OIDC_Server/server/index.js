import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import https from "https";
import morgan from "morgan";
import dotenv from "dotenv";
import express from "express";
import Provider from "oidc-provider";
import logger from "../server/config/logger.js";
import session from "express-session";
import helmet from "helmet";
import hpp from "hpp";
import cors from "cors";
import corn from "node-cron";
import configuration from "../server/config/idpConfig.js";
import { renderRoutes } from "../server/routes/idpRoutes.js";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();

app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet());
app.use(hpp());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* ---------- SSL SETUP ---------- */

const privateKeyPath = path.join(
  __dirname,
  "../Certificates/SSL_certificate/private.key"
);
const certificatePath = path.join(
  __dirname,
  "../Certificates/SSL_certificate/certificate.crt"
);

const privateKeys = fs.readFileSync(privateKeyPath, "utf8");
const certificate = fs.readFileSync(certificatePath, "utf8");

const credentials = {
  key: privateKeys,
  cert: certificate,
  passphrase: process.env.SSL_PASSPHRASE,
};

/* ---------- CRON JOB SETUP - SERVER TIMESTAMP ---------- */
corn.schedule("*/10 * * * *", () => {
  console.log(
    "Monitoring server: ",
    new Date(),
    " Minutes:  ",
    new Date().getMinutes()
  );
});

/* ---------- EXPRESS SESSION SETUP ---------- */

const corsOptions = {
  origin: process.env.ALLOWED_ORIGIN,
  methods: process.env.ALLOWED_METHODS,
  allowedHeaders: process.env.ALLOWED_HEADERS,
  credentials: process.env.ALLOWED_CREDENTIALS,
};
app.use(cors(corsOptions));

app.set("trust proxy", 1);

global.sessionStore = new Map(); // To track!
app.use(
  session({
    name: "server-session",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "None",
      path: "/",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);


/* ---------- SECURITY SETUP ---------- */

logger.info(`CORS SETUP: ${JSON.stringify(corsOptions, null, 2)}`);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "script-src-attr": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "form-action": ["*"],
      },
    },
  })
);

/* ---------- SERVER SETUP ---------- */

const PORT = 4000;
/*  1️⃣ Get IDP URL from ENV if present, else default to localhost with PORT mentioned.
 2️⃣ If CONFIRM_WEBSERVER is true, use the APP_LOGIN_URL as
 3️⃣ If APP_LOGIN_URL is not empty, append the PORT to it.  */

const IDP_URL =
  process.env.CONFIRM_WEBSERVER === "true" // set CONFIRM_WEBSERVER to true
    ? process.env.APP_LOGIN_URL
    : process.env.APP_LOGIN_URL_IP
      ? `${process.env.APP_LOGIN_URL_IP}:${PORT}`
      : `https://localhost:${PORT}`;

// const IDP_URL = `https://localhost:${PORT}`;
console.log("IDP_URL", IDP_URL);

// Create OIDC provider instance
const provider = new Provider(IDP_URL, { ...configuration });

provider.proxy = true; // HTTPS discovery setup

renderRoutes(app, provider);
provider.use(async (ctx, next) => {
  ctx.session = ctx.req.session;
  return next();
});
app.use(provider.callback());
//⚠️ set SELF_SIGNED to true and CONFIRM_WEBSERVER as false to use HTTPS (self signed) ⚠️
if (
  process.env.SELF_SIGNED === "true" &&
  process.env.CONFIRM_WEBSERVER === "false"
) {
  logger.warn("Running in HTTPS with SELF SIGNED CERT...");
  https.createServer(credentials, app).listen(PORT, "0.0.0.0", () => {
    logger.success(`Server started and listening on https://localhost:${PORT}`);
    logger.success(`Server running with machine IP: ${IDP_URL}`);
    logger.success(
      `Endpoint list: ${IDP_URL}/.well-known/openid-configuration`
    );
  });
}

/* ---------- SERVER SETUP WITHOUT SSL ---------- */
if (
  typeof process.env.SELF_SIGNED !== "undefined" && // set SELF_SIGNED to false
  process.env.SELF_SIGNED !== "true"
) {
  app.listen(PORT, "0.0.0.0", () => {
    logger.warn("Running in HTTP...");
    logger.success(`Server started and listening on http://localhost:${PORT}`);
    logger.success(`Server running with machine IP: ${IDP_URL}`);
    logger.success(
      `Endpoint list: ${IDP_URL}/.well-known/openid-configuration`
    );
  });
}
