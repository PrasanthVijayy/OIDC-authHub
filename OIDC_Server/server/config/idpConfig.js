"use strict";
import dotenv from "dotenv";
import { findUser } from "../helpers/authenticate.js";
import logger from "./logger.js";

dotenv.config();

export default {
  clients: [
    {
      client_id: process.env.CLIENT_ID_1,
      client_secret: process.env.CLIENT_SECRET_1,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: [process.env.REDIRECT_URI_1],
      backchannel_logout_uri: process.env.BACKCHANNEL_LOGOUT_1,
      backchannel_logout_session_required: true,
      post_logout_redirect_uris: [process.env.POST_LOGOUT_REDIRECT_URI_1],
    },
    {
      client_id: process.env.CLIENT_ID_2,
      client_secret: process.env.CLIENT_SECRET_2,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: [process.env.REDIRECT_URI_2],
      backchannel_logout_uri: process.env.BACKCHANNEL_LOGOUT_2,
      backchannel_logout_session_required: true,
      post_logout_redirect_uris: [process.env.POST_LOGOUT_REDIRECT_URI_2],
    },
    {
      client_id: process.env.CLIENT_ID_3,
      client_secret: process.env.CLIENT_SECRET_3,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: [process.env.REDIRECT_URI_3],
      backchannel_logout_uri: process.env.BACKCHANNEL_LOGOUT_3,
      backchannel_logout_session_required: true,
      post_logout_redirect_uris: [process.env.POST_LOGOUT_REDIRECT_URI_3],
    },
    {
      client_id: process.env.CLIENT_ID_4,
      client_secret: process.env.CLIENT_SECRET_4,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: [process.env.REDIRECT_URI_4],
      backchannel_logout_uri: process.env.BACKCHANNEL_LOGOUT_4,
      backchannel_logout_session_required: true,
      // post_logout_redirect_uris: [process.env.POST_LOGOUT_REDIRECT_URI_4],
    },
  ],
  interactions: {
    url(ctx, interaction) {
      console.warn("Interaction uid: ", interaction.uid);
      console.warn("Session data during interaction:", ctx.session);
      return `/interaction/${interaction.uid}`;
    },
  },

  cookies: {
    keys: ["your-strong-key-1", "your-strong-key-2"],
  },

  claims: {
    address: ["address"],
    email: ["email", "email_verified"],
    phone: ["phone_number", "phone_number_verified"],
    profile: [
      "birthdate",
      "family_name",
      "gender",
      "given_name",
      "locale",
      "middle_name",
      "name",
      "nickname",
      "picture",
      "preferred_username",
      "profile",
      "updated_at",
      "website",
      "zoneinfo",
    ],
  },

  features: {
    introspection: { enabled: true },
    revocation: { enabled: true },
    devInteractions: { enabled: false },
    backchannelLogout: { enabled: true },
    rpInitiatedLogout: {
      enabled: true,
      logoutSource: async (ctx, form) => {
        ctx.oidc.session.destroy(); // ✅ Force clear session
        const redirectUri = ctx.query.redirect_uri;

        if (redirectUri) {
          logger.success(`Redirecting to SP postLogout URL: ${redirectUri}`);
          return ctx.redirect(redirectUri);
        }
        logger.error(
          `❌ No post_logout_redirect_uri found for SP, rendering default page!`
        );
        ctx.body = `<!DOCTYPE html>
          <html>
            <body>
              <H1>Back channel logout initiated...</H1>
              <p> Check other SP's for logout status!</p>
            </body>
          </html>`;
      },
    },
  },

  ttl: {
    AccessToken: 3600, // 1 hour
    AuthorizationCode: 600, // 10 minutes
    IdToken: 3600, // 1 hour
    RefreshToken: 604800, // 1 week
    DeviceCode: 600, // 10 minutes
    Grant: (ctx, grant) => {
      if (grant?.scope?.includes("offline_access")) {
        return 24 * 60 * 60; // 1 day
      }
      return 24 * 60 * 60; // Default 1 day
    },
    Session: (ctx, session) => {
      if (session?.accountId) {
        return 24 * 60 * 60; // 1 day
      }
      return 12 * 60 * 60; // Default 12 hours
    },
    Interaction: (ctx, interaction) => {
      // Set interaction TTL (e.g., 10 minutes)
      return 10 * 60; // 10 minutes
    },
  },

  findAccount: async (ctx, id) => {
    const session = ctx.req.session;
    // Check if claim already present in session and return it
    if (session?.claims?.[id]) {
      console.log("Returning existing claims from session for:", id);
      return {
        accountId: id,
        claims: async () => session.claims[id],
      };
    } else {
      const user = await findUser(id);
      if (!user) return null;

      const userClaims = {
        sub: id,
        name: user?.sAMAccountName || "guest name",
        email: user?.userPrincipalName || "guest@gmail.com",
        given_name: user?.givenName || "guest",
      };

      session.claims = { ...session.claims, [id]: userClaims }; // Store user claims in session
      console.log("session of claim", session);
      return {
        accountId: id,
        claims: async () => userClaims, // Return user claims
      };
    }
  },
  jwks: {
    keys: [
      {
        d: "VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ",
        dp: "E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0",
        dq: "F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc",
        e: "AQAB",
        kty: "RSA",
        n: "xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ",
        p: "5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM",
        q: "3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M",
        qi: "wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU",
        use: "sig",
      },
      {
        crv: "P-256",
        d: "K9xfPv773dZR22TVUB80xouzdF7qCg5cWjPjkHyv7Ws",
        kty: "EC",
        use: "sig",
        x: "FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4",
        y: "_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4",
      },
    ],
  },
};
