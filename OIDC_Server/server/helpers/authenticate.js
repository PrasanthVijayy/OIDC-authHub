"use strict";
import { connectToAD } from "../config/adConfig.js";
import logger from "../config/logger.js";

const authenticate = async (username, password) => {
  logger.warn("Initiating authentication process...");
  logger.info(`Authenticating user: ${username}`);
  const adInstance = await connectToAD();

  return new Promise((resolve, reject) => {
    adInstance.authenticate(username, password, (err, auth) => {
      if (err) {
        logger.error(`Authentication failed for user: ${username}`);
        if (
          // err.message.includes(
          //   "80090308: LdapErr: DSID-0C09044B, comment: AcceptSecurityContext error, data 52e, v3839\x00"
          // )
          err.message.includes("InvalidCredentialsError")
        ) {
          reject(new Error("Invalid credentials"));
        } else if (
          err.message.includes(
            "InvalidCredentialsError: 80090308: LdapErr: DSID-0C09044B, comment: AcceptSecurityContext error, data 775, v3839"
          )
        ) {
          reject(new Error("Account Locked, Contact Admin!"));
        } else {
          reject(err);
        }
      }
      if (auth) {
        logger.success(`Authentication successful for user: ${username}`);
        resolve({ user: { name: username } });
      } else {
        reject(new Error("Invalid credentials"));
      }
    });
  });
};

const findUser = async (userPrincipalName) => {
  logger.warn("Initiating user details fetch process...");
  logger.info(`[AD] Starting to fetch user details for: ${userPrincipalName}`);
  try {
    const adInstance = await connectToAD();
    return new Promise((resolve, reject) => {
      adInstance.findUser(userPrincipalName, (err, user) => {
        if (err) {
          logger.error(`[AD] Failed to fetch user details: ${err.message}`);
          reject(new Error("User not found"));
        } else if (!user) {
          logger.error("[AD] No user details returned");
          reject(new Error("User not found"));
        } else {
          logger.info(
            `[AD] User details fetched successfully: ${JSON.stringify(
              user,
              null,
              2
            )}`
          );
          resolve(user);
        }
      });
    });
  } catch (error) {
    logger.error(`Error finding user in AD: ${error.message}`);
    throw error;
  }
};

export { authenticate, findUser };
