# OIDC-APP: A Common Platform for Identity Provider (IDP) & Service Provider (SP) Interaction in OIDC Protocol

## Overview

This project simulates an OpenID Connect (OIDC) flow where a custom-built Identity Provider (IDP) communicates with two separate Service Providers (SPs). The IDP handles authentication and authorization, while the SPs integrate with the IDP for user login and token generation through OAuth 2.0 and OIDC protocols.

The main objective of this repository is to understand and experiment with how an IDP interacts with multiple SPs, handling login flows, token issuance (JWT), and user authentication, along with an example of a cross-domain setup.

## Key Features

- **Custom Identity Provider (IDP)**: A custom-built IDP that supports OIDC flows, OAuth token issuance, and integration with Active Directory (AD).
- **Multiple Service Providers (SPs)**: Two separate SP applications (`SP1` and `SP2`), both integrating with the IDP for user authentication and token management.
- **Cross-Domain Setup**: Demonstrates OAuth integration across domains (IDP and SPs reside on different domains).
- **PKCE Support**: Implements PKCE (Proof Key for Code Exchange) to enhance security for public clients (SPs) in the OAuth flow.
- **JWT Token Generation**: The IDP generates JWT tokens for SPs after successful user authentication.
- **AD Integration**: The IDP integrates with Active Directory (AD) for user authentication and management.
- **SSO Implementation**: SSO (Single Sign-On) implementation added, allowing users to bypass authentication when accessing other SPs after the initial SP authentication.
- **Back Channel Logout**: Supports back-channel logout for securely terminating user sessions on both the IDP and SPs upon logout initiation from the IDP.

## How It Works

1. **Service Provider Initialization**:
   - Multiple SP applications are configured to communicate with the IDP to initiate OAuth authorization flows.
   - When a user tries to access a protected resource on either SP, they are redirected to the IDP for authentication.

2. **IDP Authentication Flow**:
   - The IDP authenticates the user via integration with Active Directory (AD) during the IDP interaction session.
   - Once authenticated, the IDP generates a JWT token, which is sent back to the SP.

3. **OAuth Token Flow**:
   - The SPs validate the received JWT token for authenticity and security.
   - Using the token, SPs can provide access to protected resources based on user identity and roles.

4. **Cross-Domain OAuth**:
   - Since the client applications are on different domains than the IDP, this setup demonstrates the handling of cross-domain authentication using OAuth.

5. **SSO (Single Sign-On) Implementation**:
   - Once a user authenticates with the IDP during their first interaction with any of the SPs, they can seamlessly access other SPs without needing to authenticate again. The authentication token is shared across the SPs, enabling SSO functionality.

6. **Back Channel Logout**:
   - The IDP supports back-channel logout functionality, which allows it to securely notify all SPs when a user logs out. This ensures that user sessions are properly terminated both on the IDP and SPs, maintaining security and preventing unauthorized access to protected resources.

## Setup Instructions

### 1. Create Directory

```bash
cd OIDC-APP
```

### 2. Clone the Repository

```bash
git clone https://github.com/PrasanthVijayy/OIDC-authHub.git
```

### 3. Add values to your `.env` file by referring to the [App Config file](/OIDC_Server/server/config/appConfig.js)

### 4. Load the npm packages:

```bash
npm i
```

### 5. Before starting the application:
   - Make sure you have an `Nginx` file.
   - If you don't have an `Nginx` file, set `CONFIRM_WEBSERVER=false` & `SELF_SIGNED=true` in the `.env` file.

### 6. Run the application:

```bash
npm start
```

