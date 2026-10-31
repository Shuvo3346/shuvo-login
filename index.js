const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

admin.initializeApp({
  databaseURL: "https://login-app-36cb6-default-rtdb.firebaseio.com/"
});

const db = admin.database();

const ADMIN_UID = "YujMTvlEMOcraN1he3KksH68D1G2";
const MAIN_UID = "LIoHD7oowDeR7V55tlB2Y5EEw4i1";

const PATH = "loginControl";

async function getUser(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    throw new Error("MISSING_TOKEN");
  }

  return await admin.auth().verifyIdToken(header.substring(7));
}

exports.api = onRequest(
  { invoker: "public", maxInstances: 3 },
  async (req, res) => {
    res.set("Content-Type", "application/json");
    res.set("Cache-Control", "no-store");

    if (req.method !== "POST") {
      return res.status(405).json({
        success: false,
        error: "METHOD_NOT_ALLOWED"
      });
    }

    let user;

    try {
      user = await getUser(req);
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: "INVALID_AUTHENTICATION"
      });
    }

    try {
      const body = req.body || {};
      const action = body.action;

      // MAIN APP LOGIN VERIFICATION
      if (action === "verifyAccess") {
        if (user.uid !== MAIN_UID) {
          return res.status(403).json({
            success: false,
            error: "UNAUTHORIZED"
          });
        }

        const snapshot = await db.ref(PATH).get();
        const config = snapshot.val() || {};

        if (config.active !== true) {
          return res.status(403).json({
            success: false,
            error: "LOGIN_DISABLED"
          });
        }

        const expiry = Number(config.expiry || 0);

        if (expiry > 0 && Date.now() > expiry) {
          return res.status(403).json({
            success: false,
            error: "EXPIRED"
          });
        }

        return res.json({
          success: true,
          message: "LOGIN_SUCCESS"
        });
      }

      // ADMIN AUTHORIZATION
      if (user.uid !== ADMIN_UID) {
        return res.status(403).json({
          success: false,
          error: "ADMIN_ONLY"
        });
      }

      // CHANGE MAIN APP PASSWORD
      if (action === "changePassword") {
        const password = String(body.password || "");

        if (password.length < 8) {
          return res.status(400).json({
            success: false,
            error: "PASSWORD_TOO_SHORT"
          });
        }

        await admin.auth().updateUser(MAIN_UID, {
          password: password
        });

        return res.json({
          success: true,
          message: "PASSWORD_UPDATED"
        });
      }

      // ENABLE OR DISABLE LOGIN
      if (action === "setActive") {
        if (typeof body.active !== "boolean") {
          return res.status(400).json({
            success: false,
            error: "INVALID_ACTIVE_VALUE"
          });
        }

        await db.ref(PATH).update({
          active: body.active
        });

        return res.json({
          success: true,
          message: "STATUS_UPDATED"
        });
      }

      // SET EXPIRY TIME
      if (action === "setExpiry") {
        const expiry = Number(body.expiry);

        if (!Number.isSafeInteger(expiry) || expiry < 0) {
          return res.status(400).json({
            success: false,
            error: "INVALID_EXPIRY"
          });
        }

        await db.ref(PATH).update({
          expiry: expiry
        });

        return res.json({
          success: true,
          message: "EXPIRY_UPDATED"
        });
      }

      return res.status(400).json({
        success: false,
        error: "UNKNOWN_ACTION"
      });

    } catch (error) {
      console.error("Function error:", error);

      return res.status(500).json({
        success: false,
        error: "SERVER_ERROR"
      });
    }
  }
);
