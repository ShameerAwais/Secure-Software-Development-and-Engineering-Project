const express = require("express");
const router = express.Router();
const urlController = require("../controllers/urlController");

// Public route to check URL safety
router.post("/check", urlController.checkUrlSafety);

// Route for user-specific URL check (uses allow/block lists & saves to history)
router.post("/user-check", urlController.checkURL);

// Legacy route to get URL safety history (empty for non-auth users)
router.get("/history", urlController.getUrlHistory);

// User-specific URL history routes
router.get("/user-history", urlController.getUserHistory);
router.post("/user-action", urlController.updateUserAction);
router.get("/user-stats", urlController.getUserStats);

module.exports = router;
