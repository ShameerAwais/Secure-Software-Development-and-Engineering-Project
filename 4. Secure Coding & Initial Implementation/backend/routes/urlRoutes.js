const express = require("express");
const router = express.Router();
const urlController = require("../controllers/urlController");

// Route to check URL safety
router.post("/check", urlController.checkUrlSafety);

// Route to get URL safety history
router.get("/history", urlController.getUrlHistory);

module.exports = router;
