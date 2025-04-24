const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
// Support both GET and POST for logout (POST is preferred as it contains the refresh token)
router.get('/logout', authController.logout);
router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);
router.put('/preferences', authController.updatePreferences);
router.post('/lists', authController.updateLists);

module.exports = router;