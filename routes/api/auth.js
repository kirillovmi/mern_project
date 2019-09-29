const express = require("express");
const router = express.Router();
const auth = require("../../middleware/auth");
const User = require("../../models/User");
const {check, validationResult} = require("express-validator/check");
const jwt = require("jsonwebtoken");
const config = require("config");
const bcrypt = require("bcryptjs");

//@route    GET api/auth
//@desc     Get authenticated user's data
//@access   Public

router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        res.json(user);
    } catch(error) {
        console.error(error.message);
        res.status(500).json("Server errror");
    }
});

//@route    POST api/auth
//@desc     Authenticate user & get token
//@access   Public

router.post('/', [
    check("email", "Please include a valid mail").isEmail(),
    check("password", "Password is required").exists()
], async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }

    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });

        //If user already exist
        if(!user) {
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch) {
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
        }

        const payload = {
            user: {
                id: user.id
            }
        };

        //Return jsonwebtoken
        jwt.sign(payload, config.get("jwtSecret"), {expiresIn: 360000}, (error, token) => {
            if(error) throw error;
            res.json({token});
        });

    } catch(error) {
        console.error(error.message);
        res.status(500).send("Server error");
    }
});

module.exports = router;