const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validateUser, validateUserLogin, } = require('../middleware/validator');
const sendEmail = require('../email');
const { generateDynamicEmail } = require('../emailText');
const { resetFunc } = require('../forgot');
const resetHTML = require('../resetHTML');
require('dotenv').config();

//Function to register a new user
const signUp = async (req, res) => {
    try {
        const { error } = validateUser(req.body);
        if (error) {
            return res.status(500).json({
                message: error.details[0].message
            })
        } else {
            const { firstName, lastName, userName, phoneNumber, email, password } = req.body;
            const emailExists = await userModel.findOne({ email: email.toLowerCase() });
            if (emailExists) {
                return res.status(200).json({
                    message: 'Email already exists',
                })
            }
            const salt = bcrypt.genSaltSync(12)
            const hashpassword = bcrypt.hashSync(password, salt);
            const user = await new userModel({
                firstName: firstName,
                lastName: lastName,
                userName: userName,
                phoneNumber: phoneNumber,
                email: email.toLowerCase(),
                password: hashpassword,
            });
            if (!user) {
                return res.status(404).json({
                    message: 'User not found',
                })
            }
            const token = jwt.sign({
                firstName,
                lastName,
                email,
            }, process.env.secret, { expiresIn: "120s" });
            user.token = token;
            const subject = 'Email Verification'
            //jwt.verify(token, process.env.secret)
            const link = `${req.protocol}://${req.get('host')}/api/v1/verify/${user.id}/${user.token}`
            const html = generateDynamicEmail(firstName, link)
            sendEmail({
                email: user.email,
                html,
                subject
            })
            await user.save()
            return res.status(200).json({
                message: 'User profile created successfully',
                data: user,
            })

        }
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error: " + err.message,
        })
    }
};


//Function to verify a new user with a link
const verify = async (req, res) => {
    try {
        const id = req.params.id;
        const token = req.params.token;
        const user = await userModel.findById(id);

        // Verify the token
        jwt.verify(token, process.env.secret);

        // Update the user if verification is successful
        const updatedUser = await userModel.findByIdAndUpdate(id, { isVerified: true }, { new: true });

        if (updatedUser.isVerified === true) {
            return res.status(200).send("You have been successfully verified. Kindly visit the login page.");
        }

    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            // Handle token expiration
            const id = req.params.id;
            const updatedUser = await userModel.findById(id);
            const { firstName, lastName, email } = updatedUser;
            const newtoken = jwt.sign({ email, firstName, lastName }, process.env.secret, { expiresIn: "120s" });
            updatedUser.token = newtoken;
            updatedUser.save();

            const link = `${req.protocol}://${req.get('host')}/api/v1/verify/${id}/${updatedUser.token}`;
            sendEmail({
                email: email,
                html: generateDynamicEmail(firstName, link),
                subject: "RE-VERIFY YOUR ACCOUNT"
            });
            return res.status(401).send("This link is expired. Kindly check your email for another email to verify.");
        } else {
            return res.status(500).json({
                message: "Internal server error: " + err.message,
            });
        }
    }
};


//Function to login a verified user
const logIn = async (req, res) => {
    try {
        const { error } = validateUserLogin(req.body);
        if (error) {
            return res.status(500).json({
                message: error.details[0].message
            })
        } else {
            const { email, password } = req.body;
            const checkEmail = await userModel.findOne({ email: email.toLowerCase() });
            if (!checkEmail) {
                return res.status(404).json({
                    message: 'User not registered'
                });
            }
            const checkPassword = bcrypt.compareSync(password, checkEmail.password);
            if (!checkPassword) {
                return res.status(404).json({
                    message: "Password is incorrect"
                })
            }
            const token = jwt.sign({
                userId: checkEmail._id,
                email: checkEmail.email,
            }, process.env.secret, { expiresIn: "1h" });

            if (checkEmail.isVerified === true) {
                res.status(200).json({
                    message: "Welcome " + checkEmail.userName,
                    token: token
                })
                checkEmail.token = token;
                await checkEmail.save();
            } else {
                res.status(400).json({
                    message: "Sorry user not verified yet."
                })
            }
        }

    } catch (err) {
        return res.status(500).json({
            message: "Internal server error: " + err.message,
        });
    }
};

//Function for the user incase password is forgotten
const forgotPassword = async (req, res) => {
    try {
        const checkUser = await userModel.findOne({ email: req.body.email });
        if (!checkUser) {
            return res.status(404).json({
                message: 'Email does not exist'
            });
        }
        else {
            const subject = 'Kindly reset your password'
            const link = `${req.protocol}://${req.get('host')}/api/v1/reset/${checkUser.id}`
            const html = resetFunc(checkUser.firstName, link)
            sendEmail({
                email: checkUser.email,
                html,
                subject
            })
            return res.status(200).json({
                message: "Kindly check your email to reset your password",
            })
        }
    } catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error: ' + err.message,
        })
    }
};

//Funtion to send the reset Password page to the server
const resetPasswordPage = async (req, res) => {
    try {
        const userId = req.params.userId;
        const resetPage = resetHTML(userId);

        // Send the HTML page as a response to the user
        res.send(resetPage);
    } catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error: ' + err.message,
        });
    }
};



//Function to reset the user password
const resetPassword = async (req, res) => {
    try {
        const userId = req.params.userId;
        const password = req.body.password;

        if (!password) {
            return res.status(400).json({
                message: "Password cannot be empty",
            });
        }

        const salt = bcrypt.genSaltSync(12);
        const hashPassword = bcrypt.hashSync(password, salt);

        const reset = await userModel.findByIdAndUpdate(userId, { password: hashPassword }, { new: true });
        return res.status(200).json({
            message: "Password reset successfully",
        });
    } catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error: ' + err.message,
        })
    }
};

//Function to signOut a user
const signOut = async (req, res) => {
    try {
        const userId = req.params.userId
        const user = await userModel.findById(userId)

        user.token = null;
        await user.save();
        res.status(201).json({
            message: `user has been signed out successfully`
        })
    }
    catch (error) {
        res.status(500).json({
            message: 'Internal Server Error: ' + err.message,
        })
    }
}



module.exports = {
    signUp,
    verify,
    logIn,
    forgotPassword,
    resetPasswordPage,
    resetPassword,
    signOut,

}