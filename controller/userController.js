const UserModel = require('../model/userModel.js');
const fs = require('fs');
require(`dotenv`)
const bcrypt = require(`bcrypt`)
const jwt = require(`jsonwebtoken`)
const sendMail = require(`../helpers/email.js`)
const {signUpTemplate, verifyTemplate, forgotPasswordTemplate} = require(`../helpers/html.js`)

exports.signUp = async (req, res) => {
    try {
        // check if user exists
        const { fullName, email, password } = req.body;
        const emailExist = await UserModel.findOne({email})
        if (emailExist) {
            return res.status(400).json(`User with email already exist`)
        } else {
        //perform an encryption using salt
        const saltedPassword = await bcrypt.genSalt(10)
        //perform an encrytion of the salted password
        const hashedPassword = await bcrypt.hash(password, saltedPassword)
        // create object of the body
        const user = new UserModel({
            fullName,
            email,
            password: hashedPassword,
            image: req.file.filename
        })

        user.cohort = "cohort 4"
        const userToken = jwt.sign({id:user._id,email:user.email},process.env.jwt_secret,{expiresIn: "3 Minutes"})
        const verifyLink=  `${req.protocol}://${req.get("host")}/api/v1/user/verify/${userToken}`
    
            await user.save()
            await sendMail({ subject : `Kindly Verify your mail`,
            email:user.email,
            html: signUpTemplate(verifyLink,user.fullName)})
        res.status(201).json({
            message: `Welcome ${user.fullName} kindly check your gmail to access the link to verify your email`,
            data: user
        })}
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.verifyEmail = async (req, res) => {
    try {
        // Extract the token from the request params
        const { token } = req.params;
        // Extract the email from the verified token
        const { email } = jwt.verify(token, process.env.jwt_secret);
        // Find the user with the email
        const user = await UserModel.findOne({ email });
        // Check if the user is still in the database
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }
        // Check if the user has already been verified
        if (user.isVerified) {
            return res.status(400).json({
                message: 'User already verified'
            })
        }
        // Verify the user
        user.isVerified = true;
        // Save the user data
        await user.save();
        // Send a success response
        res.status(200).json({
            message: 'User verified successfully'
        })

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.json({ message: 'Link expired.' })
        }
        res.status(500).json({
            message: error.message
        })
    }
}


exports.loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        const existingUser = await UserModel.findOne({ email: email.toLowerCase() });
        if (!existingUser) {
            return res.status(404).json({
                message: 'User not found'
            })
        }

        const confirmPassword = await bcrypt.compare(password, existingUser.password);
        if (!confirmPassword) {
            return res.status(404).json({
                message: 'Incorrect Password'
            })
        }
        if (!existingUser.isVerified) {
            return res.status(400).json({
                message: 'User not verified, Please check you email to verify your account.'
            })
        }

        const token = await jwt.sign({
            userId: existingUser._id,
            email: existingUser.email
        }, process.env.jwt_secret, { expiresIn: '1h' })

        res.status(200).json({
            message: 'Login successfully',
            data: existingUser,
            token
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.resendVerificationEmail = async (req, res) => {
    try {
        const { email } = req.body;
        // Find the user with the email
        const user = await UserModel.findOne({ email });
        // Check if the user is still in the database
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }

        // Check if the user has already been verified
        if (user.isVerified) {
            return res.status(400).json({
                message: 'User already verified'
            })
        }

        const token = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: '20mins' });
        const verifyLink = `${req.protocol}://${req.get('host')}/api/v1/user/verify/${token}`
        let mailOptions = {
            email: user.email,
            subject: 'Verification email',
            html: verifyTemplate(verifyLink, user.fullName),
        }
        // Send the the email
        await sendMail(mailOptions);
        // Send a success message
        res.status(200).json({
            message: 'Verification email resent successfully'
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.forgotPassword = async (req, res) => {
    try {
        // Extract the email from the request body
        const { email } = req.body;

        // Check if the email exists in the database
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

         // Generate a reset token
         const resetToken = jwt.sign({ email: user.email }, process.env.jwt_secret, { expiresIn: "30m" });
         const resetLink = `${req.protocol}://${req.get("host")}/api/v1/user/reset-password/${resetToken}`
 
         // Send reset password email
         const mailOptions = {
             email: user.email,
             subject: "Password Reset",
             html: forgotPasswordTemplate(resetLink, user.fullName),
         };
        //   Send the email
        await sendMail(mailOptions);
        //   Send a success response
        res.status(200).json({
            message: "Password reset email sent successfully."
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // Verify the user's token and extract the user's email from the token
        const { email } = jwt.verify(token, process.env.jwt_secret);

        // Find the user by ID
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Salt and hash the new password
        const saltedRound = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, saltedRound);

        // Update the user's password
        user.password = hashedPassword;
        // Save changes to the database
        await user.save();
        // Send a success response
        res.status(200).json({
            message: "Password reset successful"
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
};

exports.changePassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password, existingPassword } = req.body;

        // Verify the user's token and extract the user's email from the token
        const { email } = jwt.verify(token, process.env.jwt_secret);

        // Find the user by ID
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Confirm the previous password
        const isPasswordMatch = await bcrypt.compare(existingPassword, user.password);
        if (!isPasswordMatch) {
            return res.status(401).json({
                message: "Existing password does not match"
            });
        }

        // Salt and hash the new password
        const saltedRound = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, saltedRound);

        // Update the user's password
        user.password = hashedPassword;
        // Save the changes to the database
        await user.save();
        //   Send a success response
        res.status(200).json({
            message: "Password changed successful"
        });
    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
};



exports.getOne = async (req, res) => {
    try {
        const { id } = req.params
        const oneUser = await UserModel.findById(id);
        if(!oneUser){
            return res.status(404).json({
                message: 'User not found'
            })
        }
        res.status(200).json({
            message: 'User details',
            data: oneUser
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.getAll = async (req, res) => {
    try {
        const users = await UserModel.find();
        if(users.length === 0){
            return res.status(404).json({
                message: 'No user found in this database'
            })
        }
        res.status(200).json({
            message: 'Users details',
            data: users
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params
        const { fullName, stack } = req.body;
        const user = await UserModel.findById(id);
        if(!user){
            return res.status(404).json({
                message: 'User not found'
            })
        }
        const data = {
            fullName: fullName || user.fullName,
            stack: stack || user.stack,
            image: user.image
        }
        // Check if the user is passing a image
        if(req.file && req.file.filename) {
            // Dynamically get the old image path
            const oldFilePath = `uploads/${user.image}`
            // Check if the file exists inside of the path
            if(fs.existsSync(oldFilePath)){
                // Delete the existing image
                fs.unlinkSync(oldFilePath)
                // Update the data object
                data.image = req.file.filename
            }
        }
        // Update the changes to our database
        const updatedUser = await UserModel.findByIdAndUpdate(id, data, { new: true});
        // Send a succes response to the user
        res.status(200).json({
            message: 'User details updated successfully',
            data: updatedUser
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}