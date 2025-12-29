import userModel from "../models/userModel.js";
import bcrypt from 'bcryptjs'
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from "../config/emailTemplates.js";

export const register = async (req, res)=>{

    const {name, email, password } = req.body;

    if(!name || !email || !password)
    {
        return res.json({success : false, msg: 'Details Not found.'});
    }

    try
    {
        const existingUser = await userModel.findOne({email});
        if(existingUser)
        {
            return res.json({success: false, msg: 'User Already exists.'});
        }

        const hashPassword = await bcrypt.hash(password, 10);
        const newUser = userModel({name, email, password : hashPassword});

        await newUser.save();
        
        const token = jwt.sign({id: newUser._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        const mailOptions = 
        {
            from: process.env.SENDER_MAIL,
            to: email,
            subject: 'Welcome to Hyrup',
            text: `Hey there, Welcome to Hyrup and get an intern as ease!!!, Successful registeration with email: ${email}`
        }

        await transporter.sendMail(mailOptions);
        
        return res.json({success: true, msg: "Successfully registered"})
    }
   
    catch(error)
    {
        res.json({success: false, msg: error.message})
    }

}


export const login = async (req, res) => {

    const {email, password} = req.body;

    if(!email || !password)
    {
       return res.json ({success: false, msg: 'Email and password are required'});
    } 

    try
    {
        const user = await userModel.findOne({email})

        if(!user)
        {
            return res.json({success: false, msg: "Invalid email"})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch)
        {
            return res.json({success: false, msg: 'Invalid Password'})
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        const mailOptions = {
            from: process.env.SENDER_MAIL,
            to: email,
            subject: 'Welcome to Hyrup',
            text: `Hey there, Welcome to Hyrup and get an intern as ease!!!, Successful Loginn with email: ${email}`
        }

        res.status(201).json({success: true, msg: "Successfully registered"});


        await transporter.sendMail(mailOptions);

        return res.json({success: true, msg: "Successfully Logged in"})

    }

    catch(error)
    {
        return res.json({success: false, msg: error.message})
    }
}

export const logout = async (req, res) => {

    try
    {
        res.clearCookie('token', {
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'  
        })

        return res.json({success: true, msg: "Successfully Logged out"})
    }
    
    catch(error)
    {
        return res.json({success: false, msg: error.message})
    }
}

export const sendVerifyOTP = async(req, res) => {
    try{
        const userId = req.userId;
        const user = await userModel.findById(userId);

        if(!user)
        {
            res.json({success: false, msg: 'User Not Found'})
        }

        if(user.isAccountVerified)
        {
            return res.json({success: false, msg:'Account is already verified'})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000))

        user.verifyOTP = otp;
        user.verifyOTPExpireAt = Date.now() + 24*60*60*1000;  // Expire after 1 day

        await user.save();

        const email = user.email;

        const mailOptions = {
            from: process.env.SENDER_MAIL,
            to: email,
            subject: 'Account Verification OTP',
           /*  text: `Your OTP is ${otp}. Verify your account using this otp.`, */
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", email)
        }

        await transporter.sendMail(mailOptions);
        res.json({success: true, msg:'Verification OTP is send to email successfully' })
    }
    catch(error)
    {
        res.json({success: false, msg: error.message})
    }
}

export const verifyemail = async(req, res) =>{
    try
    {
        const userId = req.userId;
        const {otp} = req.body;

        if(!userId || !otp)
        {
            res.json({success: false, msg: "Missing Details"});
        }

        const user = await userModel.findById(userId);
        if(!user)
        {
            return res.json({success: false, msg: 'User Not Found'});
        }

        if(otp !== user.verifyOTP)
        {
            return res.json({success: false, msg: "Invalid OTP"});
        }

        if(user.verifyOTPExpireAt < Date.now())
        {
            return res.json({success: false, msg: "OTP Expired"})
        }
        
        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt = 0;

        await user.save();

        return res.json({success: true, msg: 'Account verified successfully'})
    }

    catch(error)
    {
        return res.json({success: false, msg:error.message})
    }
}


//Check if user is Authenticated (Logged in with active cookie)
export const isAuthenticated = async (req, res) => {
    try
    {
        return res.json({success: true, msg: "Authenticated"});
    }
    catch(error)
    {
        return res.json({success: false, msg: error.message});
    }
}


export const sendResetOtp = async(req, res) => {
    
    const {email} = req.body;

    if(!email)
    {
       return res.json({success: false, msg: "Email Required"})
    }
    try
    { 
        const user = await userModel.findOne({email});
        if(!user)
        {
           return res.json({success: false, msg: 'User Not Found'});
        }

        const resetOtp = String(Math.floor(100000 + Math.random() * 900000));

        user.resendOTP = resetOtp;
        user.resendOTPExpireAt = Date.now() + 15*60*1000;  //Expires after 15 minutes

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_MAIL,
            to: email,
            subject: 'Password Reset OTP',
            /* text: `Your OTP for resetting the Password is ${resetOtp}. Use this OTP to proceed with resetting your accound password.`, */
            html: PASSWORD_RESET_TEMPLATE.replace("{{email}}", email).replace("{{otp}}", otp)
        }

        await transporter.sendMail(mailOptions);

        return res.json({success: true, msg: "Reset OTP sent to your mail successfully."})
    }
    catch(error)
    {
        return res.json({success: false, msg: error.message});
    }
}

export const resetPassword = async(req, res) => {
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword)
    {
       return res.json({success: false, msg: "Email, OTP and NewPassword are required"});
    }

    try 
    {
        const user = await userModel.findOne({email});
        if(!user)
        {
           return res.json({success: false, msg: "User Not Found"});
        }

        if(user.resendOTP !== otp)
        {
           return res.json({success: false, msg: "Invalid OTP"});
        }

        if(user.resendOTPExpireAt < Date.now())
        {
           return res.json({success: false, msg: "OTP Expired"});
        }

        const hashPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashPassword;
        user.resendOTP = "";
        user.resendOTPExpireAt = 0;

        await user.save();

       return res.json({success: true, msg: "Password has been reset successfully"});
    } 
    catch (error) 
    {
       return res.json({success: false, msg: error.message})
    }
}