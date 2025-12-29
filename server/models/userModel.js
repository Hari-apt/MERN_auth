import mongoose from "mongoose";

const userSchema = new mongoose.Schema({

    name: {type: String, required: true},
    email: {type: String, required:true, unique: true},
    password: {type: String, required: true},
    verifyOTP: {type: String, default: ''},
    verifyOTPExpireAt: {type: Number, default: 0},
    resendOTP: {type: String, default: ""},
    resendOTPExpireAt: {type: Number, default: 0},
    isAccountVerified: {type: Boolean, default: false}
});

const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;
