import userModel from "../models/userModel.js";

const getUserData = async(req, res) => {
    try 
    {
        const userId = req.userId;
        if(!userId)
        {
            return res.json({success: false, msg: "UserID is missing"})
        }
        const user = await userModel.findById(userId);

        if(!user)
        {
            return res.json({success: false, msg: "User Not Found"});
        }

        return res.json({
            success: true,
            userData: {
                name: user.name,
                isAccountVerified: user.isAccountVerified
            }
        })
    } 
    catch (error) 
    {
        return res.json({success: false, msg: error.message})
    }

}

export default getUserData;