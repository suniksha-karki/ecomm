import userModel from "../models/userModel.js";
import orderModel from "../models/orderModel.js";
import { comparePassword, hashPassword } from "./../helpers/authHelper.js";
import JWT from "jsonwebtoken";
import validator from 'validator';


export const registerController = async (req, res) => {
  try {
    const { name, email, password,confirmPassword, phone, address, answer } = req.body;
    //validations

    //name
    if (!validator.isLength(name,{min:1})) {
      return res.send({ error: "Name is Required" });
    }
    // Additional name validations
    if (!/^[a-zA-Z\s]+$/.test(name)) {
     return res.send({ error: "Name can only contain letters and spaces" });
    }

    if (name.length > 50) {
    return res.send({ error: "Name must be less than or equal to 50 characters" });
    }

    // If all validation checks pass, the code continues execution

    //email
    if (!validator.isEmail(email)) {
      return res.send({ message: "Email is Required" });
    }
    

   // Additional email validations
   if (email.length > 100) {
   return res.send({ message: "Email must be less than or equal to 100 characters" });
   }

    const emailParts = email.split("@");
    const domain = emailParts[1];

    // Domain-specific validations
    if (domain.length > 50) {
    return res.send({ message: "Domain must be less than or equal to 50 characters" });
    }

    // Check for specific domain names
    const allowedDomains = ["gmail.com", "yahoo.com", "companyname.com"];
    if (!allowedDomains.includes(domain)) {
    return res.send({ message: "Email domain is not allowed" });
   }

    // Validate local part of the email (part before the @ symbol)
    const localPart = emailParts[0];
    if (localPart.length > 64) {
    return res.send({ message: "Local part must be less than or equal to 64 characters" });
    }

   // Check for special characters in the local part
   const specialCharactersRegex = /[!#$%^&*()+=\-[\]\\';,/{}|":<>?~_]/;
   if (specialCharactersRegex.test(localPart)) {
   return res.send({ message: "Local part contains invalid characters" });
   }

 
    //password
    if (!validator.isLength(password,{min:6})) {
      return res.send({ message: "Password must be atleast 6 characters long" });
    }
    if (!/[A-Z]/.test(password)) {
      return res.send({ message: 'Password must contain at least one capital letter' });
    }
    
    if (!/\d/.test(password)) {
      return res.send({ message: 'Password must contain at least one number' });
    }
    //confirm password
    if (password !== confirmPassword) {
      return res.send({message:"Password and confirm password do not match"});
      
    }

    // If all validation checks pass, the code continues execution

    //phone
    if (!validator.isMobilePhone(phone, 'any')) {
      return res.send({ message: "Phone no is Required" });
    }
    if (!validator.isLength(address,{min:1})) {
      return res.send({ message: "Address is Required" });
    }
    if (!validator.isAlphanumeric(address)) {
      return res.status(400).send({ message: "Address should only contain alphanumeric characters" });
    }

    if (!validator.isLength(answer,{min:1})) {
      return res.send({ message: "Answer is Required" });
    }



    //send verification email
    const mailOptions = {
      from: "sender@example.com",
      to: email,
      subject: "Verify your email",
      text: "Please verify your email",
      html: "<p>Please verify your email</p>",
    };

    await sendEmail(mailOptions);
    console.log("Verification email sent successfully");



    //check user
    const exisitingUser = await userModel.findOne({ email });
    //exisiting user
    if (exisitingUser) {
      return res.status(200).send({
        success: false,
        message: "Already Register please login",
      });
    }
    //register user
    const hashedPassword = await hashPassword(password);
    //save
    const user = await new userModel({
      name,
      email,
      phone,
      address,
      password: hashedPassword,
      confirmPassword,
      answer,
    }).save();

    res.status(201).send({
      success: true,
      message: "User Register Successfully",
      user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in Registeration",
      error,
    });
  }
};



//POST LOGIN
export const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
     //validation
     if (!email || !password) {
      return res.status(404).send({
        success: false,
        message: "Invalid email or password",
      });
    }

    //check user
    const user = await userModel.findOne({ email });
    console.log('User:', user);

    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Email is not registerd",
      });
    }
    
    const match = await comparePassword(password, user.password);
    console.log('Password match:', match);

    if (!match) {
      console.log('Password match:', match);
      return res.status(200).send({
        success: false,
        message: "Invalid Password",
      });
      
    }
    //token
    const token = await JWT.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.status(200).send({
      success: true,
      message: "login successfully",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address,
        role: user.role,
      },
      token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in login",
      error,
    }); 
  }
};

//forgotPasswordController

export const forgotPasswordController = async (req, res) => {
  try {
    const { email, answer, newPassword } = req.body;
    if (!email) {
      res.status(400).send({ message: "Emai is required" });
    }
    if (!answer) {
      res.status(400).send({ message: "answer is required" });
    }
    if (!newPassword) {
      res.status(400).send({ message: "New Password is required" });
    }

    
    
    


    //check
    const user = await userModel.findOne({ email, answer });
    //validation
    if (!user) {
      return res.status(404).send({
        success: false,
        message: "Wrong Email Or Answer",
      });
    }
     // Send the password reset email
    await sendEmail(mailOptions);
    console.log("Password reset email sent successfully");

    // Send a response to the client
    res.status(200).send({
      success: true,
      message: "Password reset email sent successfully",
    });




  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Something went wrong",
      error,
    });
  } 
  

};



//test controller
export const testController = (req, res) => {
  try {
    res.send("Protected Routes");
  } catch (error) {
    console.log(error);
    res.send({ error });
  }
};

//update prfole
export const updateProfileController = async (req, res) => {
  try {
    const { name, email, password, address, phone } = req.body;
    const user = await userModel.findById(req.user._id);
    //password
    if (password && password.length < 6) {
      return res.json({ error: "Passsword is required and 6 character long" });
    }
    const hashedPassword = password ? await hashPassword(password) : undefined;
    const updatedUser = await userModel.findByIdAndUpdate(
      req.user._id,
      {
        name: name || user.name,
        password: hashedPassword || user.password,
        phone: phone || user.phone,
        address: address || user.address,
      },
      { new: true }
    );
    res.status(200).send({
      success: true,
      message: "Profile Updated SUccessfully",
      updatedUser,
    });
  } catch (error) {
    console.log(error);
    res.status(400).send({
      success: false,
      message: "Error WHile Update profile",
      error,
    });
  }
};

//orders
export const getOrdersController = async (req, res) => {
  try {
    const orders = await orderModel
      .find({ buyer: req.user._id })
      .populate("products", "-photo")
      .populate("buyer", "name");
    res.json(orders);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error WHile Geting Orders",
      error,
    });
  }
};
//orders
export const getAllOrdersController = async (req, res) => {
  try {
    const orders = await orderModel
      .find({})
      .populate("products", "-photo")
      .populate("buyer", "name")
      .sort({ createdAt: "-1" });
    res.json(orders);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error WHile Geting Orders",
      error,
    });
  }
};

//order status
export const orderStatusController = async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;
    const orders = await orderModel.findByIdAndUpdate(
      orderId,
      { status },
      { new: true }
    );
    res.json(orders);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error While Updateing Order",
      error,
    });
  }
};
