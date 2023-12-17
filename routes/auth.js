import { Router } from "express";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import { generateJWTToken } from "../services/token.js";

const router = Router();

router.get("/login", (req, res) => {
  if(req.cookies.token){
    res.redirect('/')
  }
  res.render("login", {
    title: "Login || Muhammadnozim",
    isLogin: true,
    loginError: req.flash('loginError'),
  });
});

router.get("/register", (req, res) => {
  if(req.cookies.token){
    res.redirect('/')
  }
  res.render("register", {
    title: "Register || Muhammadnozim",
    isRegister: true,
    registerError: req.flash('registerError'),
  });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token")
  res.redirect('/login')
})

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if(!email || !password){
    req.flash('loginError', "All fields is fill requaired")
    res.redirect('/login')
    return
  }
  const existUser = await User.findOne({ email });
  if (!existUser) {
    req.flash('loginError', "User not found!")
    res.redirect('/login')
    return;
  }
  const isPassEqual = await bcrypt.compare(
    password,
    existUser.password
  );
  if (!isPassEqual) {
    req.flash('loginError', "Password wrong!")
    res.redirect('/login')
    return;
  }
  const token = generateJWTToken(existUser._id);
  res.cookie("token",token, {httpOnly: true, secure: true})

  res.redirect("/");
});

// router.post("/login", async (req, res) => {
// try {
//   // Foydalanuvchini bazadan email orqali izlash
//   const existUser = await User.findOne({ email: req.body.email });

//   // Foydalanuvchi topilmagan bo'lsa, not found xabarni yuborish
//   if (!existUser) {
//     console.log("User not found");
//     return res.status(404).send("User not found");
//   }

//   // Foydalanuvchi topilsa, kiritilgan parolni tekshirish
//   const isPassEqual = await bcrypt.compare(
//     req.body.password,
//     existUser.password
//   );

//   // Parol noto'g'ri kiritilgan bo'lsa, xabar yuborish
//   if (!isPassEqual) {
//     console.log("Password wrong");
//     return res.status(401).send("Password wrong");
//   }

//   // Foydalanuvchi to'g'ri login qilingan bo'lsa, ma'lumotlarni chiqarish
//   console.log(existUser);
//   res.redirect("/"); // yoki boshqa manzilga yo'naltirish
// } catch (error) {
//   console.error("Error during login:", error.message);
//   res.status(500).send("Internal Server Error");
// }
// });

router.post("/register", async (req, res) => {
  const { firstname, lastname, email, password } = req.body;
  if(!firstname || !lastname || !email || !password){
    req.flash('registerError', "All fields is fill requaired")
    res.redirect('/register')
    return
  }
  
  const candidate = await User.findOne({email})

  if(candidate){
    req.flash('registerError', "User already exist")
    res.redirect('/register')
    return
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const userData = {
      firstname,
      lastname,
      email,
      password: hashedPassword,
    };


    console.log("Received user data:", userData); // Qo'shimcha log

    const user = await User.create(userData);
    console.log("User created:", user); // Qo'shimcha log
    const token = generateJWTToken(user._id);
    res.cookie("token",token, {httpOnly: true, secure: true})
    res.redirect("/");
  } catch (error) {
    console.error("Error during user registration:", error.message);
    res.status(500).send("Internal Server Error");
  }
});

export default router;
