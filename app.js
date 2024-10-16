const express               =  require('express'),
      expSession            =  require("express-session"),
      app                   =  express(),
      mongoose              =  require("mongoose"),
      passport              =  require("passport"),
      bodyParser            =  require("body-parser"),
      LocalStrategy         =  require("passport-local"),
      passportLocalMongoose =  require("passport-local-mongoose"),
      User                  =  require("./models/user"),
      mongoSanitize         =  require("express-mongo-sanitize"),
      rateLimit             =  require("express-rate-limit"),
      xss                   =  require("xss-clean"),
      helmet                =  require("helmet");
const { body, validationResult } = require('express-validator');

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

app.use(expSession({
    secret:"mysecret",       //decode or encode session
    resave: false,          
    saveUninitialized:true,
    cookie: {
        httpOnly: true,
        secure: true,
        maxAge: 1 * 60 * 1000 // 10 minutes
    }
}))

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded(
      { extended:true }
))
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================
app.use(mongoSanitize());
// Preventing Brute Force & DOS Attacks - Rate Limiting
const limit = rateLimit({
    max: 100,// max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout
    message: 'Too many requests' // message to send
});
app.use('/routeName', limit);
// Preventing DOS Attacks - Body Parser
app.use(express.json({ limit: '10kb' })); // Body limitis 10 kb
// Data Sanitization against XSS attacks
app.use(xss());
// Helmet to secure connection and data
app.use(helmet());
// Validation middleware
const registerValidationRules = [
    body('username')
      .isLength({ min: 5 }).withMessage('Username must be at least 5 characters long')
      .isAlphanumeric().withMessage('Username must contain only letters and numbers'),
    body('email')
      .isEmail().withMessage('Please enter a valid email'),
    body('phone')
      .isMobilePhone().withMessage('Please enter a valid phone number'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
      .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/)
      .withMessage('Password must include one lowercase character, one uppercase character, a number, and a special character')
  ];
//=======================
//      R O U T E S
//=======================
app.get("/", (req,res) =>{
    res.render("home");
})
app.get("/userprofile" ,(req,res) =>{
    res.render("userprofile");
})
//Auth Routes
app.get("/login",(req,res)=>{
    res.render("login");
});
app.post("/login",passport.authenticate("local",{
    successRedirect:"/userprofile",
    failureRedirect:"/login"
}),function (req, res){
});
app.get("/register",(req,res)=>{
    res.render("register");
});

// app.post("/register",(req,res)=>{
    
//     User.register(new User({username: req.body.username,email: req.body.email,phone: req.body.phone}),req.body.password,function(err,user){
//         if(err){
//             console.log(err);
//             res.render("register");
//         }
//         passport.authenticate("local")(req,res,function(){
//             res.redirect("/login");
//         })    
//     })
// })

app.post("/register", registerValidationRules, (req,res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render("register", { 
            errors: errors.array(),
            username: req.body.username,
            email: req.body.email,
            phone: req.body.phone
        });
    }
    
    User.register(new User({username: req.body.username, email: req.body.email, phone: req.body.phone}), req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            return res.render("register", { 
                error: err.message,
                username: req.body.username,
                email: req.body.email,
                phone: req.body.phone
            });
        }
        passport.authenticate("local")(req, res, function() {
            res.redirect("/login");
        })    
    })
})

app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect("/");
});
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000,function (err) {
    if(err){
        console.log(err);
    }else {
        console.log("Server Started At Port 3000");  
    }
});