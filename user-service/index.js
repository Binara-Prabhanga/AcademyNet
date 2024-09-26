const express = require("express");
const session = require("express-session");
const cors = require("cors");
const helmet = require("helmet");
const passport = require("passport");
require("./config/passport"); 
const app = express();
const Razorpay = require("razorpay");
const PORT = process.env.PORT_ONE || 5000;
const mongoose = require("mongoose");
const User = require("./user");
const nodemailer = require("nodemailer");
const Course = require("./course");
const jwt = require("jsonwebtoken");
const amqp = require("amqplib");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const gravatar = require("gravatar");
const keys = require("./config/keys");
const validateUserLoginInput = require("./validation/userLogin");
const validateUserRegisterInput = require("./validation/userRegister");
const validateOTP = require("./validation/otpValidation");
const validateForgotPassword = require("./validation/forgotPassword");
const validateUserUpdatePassword = require("./validation/updatePassword");
const dotenv = require("dotenv");
dotenv.config();
const initializePassport = require("./config/passport");
initializePassport();
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());


app.use(
  session({
    secret:
      "ZvEFI9ZLHTia1VeUas4J3D6pYPdGyFRmQ2h4gh0RXZXOv3Cw6YhT2Ec400xZM8edwd",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:8080",
  "http://localhost:5000",
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // Allow non-browser clients (like curl)
    if (allowedOrigins.includes(origin)) {
      return callback(null, true); // Allow requests from allowed origins
    } else {
      return callback(new Error("Not allowed by CORS"), false); // Block others
    }
  },
  credentials: true, // Allow credentials (cookies, authorization headers)
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allow specific methods
  allowedHeaders: ["Content-Type", "Authorization"], // Allow specific headers
  preflightContinue: false, // Disable passing preflight responses to next handlers
  optionsSuccessStatus: 204, // Response status for successful OPTIONS requests
};
app.use(cors(corsOptions));

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Credentials", true);
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin,X-Requested-With,Content-Type,Accept,content-type,application/json"
  );
  next();
});

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://js.stripe.com",
        "https://trusted-scripts.com",
        "https://m.stripe.network",
        "'sha256-/5Guo2nzv5n/w6ukZpOBZOtTJBJPSkJ6mhHpnBgm3Ls='"
      ],
      styleSrc: [
        "'self'",
        "'sha256-0hAheEzaMe6uXIKV4EehS9pu1am1lj/KnnzrOYqckXk='",
        "'unsafe-inline'",
        "https://m.stripe.network",
      ],
      imgSrc: [
        "'self'",
        "https://q.stripe.com",
        "https://trusted-images.com",
        "https://m.stripe.network",
        "https://b.stripecdn.com"
      ],
      mediarc: ["'none'"],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        "https://merchant-ui-api.stripe.com",
      ],
      frameSrc: ["'self'", "https://m.stripe.network"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      reportUri: ["https://q.stripe.com/csp-report"],
      workerSrc: ["'none'"],
      // Add the report-to directive for newer CSP reporting
      reportTo: "/csp-violation-report-endpoint"
    },
    reportOnly: false,
  })
);

// explicitly suppress the X-Powered-By header
app.use(helmet.hidePoweredBy());

// disable x-powered-by header
app.disable("x-powered-by")

app.use((req, res, next) => {
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );
  next();
});

let loggedInUsers = [];
app.use(morgan("dev"));

var channel, connection;

app.use(express.json());
app.use((req, res, next) => {
  // Set security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY"); // Deny framing entirely
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  ); // Set HSTS

  // Get the IP address of the request
  const forwardedFor =
    req.headers["x-forwarded-for"] || req.connection.remoteAddress;

  // Define the metadata IP we want to block
  const metadataIP = "169.254.169.254";

  // Check if the request is attempting to access the metadata IP
  const isMetadataIP =
    req.headers.host === metadataIP ||
    req.url.includes(metadataIP) ||
    req.hostname === metadataIP ||
    forwardedFor.includes(metadataIP);

  if (isMetadataIP) {
    console.log(`Blocked attempt to access metadata IP from ${forwardedFor}`);
    return res.status(403).json({ error: "Access Forbidden" });
  }

  next();
});

mongoose.connect(
  process.env.MONGO_URL,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => {
    console.log(`User-Service DB Connected`);
  }
);

async function connect() {
  const amqpServer = "amqp://localhost:5672";
  connection = await amqp.connect(amqpServer);
  channel = await connection.createChannel();
  await channel.assertQueue("PRODUCT");
}
connect();

// configure CSP
app.get('/', (req, res) => {
  res.send('user-service is running with CSP.');
});

// Apply CSP middleware to all routes
app.get('/', (req, res) => {
  res.send('CSP is set for user-service!');
});

// CSP Reporting Endpoint
app.post('/csp-violation-report-endpoint', (req, res) => {
  console.log('CSP Violation Report:', req.body);
  // You can log this to a file or a logging service here
  res.status(204).end(); // Respond with no content
});

app.post("/register", cors(corsOptions), async (req, res) => {
  try {
    const { errors, isValid } = validateUserRegisterInput(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }

    const { name, email, password, role } = req.body;
    const user = await User.findOne({ email });

    if (user) {
      errors.email = "Email already exists";
      return res.status(400).json(errors);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const avatar = gravatar.url(email, { s: "200", r: "pg", d: "mm" });
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      avatar,
      role,
      active: true,
    });

    await newUser.save();
    res.status(200).json({ message: newUser });
  } catch (err) {
    console.error("Error in userRegister:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", cors(corsOptions), async (req, res) => {
  try {
    const { errors, isValid } = validateUserLoginInput(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email })
      .populate("coursesCreated")
      .populate("coursesBought")
      .populate("cart");

    if (!user) {
      errors.email = "Email doesn't exist";
      return res.status(400).json(errors);
    }

    // Check if the user is active
    if (!user.active || user.active == null) {
      errors.account = "Your account is not active. Please contact support.";
      return res.status(400).json(errors);
    }

    const isCorrect = await bcrypt.compare(password, user.password);

    if (!isCorrect) {
      errors.password = "Invalid Credentials";
      return res.status(404).json(errors);
    }

    // Save the logged in user's ID
    loggedInUsers.push(user.id);

    const payload = { id: user.id, user: user };
    jwt.sign(payload, keys.secretKey, { expiresIn: 7200 }, (err, token) => {
      if (err) {
        console.error("Error in generating token:", err);
        return res.status(500).json({ error: "Failed to authenticate" });
      }
      res.json({
        success: true,
        token: "Bearer " + token,
      });
    });
  } catch (err) {
    console.error("Error in userLogin:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    console.log("Google OAuth successful", req.user); // Log user details
    res.redirect("/home");
  }
);

// ADMIN
app.put("/users/:userId/deactivate", cors(corsOptions), async (req, res) => {
  try {
    const userId = req.params.userId;

    // Find the user by ID
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update the active status to false
    user.active = false;

    // Save the updated user
    await user.save();

    res.json({ message: "User deactivated successfully" });
  } catch (err) {
    console.error("Error in deactivating user:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});


//ADMIN
//Hash Disclosure - BCrypt
// FETCH USERS (Excluding Password)
app.get("/api/:userId/users", cors(corsOptions), async (req, res) => {
  try {
    // Get the _id of the logged-in user
    const _id = req.params.userId;

    // Fetch all users from the database except the logged-in user, excluding their password
    const users = await User.find({ _id: { $ne: _id } }).select("-password");
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

//Hash Disclosure - BCrypt
// ADMIN - UPDATE USER ROLE (Excluding Password)
app.put("/api/users/:userId/role", cors(corsOptions), async (req, res) => {
  try {
    const userId = req.params.userId;
    const { role } = req.body;

    // Validate the role
    if (!["Admin", "Instructor", "Learner"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    // Find the user by ID and update their role, excluding the password in the response
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(updatedUser);
  } catch (err) {
    console.error("Error updating user role:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

async function sendEmail(to, OTP, subject) {
  try {
    const transporter = nodemailer.createTransport({
      host: "smtp.elasticemail.com",
      port: 2525, // or 587 for TLS
      secure: false, // for SSL
      auth: {
        user: "eripper85@gmail.com",
        pass: "97E08D07458603B6690F74303BF500551E9E",
      },
    });

    // Email content
    const mailOptions = {
      from: "eripper85@gmail.com",
      to: to,
      subject: subject,
      text: `Your OTP is ${OTP}`,
    };

    // Send email
    await transporter.sendMail(mailOptions);
  } catch (error) {
    throw new Error(`Error sending email: ${error.message}`);
  }
}

// Update the sendEmail function call in your /forgotPassword route
app.post("/forgotPassword", cors(corsOptions), async (req, res) => {
  try {
    const { errors, isValid } = validateForgotPassword(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      errors.email = "Email Not found, Provide registered email";
      return res.status(400).json(errors);
    }

    function generateOTP() {
      var digits = "0123456789";
      let OTP = "";
      for (let i = 0; i < 6; i++) {
        OTP += digits[Math.floor(Math.random() * 10)];
      }
      return OTP;
    }

    const OTP = await generateOTP();
    user.otp = OTP;
    await user.save();

    // Send email with OTP
    await sendEmail(user.email, OTP, "OTP");

    // Respond to client
    res.status(200).json({ message: "Check your registered email for OTP" });

    // Clear OTP after 5 minutes
    const helper = async () => {
      user.otp = "";
      await user.save();
    };
    setTimeout(function () {
      helper();
    }, 300000);
  } catch (err) {
    console.log("Error in sending email", err.message);
    return res
      .status(400)
      .json({ message: `Error in generateOTP: ${err.message}` });
  }
});

// Post OTP
app.post("/postOTP", cors(corsOptions), async (req, res) => {
  try {
    const { errors, isValid } = validateOTP(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }
    const { email, otp, newPassword, confirmNewPassword } = req.body;
    if (newPassword !== confirmNewPassword) {
      errors.confirmNewPassword = "Password Mismatch";
      return res.status(400).json(errors);
    }
    const user = await User.findOne({ email });
    if (user.otp === "") {
      errors.otp = "OTP has expired";
      return res.status(400).json(errors);
    }
    if (user.otp !== otp) {
      errors.otp = "Invalid OTP, check your email again";
      return res.status(400).json(errors);
    }
    let hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    return res.status(200).json({ message: "Password Changed" });
  } catch (err) {
    console.log("Error in submitting otp", err.message);
    return res.status(400).json({ message: `Error in postOTP${err.message}` });
  }
});

// Update password
// Update password
app.post(
  "/updatePassword",
  passport.authenticate("jwt", { session: false }),
  cors(corsOptions),
  async (req, res) => {
    try {
      const { errors, isValid } = validateUserUpdatePassword(req.body);
      if (!isValid) {
        return res.status(400).json(errors);
      }
      const { email, oldPassword, newPassword, confirmNewPassword } = req.body;
      if (newPassword !== confirmNewPassword) {
        errors.confirmNewPassword = "Password Mismatch";
        return res.status(404).json(errors);
      }
      const user = await User.findOne({ email });
      const isCorrect = await bcrypt.compare(oldPassword, user.password);
      if (!isCorrect) {
        errors.oldPassword = "Invalid old Password";
        return res.status(404).json(errors);
      }
      let hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();
      res.status(200).json({ message: "Password Updated" });
    } catch (err) {
      console.log("Error in updating password", err.message);
      return res
        .status(400)
        .json({ message: `Error in updatePassword${err.message}` });
    }
  }
);

// Buy Course
// POST endpoint to process a course purchase by a user.
app.post("/buyCourse/:courseId", cors(corsOptions), async (req, res) => {
  try {
    // Extract userId from request body and courseId from parameters
    const userId = req.body.userId;
    const { _id } = userId;
    const { courseId } = req.params;
    const course = await Course.findById(courseId);
    console.log("course check", course);

    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    course.userWhoHasBought.push(userId);
    await course.save();

    const buyerUser = await User.findById(userId);
    if (!buyerUser) {
      return res.status(404).json({ error: "User not found" });
    }
    buyerUser.coursesBought.push(courseId);
    buyerUser.totalExpenditure =
      (buyerUser.totalExpenditure || 0) + parseInt(course.price);
    await buyerUser.save();

    const index = buyerUser.cart.findIndex(
      (courseid) => courseId.toString() === courseid.toString()
    );
    buyerUser.cart.splice(index, 1);
    await buyerUser.save();

    const buyerUserResponse = await User.findById(userId)
      .populate("coursesCreated")
      .populate("coursesBought")
      .populate("cart");

    const seller = await User.findById(course.createdBy);
    seller.totalIncome = (seller.totalIncome || 0) + parseInt(course.price);
    await seller.save();

    return res.status(200).json({ message: course });
  } catch (err) {
    console.log("error in buyCourse", err.message);
    res.status(400).json({ "Error in buyCourse": err.message });
  }
});

app.post("/create-checkout-session", cors(corsOptions), async (req, res) => {
  const { course } = req.body;

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: course.title,
              description: course.description,
              images: [course.image],
            },
            unit_amount: course.price * 100,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `http://localhost:3000/payment-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `http://localhost:3000/home`,
    });

    res.json({ id: session.id });
  } catch (err) {
    console.error("Stripe Checkout Session creation failed:", err);
    res.status(500).send({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`User-Service at ${PORT}`);
});
