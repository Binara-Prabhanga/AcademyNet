const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const app = express();
const PORT = process.env.PORT_ONE || 8000;
const mongoose = require("mongoose");
const User = require("./user");
const Course = require("./course");
const jwt = require("jsonwebtoken");
const amqp = require("amqplib");
const bufferConversion = require("./utils/bufferConversion");
const cloudinary = require("./utils/cloudinary");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const gravatar = require("gravatar");
const sendEmail = require("./utils/nodemailer");
const multer = require("multer");
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const keys = require("./config/keys");
const validateUserLoginInput = require("./validation/userLogin");
const validateUserRegisterInput = require("./validation/userRegister");
const validateOTP = require("./validation/otpValidation");
const validateForgotPassword = require("./validation/forgotPassword");
const validateUserUpdatePassword = require("./validation/updatePassword");
const dotenv = require("dotenv");
dotenv.config();
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const initializePassport = require("./config/passport"); // Import Passport configuration
const Quiz = require("./quizSchema");
const fs = require("fs");
const path = require("path");
initializePassport();

// Logging error details to a file
const logFilePath = path.join(__dirname, 'error.log');
const logErrorToFile = (error) => {
    const logMessage = `[${new Date().toISOString()}] ${error.stack || error}\n`;
    fs.appendFileSync(logFilePath, logMessage);
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  cookieParser({
    sameSite: "Lax",
    secure: true, // Ensure cookies are only sent over HTTPS
  })
);
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
  preflightContinue: false, // Disable passing preflight responses to next handlers
  optionsSuccessStatus: 204, // Response status for successful OPTIONS requests
};
app.use(cors(corsOptions));

let loggedInUsers = [];
app.use(morgan("dev"));
app.use(passport.initialize());
app.use(helmet());

var channel, connection;

app.use(express.json());
app.use((req, res, next) => {
  // Set security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY"); // Deny framing entirely
  res.setHeader("X-Frame-Options", "SAMEORIGIN"); // Allow framing from the same origin
  // Alternatively, use Content-Security-Policy's frame-ancestors directive
  res.setHeader("Content-Security-Policy", "frame-ancestors 'self';"); 
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

// Helmet security headers, including CSP
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://js.stripe.com",
        "https://trusted-scripts.com",
        "https://api.stripe.com",
        "https://merchant-ui-api.stripe.com",
        "https://stripe.com/cookie-settings/enforcement-mode",
        "https://errors.stripe.com",
        "https://r.stripe.com",
        "https://m.stripe.network",
        "'sha256-/5Guo2nzv5n/w6ukZpOBZOtTJBJPSkJ6mhHpnBgm3Ls='",
      ],
      styleSrc: [
        "'self'",
        "'sha256-0hAheEzaMe6uXIKV4EehS9pu1am1lj/KnnzrOYqckXk='",
        "'unsafe-inline'",
        "https://m.stripe.network",
        "https://trusted-images.com",
        "https://q.stripe.com",
        "https://b.stripecdn.com",
      ],
      imgSrc: [
        "'self'",
        "https://q.stripe.com",
        "https://trusted-images.com",
        "https://q.stripe.com",
        "https://m.stripe.network",
        "https://b.stripecdn.com"],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        "https://merchant-ui-api.stripe.com",
        "https://api.trusted.com",
      ],
      frameSrc: ["'self'", "https://m.stripe.network"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
      mediaSrc: ["'none'"],
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

mongoose.connect(
  process.env.MONGO_URL,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => {
    console.log(`Learner-Service DB Connected`);
  }
);

// configure CSP
app.get('/', (req, res) => {
  res.send('Learner service is running with CSP');
});

// Apply CSP middleware to all routes
app.get('/', (req, res) => {
  res.send('CSP is set for lerner-service!');
});

// CSP Reporting Endpoint
app.post('/csp-violation-report-endpoint', (req, res) => {
  console.log('CSP Violation Report:', req.body);
  // You can log this to a file or a logging service here
  res.status(204).end(); // Respond with no content
});

//Hash Disclosure - BCrypt
// User Courses (Excluding Password)
app.get(
  "/userCourses",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;

      // Fetch the user data, excluding the password field
      const user = await User.findOne({ _id })
        .populate("coursesCreated")
        .populate("coursesBought")
        .populate("cart")
        .select("-password"); // Exclude password from the user data

      return res.status(200).json({ message: user });
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/deleteUserCourses/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const courseIdToDelete = req.params.courseId;
      const user = await User.findOne({ _id }).populate("coursesBought");

      // Check if the user has bought the course
      const courseIndex = user.coursesBought.findIndex((course) =>
        course._id.equals(courseIdToDelete)
      );

      if (courseIndex !== -1) {
        // Remove the course ID from the coursesBought array
        user.coursesBought.splice(courseIndex, 1);
        await user.save();

        return res
          .status(200)
          .json({ message: "Course removed from user coursesBought" });
      } else {
        return res
          .status(404)
          .json({ message: "Course not found in user coursesBought" });
      }
    } catch (err) {
      next(err);
    }
  }
);

// Comment on Q&A
app.post(
  "/commentOnQna/:courseId/:videoIndex",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { name } = req.user;
      const { courseId, videoIndex } = req.params;
      const { question } = req.body;

      // Find the course by ID
      const course = await Course.findOne({ _id: courseId });

      const video = course.file[videoIndex];
      if (!video) {
        return res.status(404).json({ error: "Video not found" });
      }

      // Get the video URL from the file object
      const videoUrl = video;

      // Push the question to the Q&A section of the video
      course.qna.push({ video: videoUrl, sender: name, message: question });

      // Save the updated course
      await course.save();

      res.status(200).json({ message: "Question added successfully", course });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/submit-answers",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { userId, answers } = req.body;
      const { _id } = req.user;

      for (const [quizId, selectedOptions] of Object.entries(answers)) {
        // Fetch the quiz from the database
        const quiz = await Quiz.findById(quizId);
        if (!quiz) {
          return res
            .status(404)
            .json({ message: `Quiz with ID ${quizId} not found` });
        }

        // Calculate marks for the quiz
        let marks = 0;
        quiz.questions.forEach((question, questionIndex) => {
          const correctOptionIndex = question.options.findIndex(
            (option) => option.isCorrect
          );
          if (
            correctOptionIndex !== -1 &&
            selectedOptions[questionIndex] === correctOptionIndex
          ) {
            marks++;
          }
        });

        // Update the user's quiz information
        await User.findByIdAndUpdate(_id, {
          $push: {
            quizzes: {
              courseId: quiz.courseId,
              quizId: quizId,
              marks: marks,
            },
          },
        });
      }

      res.status(200).json({ message: "Marks updated successfully" });
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/deleteUserQuiz/:quizId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { quizId } = req.params;

      // Update the user document to remove the quiz
      const user = await User.findByIdAndUpdate(_id, {
        $pull: { quizzes: { quizId } },
      });

      // Check if the user exists
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      res.status(200).json({ message: "Quiz deleted successfully" });
    } catch (err) {
      next(err);
    }
  }
);

// Add to Cart
app.get(
  "/addToCart/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { courseId } = req.params;
      const user = await User.findById(_id);
      user.cart.push(courseId);
      await user.save();
      const userRes = await User.findById(_id)
        .populate("coursesCreated")
        .populate("coursesBought")
        .populate("cart");
      res.status(200).json({ message: userRes });
    } catch (err) {
      next(err);
    }
  }
);

app.use((err, req, res, next) => {
  // Log the error to the console or a log file
  console.error(err);

  // Log error details to a file
  logErrorToFile(err);

  // Send a generic error response to the client
  res.status(err.statusCode || 500).json({
    message:
      err.message ||
      "An internal server error occurred. Please try again later.",
  });
});


app.listen(PORT, () => {
  console.log(`Learner-Service at ${PORT}`);
});
