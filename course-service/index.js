const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const app = express();
const fs = require("fs");
const path = require("path");

//Helmet to set various HTTP headers for security
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
      ],
      imgSrc: [
        "'self'",
        "https://q.stripe.com",
        "https://trusted-images.com",
        "https://m.stripe.network",
        "https://b.stripecdn.com",
      ],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",
        "https://merchant-ui-api.stripe.com",
        "https://api.trusted.com",
      ],
      frameSrc: ["'self'", "https://m.stripe.network"],
      formAction: ["'self'"],
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

// Logging error details to a file
const logFilePath = path.join(__dirname, 'error.log');
const logErrorToFile = (error) => {
    const logMessage = `[${new Date().toISOString()}] ${error.stack || error}\n`;
    fs.appendFileSync(logFilePath, logMessage);
};

const PORT = process.env.PORT_ONE || 8080;
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
initializePassport();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(morgan("dev"));
app.use(passport.initialize());

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

// Add middleware to block malicious Host headers targeting internal IP addresses
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

// Add cookieParser middleware with SameSite option
app.use(
  cookieParser({
    sameSite: "Lax",
    secure: true, // Ensure cookies are only sent over HTTPS
  })
);

mongoose.connect(
  process.env.MONGO_URL,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => {
    console.log(`Course-Service DB Connected`);
  }
);

// configure CSP
app.get('/', (req, res) => {
  res.send('course-service is running with CSP.');
});

// Apply CSP middleware to all routes
app.get('/', (req, res) => {
  res.send('CSP is set for course-service!');
});

// CSP Reporting Endpoint
app.post('/csp-violation-report-endpoint', (req, res) => {
  console.log('CSP Violation Report:', req.body);
  // You can log this to a file or a logging service here
  res.status(204).end(); // Respond with no content
});

// Add Course
app.post(
  "/addCourse",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  upload.single("file"),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { title, category, description, price } = req.body;

      const convertedBuffer = await bufferConversion(
        req.file.originalname,
        req.file.buffer
      );
      const uploadedImage = await cloudinary.uploader.upload(convertedBuffer, {
        resource_type: "image",
      });
      const course = new Course({
        title,
        category,
        description,
        file: null, // Set file to null
        image: uploadedImage.secure_url,
        price,
        createdBy: _id,
        duration: 0,
        approve: false, // Set approve to false
      });
      await course.save();
      const user = await User.findById(_id);
      user.coursesCreated.push(course._id);
      await user.save();
      res.status(200).json({ message: course });
    } catch (err) {
      next(err);
    }
  }
);

//Hash Disclosure - BCrypt
// FETCH ALL APPROVED COURSES (Excluding Password)
app.get(
  "/getAllCourse",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;

      // Fetch the logged-in user, excluding the password field
      const user = await User.findById(_id)
        .populate("coursesCreated")
        .populate("coursesBought")
        .populate("cart")
        .select("-password");

      // Fetch all approved courses, and exclude the password from the 'createdBy' field
      const allApprovedCourses = await Course.find({ approve: true }).populate({
        path: "createdBy",
        select: "-password",
      });

      if (allApprovedCourses.length === 0) {
        return res.status(400).json({ message: "No approved courses found" });
      }

      return res.status(200).json({ message: allApprovedCourses, user });
    } catch (err) {
      next(err);
    }
  }
);

//Hash Disclosure - BCrypt
// FETCH ALL NON-APPROVED COURSES (Excluding Password)
app.get(
  "/getAllCourseNot",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;

      // Fetch the logged-in user, excluding the password field
      const user = await User.findById(_id)
        .populate("coursesCreated")
        .populate("coursesBought")
        .populate("cart")
        .select("-password");

      // Fetch all non-approved courses, and exclude the password from the 'createdBy' field
      const allApprovedCourses = await Course.find({ approve: false }).populate(
        {
          path: "createdBy",
          select: "-password",
        }
      );

      if (allApprovedCourses.length === 0) {
        return res
          .status(400)
          .json({ message: "No non-approved courses found" });
      }

      return res.status(200).json({ message: allApprovedCourses, user });
    } catch (err) {
      next(err);
    }
  }
);

// Update Course Approval
app.put(
  "/updateCourseApproval/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { courseId } = req.params;
      const { approve } = req.body;

      // Check if the user has permission to update course approval
      const user = await User.findById(_id);
      if (!user) {
        return res.status(403).json({
          error: "You do not have permission to update course approval",
        });
      }

      // Find the course by ID and update its approval status
      const course = await Course.findByIdAndUpdate(
        courseId,
        { approve },
        { new: true }
      );

      if (!course) {
        return res.status(404).json({ error: "Course not found" });
      }

      return res
        .status(200)
        .json({ message: "Course approval updated successfully", course });
    } catch (err) {
      next(err);
    }
  }
);

//Hash Disclosure - BCrypt
// FETCH COURSE DETAILS BY ID (Excluding Password)
app.get(
  "/getCourseById/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { courseId } = req.params;

      // Fetch the course by ID, excluding the password field from the 'createdBy' field
      const course = await Course.findOne({ _id: courseId }).populate({
        path: "createdBy",
        select: "-password",
      });

      return res.status(200).json({ message: course });
    } catch (err) {
      next(err);
    }
  }
);

app.put(
  "/updateCourse/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  upload.fields([
    { name: "file", maxCount: 1 },
    { name: "image", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { courseId } = req.params;
      const { title, category, description, price } = req.body;

      // Find the course by ID
      let course = await Course.findById(courseId);

      // Check if the course exists
      if (!course) {
        return res.status(404).json({ error: "Course not found" });
      }

      // Check if a new video file is uploaded
      if (req.files["file"]) {
        const videoFile = req.files["file"][0];
        const convertedBuffer = await bufferConversion(
          videoFile.originalname,
          videoFile.buffer
        );
        const uploadedVideo = await cloudinary.uploader.upload(
          convertedBuffer,
          { resource_type: "video" }
        );
        const newVideoUrl = uploadedVideo.secure_url;
        // Update the duration if needed
        course.duration = (uploadedVideo.duration / 60).toFixed(2);
        // Add the new video URL to the array
        if (course.file === null) {
          course.file = [];
        }
        // Add the new video URL to the array
        course.file.push(newVideoUrl);
      }

      // Check if a new image file is uploaded
      if (req.files["image"]) {
        const imageFile = req.files["image"][0];
        const convertedBuffer = await bufferConversion(
          imageFile.originalname,
          imageFile.buffer
        );
        const uploadedImage = await cloudinary.uploader.upload(
          convertedBuffer,
          { resource_type: "image" }
        );
        const newImageUrl = uploadedImage.secure_url;
        // Set the new image URL
        course.image = newImageUrl;
      }

      // Update course details
      course.title = title;
      course.category = category;
      course.description = description;
      course.price = price;

      // Save the updated course
      await course.save();

      res.status(200).json({ message: "Course updated successfully", course });
    } catch (err) {
      next(err);
    }
  }
);

// Delete Course
app.delete(
  "/deleteCourse/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { courseId } = req.params;

      // Find the course by ID
      const course = await Course.findById(courseId);

      // Check if the course exists
      if (!course) {
        return res.status(404).json({ error: "Course not found" });
      }

      // Delete the course
      await Course.findByIdAndDelete(courseId);

      res.status(200).json({ message: "Course deleted successfully" });
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/deleteCourseVideo/:courseId/:videoIndex",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { courseId, videoIndex } = req.params;
      const { _id } = req.user;

      // Find the course by ID
      const course = await Course.findById(courseId);

      // Check if the course exists
      if (!course) {
        return res.status(404).json({ error: "Course not found" });
      }
      // Check if the video index is valid
      if (videoIndex < 0 || videoIndex >= course.file.length) {
        return res.status(404).json({ error: "Video index out of range" });
      }

      // Remove the video at the specified index from the course file array
      course.file.splice(videoIndex, 1);
      // Save the updated course
      await course.save();

      res.status(200).json({ message: "Video deleted successfully" });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/createQuiz",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { courseId, questions } = req.body;
      const { _id: userId } = req.user;

      // Convert courseId to mongoose ObjectId
      const courseIdObjectId = mongoose.Types.ObjectId(courseId);

      // Check if questions is an array
      if (!Array.isArray(questions)) {
        return res.status(400).json({ error: "Questions must be an array" });
      }

      // Check if any question is missing questionText or options
      const invalidQuestions = questions.some(
        (question) => !question.questionText || !Array.isArray(question.options)
      );
      if (invalidQuestions) {
        return res.status(400).json({
          error:
            "Each question must have questionText and options as an array of objects",
        });
      }

      // Create new quiz document
      const formattedQuestions = questions.map((question) => ({
        questionText: question.questionText,
        options: question.options.map((option) => ({
          optionText: option.optionText,
          isCorrect: option.isCorrect,
        })), // Mapping to embed option documents
      }));

      // Create new quiz document
      const quiz = new Quiz({
        course: courseIdObjectId,
        user: userId,
        questions: formattedQuestions,
      });

      // Save the quiz to the database
      await quiz.save();

      res.status(200).json({ message: "Quiz created successfully", quiz });
    } catch (error) {
      next(err);
    }
  }
);

app.get(
  "/quizzes/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { courseId } = req.params;

      // Find quizzes by courseId and populate the 'course' field
      const quizzes = await Quiz.find({ course: courseId });

      if (quizzes.length === 0) {
        return res.status(400).json({ message: "No course Found" });
      }

      return res.status(200).json({ message: quizzes });
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  "/quizzes/:quizId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { _id } = req.user;
      const { quizId } = req.params;

      // Find the quiz by ID
      const quiz = await Quiz.findById(quizId);

      // Check if the quiz exists
      if (!quiz) {
        return res.status(404).json({ error: "Quiz not found" });
      }

      // Ensure that the quiz belongs to the user
      if (quiz.user.toString() !== _id.toString()) {
        return res.status(403).json({ error: "Unauthorized" });
      }

      // Delete the quiz
      await Quiz.findByIdAndDelete(quizId);

      res.status(200).json({ message: "Quiz deleted successfully" });
    } catch (err) {
      next(err);
    }
  }
);

app.get(
  "/user/quizzes",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      // Extract the user ID from the authenticated user
      const userId = req.user._id;

      // Fetch the user from the database including their submitted quizzes
      const user = await User.findById(userId).populate("quizzes");

      // Extract the submitted quizzes from the user object
      const submittedQuizzes = user.quizzes.map((quiz) => ({
        quizId: quiz.quizId,
        quizCourse: quiz.courseId,
        quizMarks: quiz.marks,
      }));

      res.status(200).json({ submittedQuizzes });
    } catch (err) {
      next(err);
    }
  }
);

app.get(
  "/quizzesList/:courseId",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { courseId } = req.params;

      // Find quizzes by courseId and populate the 'course' field
      const quizzes = await Quiz.find({ course: courseId });

      if (quizzes.length === 0) {
        return res
          .status(404)
          .json({ message: "No quizzes found for the provided courseId" });
      }

      return res.status(200).json({ quizzes });
    } catch (err) {
      next(err);
    }
  }
);

app.get(
  "/user/details",
  cors(corsOptions),
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      // Fetch all users from the database
      const { _id } = req.user;
      const users = await User.find();

      // Prepare an array to store user details
      const userDetails = [];

      // Iterate over each user to extract required details
      for (const user of users) {
        // Extract user details
        const { name, email } = user;

        // Extract submitted quizzes details for the user
        const submittedQuizzes = [];
        for (const quiz of user.quizzes) {
          const quizDetails = await Quiz.findOne({
            user: _id,
            _id: quiz.quizId,
          }).populate("course");

          if (quizDetails) {
            submittedQuizzes.push({
              quizId: quizDetails._id,
              quizCourse: quizDetails.course.title, // Assuming the course title is stored in the 'title' field of the Course model
              quizMarks: quiz.marks,
            });
          } else {
            console.log(
              `Quiz with ID ${quiz.quizId} not found for user ${_id}`
            );
          }
        }

        // Push user details along with submitted quizzes details to userDetails array
        userDetails.push({
          name,
          email,
          submittedQuizzes,
        });
      }

      res.status(200).json({ userDetails });
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
  console.log(`Course-Service at ${PORT}`);
});
