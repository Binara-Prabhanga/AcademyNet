const passport = require("passport");
const User = require("../user");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const keys = require("../config/keys");
const dotenv = require("dotenv");
dotenv.config();

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = keys.secretKey;

module.exports = () => {
  // JWT Strategy
  passport.use(
    new JwtStrategy(opts, async (jwt_payload, done) => {
      try {
        const user = await User.findById(jwt_payload.id);
        if (user) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      } catch (err) {
        return done(err, false);
      }
    })
  );

  // Google OAuth Strategy
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ googleId: profile.id });
  
          if (!user) {
            // If no user is found, create a new user
            user = new User({
              googleId: profile.id,
              name: profile.displayName,
              email: profile.emails[0].value,
              accessToken,  // Store accessToken in the user object
              refreshToken, // Store refreshToken if provided
            });
            await user.save();
          } else {
            // Update the user's accessToken each time they log in
            user.accessToken = accessToken;
  
            // Optionally update the refreshToken if it's provided (usually on first login)
            if (refreshToken) {
              user.refreshToken = refreshToken;
            }
  
            await user.save(); // Save updated tokens
          }
  
          done(null, user);
        } catch (err) {
          done(err, null);
        }
      }
    )
  );
  

  // Serialize and Deserialize User
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
};
