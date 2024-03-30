import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

env.config();

const app = express();
const port = 3000;
const saltRounds = process.env.SALT_ROUND;

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRETS,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get(
  "/auth/google", 
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {

    try {
      const result = await db.query("SELECT secret FROM users WHERE email = $1", [req.user.email]);
      const secret = result.rows[0].secret;
      if (secret) {
        res.render("secrets.ejs", {secret: secret});
      } else {
        res.render("secrets.ejs", {secret: "Submit a Secret"});
      }
    } catch (err) {
      console.log(err)
    }
  } else {
    res.redirect("/login");
  }
});

// app.get("/secrets", async (req, res) => {
//   if (req.isAuthenticated()) {
//     try {
//       const result = await db.query("SELECT secret FROM users WHERE email = $1", [req.user.email]);
//       const secret = result.rows[0] ? result.rows[0].secret : "Submit a Secret";
//       res.render("secrets.ejs", { secret: secret }); // Pass the secret variable to the template
//     } catch (err) {
//       console.log(err);
//       res.redirect("/login");
//     }
//   } else {
//     res.redirect("/login");
//   }
// });


app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  console.log(req.user);

  try {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [secret, req.user.email]);
    res.redirect("/secrets");
  } catch (error) {
    console.log(err);
  }
});

// app.post("/submit", async (req, res) => {
//   const secret = req.body.secret;

//   try {
//     await db.query("UPDATE users SET secret = $1 WHERE email = $2", [secret, req.user.email]);
//     // Render the secrets.ejs template and pass the secret variable
//     res.render("secrets.ejs", { secret: secret });
//   } catch (error) {
//     console.log(err);
//   }
// });

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {

  const email = req.body.username
  const password = req.body.password

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
  
    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //Password Hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log(err)
            res.redirect("/secrets")
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    console.log(username);

    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;

        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err)
          } else {
            if (result) {
              return cb(null, user)
            } else {
              return cb(null, false)
            }
          }
        });
      } else {
        return cd("User not Found");
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "http://www.googleapis.com/oauth2/v3/userinfo",
    }, 
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "google"]);
          cb(null, newUser.rows[0]);
        } else {
          cb(null, result.rows[0]);
        }
      } catch (err) {
        cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log("Server running on port 3k");
});
