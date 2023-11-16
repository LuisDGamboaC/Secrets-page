//jshint esversion:6
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from 'bcrypt';
import util from 'util';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from "passport";
import passportLocal from 'passport-local';
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

dotenv.config();

const app = express();
const saltRounds = 10;

app.use(session({
    secret: 'gorda pato',
    resave: false,
    saveUninitialized: false,
  }));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.DB_USER,
    host: "localhost",
    database: "User",
    password: process.env.DB_PASSWORD,
    port: 5432,
  });
  db.connect();

app.use(express.static("public"));  //css
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

const LocalStrategy = passportLocal.Strategy;

passport.use('local-signup', new LocalStrategy({
    usernameField: 'username', // assuming you use 'username' for the email field
    passwordField: 'password',
    passReqToCallback: true
  },
  async (req, username, password, done) => {
    try {
      // Check if the user already exists in the database
      const result = await db.query("SELECT * FROM userschema WHERE email = $1", [username]);
      
      if (result.rows.length > 0) {
        return done(null, false, { message: 'Email is already taken.' });
      } else {
        // If the email is not taken, insert the new user into the database
        const hash = await bcrypt.hash(password, saltRounds);
        await db.query("INSERT INTO userschema (email, passwords) VALUES ($1, $2)", [username, hash]);
        return done(null, { username: username });
      }
    } catch (error) {
      return done(error);
    }
  }
));

passport.use('local-login', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
  },
  async (req, username, password, done) => {
    try { 
            const result = await db.query("SELECT * FROM userschema WHERE email = $1", 
            [username]);
         
            if (result.rows.length > 0) {
                const user = result.rows[0];
                const storedPassword = user.passwords; 
         
                const passwordMatch = await bcrypt.compare(password, storedPassword) 
                    // result == true
                    if (passwordMatch) {
                        return done(null, user);
                    } else {
                        return done(null, false, { message: 'Incorrect password'});
                    } 
                    }
                    else {
                        return done(null, false, {message: 'User not found'});
                    }

        } catch (error) {
            console.error('Error occurred during login:', error);
            return done(error);
        }
  }
));

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        email: user.email, // Include the email
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

  // GOOGLE OAUTH
  passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    handleOAuth(accessToken, refreshToken, profile, cb);
    console.log(profile);

  }
));

function handleOAuth(accessToken, refreshToken, profile, cb) {
  const googleId = profile.id;

  // Check if the user with the given Google ID exists in the database
  db.query('SELECT * FROM userschema WHERE google_id = $1', [googleId], (err, result) => {
    if (err) {
      return cb(err);
    }

    // If the user exists, return the user
    if (result.rows.length > 0) {
      return cb(null, result.rows[0]);
    }

    // If the user doesn't exist, create a new user
    const insertQuery = 'INSERT INTO userschema (google_id) VALUES ($1) RETURNING *';
    const values = [googleId];

    db.query(insertQuery, values, (err, result) => {
      if (err) {
        return cb(err);
      }

      const newUser = result.rows[0];
      return cb(null, newUser);
    });
  });
}

app.get("/", (req, res)=> {
    res.render("home")
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }
));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", (req, res)=> {
    res.render("login")
});

app.get("/register", (req, res)=> {
    res.render("register")
});

 app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  if (req.isAuthenticated()) {
    const userId = req.user.id;

    // Insert a new secret for the authenticated user
    const insertQuery = 'INSERT INTO secretschema (user_id, secret) VALUES ($1, $2)';
    const values = [userId, submittedSecret];

    db.query(insertQuery, values, (err, result) => {
      if (err) {
        console.error('Error inserting secret:', err);
        res.status(500).send('Internal Server Error');
      } else {
        res.redirect("/secrets");
      }
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
    
});

app.get("/secrets", (req, res)=> {
  if (req.isAuthenticated()) {
    const userId = req.user.id;

    // Fetch all secrets for the authenticated user
    const selectQuery = 'SELECT secret FROM secretschema WHERE user_id = $1';
    const values = [userId];

    db.query(selectQuery, values, (err, result) => {
      if (err) {
        console.error('Error fetching secrets:', err);
        res.status(500).send('Internal Server Error');
      } else {
        const userSecrets = result.rows.map(row => row.secret);
        res.render("secrets.ejs", { secrets: userSecrets });
      }
    });
  } else {
    res.redirect("/login");
  }

});

//REGISTER:
// const bcryptHash = util.promisify(bcrypt.hash);
// 'promisify' is used to convert the callback-style (bcrypt.hash) function into a promise-based function. 
//The (bcrypt.hash) function traditionally uses a callback for its asynchronous operation, 
//but 'promisify' allows you to use it with async/await syntax, making the code more readable and easier to work with.

 
app.post("/register",passport.authenticate("local-signup", {
    successRedirect: '/secrets',  // Redirect to secrets page on successful registration
    failureRedirect: '/register'   // Redirect back to the registration page if there is an error
  })
);

 //MD5 NO ES SSEGURO

//LOGIN:

 app.post("/login", passport.authenticate("local-login", {
    successRedirect: '/secrets',
    failureRedirect: '/login',
}), (req, res) => {
console.log(req.user);
res.redirect("/secrets");
});


app.listen(3000, ()=> {
    console.log("Server running in port 3000");
})