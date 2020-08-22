require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}))

// Session and passport initialize
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());


//Mongoose connection and userSchema
mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    username: { type: String,
            required: true},
    password: { type: String,
        required: true,
        minlength: 6
    },
    confirmPass: { type: String,
        required: true,
        minlength: 6
    },
    googleId: String,
    secret: String
});

userSchema.plugin(passportMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

//Using passport to serialize and desirialize User
passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser((id, done) => {
    User.findById(id,(err, user) => {
      done(err, user);
    });
  });

//Authenticate user
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/home',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  (accessToken, refreshToken, profile, cb) => {
    User.findOrCreate({ googleId: profile.id }, (err, user) => {
      return cb(err, user);
    });
  }
));


//get routes
app.get('/', (req, res) => {
    res.render('welcome');
})

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }))

app.get('/auth/google/home',  passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
    res.redirect('/home');
    }
)

app.get('/login', (req, res) => {
    res.render('login');
})

app.get('/register', (req, res) => {
    res.render('register');
})

app.get('/home', (req, res) => {
    User.find({ 'secret': { $ne: null}}, (err, userFound) => {
        if(err){
            console.log(err);
        } else{
            if(userFound){
                res.render("home", {usersWithSecrets: userFound});
            }
        }
    })
})

app.get('/submit', (req, res) => {
    if(req.isAuthenticated()){
        res.render('submit');
    } else{
        res.redirect('/login');
    }
})

app.get('/logout', (req, res) => {
    req.logOut();
    res.redirect('/');
})


//post routes
app.post('/submit', (req, res) => {

    const secret = req.body.secret;
    
    User.findById(req.user.id, (err, userFound) => {
        if(err){
            console.log(err);
        } else{
            if(userFound){
                userFound.secret = secret;
                userFound.save(() => {
                    res.redirect('/home');
                })
            }
        }
    })
});

app.post('/register', (req, res) => {

    if(req.body.password === req.body.confirmPass){
        User.register({username: req.body.username}, req.body.password, (err, user) => {
            if(err){
                console.log(err);
                res.redirect('/register');
            } else{
                passport.authenticate('local')(req, res, () => {
                    res.redirect('/home');
                })
            }
        })
    }
    else{
        console.log('Passwords must match!');
        res.redirect('/register');
    }
})

app.post('/login', (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err){
            console.log(err);
            res.redirect('/login')
        } else{
            passport.authenticate('local')(req, res, () => {
                res.redirect('/home');
            })
        }
    })

})

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
})