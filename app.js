const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const csrf = require('csurf');
const flash = require("connect-flash");
const multer = require('multer');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const fs = require('fs');
const https = require('https');

const errorController = require('./controllers/error');
const User = require('./models/user');
const MONGODB_URI =
  `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.dkcigav.mongodb.net/${process.env.MONGO_DEFAULT_DATABASE}`;

const app = express();
const csrfProtection = csrf();

const privateKey  = fs.readFileSync('server.key');
const certificate = fs.readFileSync('server.cert');

const fileStorage = multer.diskStorage({
  destination:(req,file,cb)=>{
    cb(null,'productImages');
  },
  filename:(req,file,cb)=>{
    cb(null,new Date().toISOString()+'-'+file.originalname)
  }
})

const fileFilter = (req,file,cb)=>{
  if(file.mimetype === 'image/jpeg' || ile.mimetype === 'image/jpg' || ile.mimetype === 'image/png'){
    cb(null,true);
  }else{
    cb(null,false);
  }
}

const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: 'sessions'
});

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

const accessLogStream = fs.createWriteStream(path.join(__dirname,"access.log"),{flags:"a"});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(multer({storage:fileStorage,fileFilter:fileFilter}).single('image'))
app.use(express.static(path.join(__dirname, 'public')));
app.use('/productImages',express.static(path.join(__dirname, 'productImages')));
app.use(
  session({
    secret: 'my secret',
    resave: false,
    saveUninitialized: false,
    store: store
  })
);

app.use(csrfProtection);
app.use(flash());
app.use(helmet());
app.use(compression());
app.use(morgan('combined',{stream:accessLogStream}));

app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  }
  User.findById(req.session.user._id)
    .then(user => {
      if(!user){
        return next();
      }
      req.user = user;
      next();
    })
    .catch(err => {
      next(new Error(err))
    });
});

app.use((req,res,next)=>{
  res.locals.isAuthenticated = req.session.isLoggedIn;
  res.locals.csrfToken = req.csrfToken();
  next();
})

app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.get('/500',errorController.get500);
app.use(errorController.get404);
app.use((error,req,res,next)=>{
  res.status(500).render('500', {
    pageTitle: 'Something went wrong',
    path: '/500',
    isAuthenticated: req.session.isLoggedIn
  });
})

mongoose
  .connect(MONGODB_URI,{ useNewUrlParser: true,useUnifiedTopology:true })
  .then(result => {
    // https.createServer({key:privateKey,cert:certificate},app).listen(process.env.PORT || 5000);
    app.listen(process.env.PORT || 5000)
    console.log(`APPLICATION IS RUNNING AT PORT ${process.env.PORT}`);
  })
  .catch(err => {
    console.log(err);
  });
