const crypto = require('crypto');
const bcrypt = require('bcryptjs')
const User = require('../models/user');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const { validationResult } = require('express-validator')

const transporter = nodemailer.createTransport(sendgridTransport({
  auth:{
    api:""
  }
}))

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  
  if(message.length>0){
    message = message[0];
  }else{
    message=null;
  }
  
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage:message,
    oldInput:{
      email:'',
      password:''
    },
    validationErrors:[]
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  
  if(message.length>0){
    message = message[0];
  }else{
    message=null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage:message,
    oldInput:{email:"",password:"",confirmPassword:""},
    validationErrors:[]
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if(!errors.isEmpty()){
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage:errors.array()[0].msg,
      oldInput:{
        email:email,
        password:password
      },
      validationErrors:errors.array()
    });
  }

  User.findOne({email:email})
    .then(user => {
      if(!user){
        req.flash('error','Invalid username or password.');
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage:'Invalid username or password.',
          oldInput:{
            email:email,
            password:password
          },
          validationErrors:[]
        });
      }
      bcrypt.compare(password,user.password)
      .then(doMatch=>{
        if(doMatch){
          req.session.isLoggedIn = true;
          req.session.user = user;
          return req.session.save(err => {
            console.log(err);
            return res.redirect('/');
          });
        }
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage:'Invalid username or password.',
          oldInput:{
            email:email,
            password:password
          },
          validationErrors:[]
        });
      }).catch(err=>{
        console.log(err);
        res.redirect("/login");
      })
     
    })
    .catch(err => {
      const error = new Error('Failed to get Products');
      error.httpStatusCode = 500;
      return next(error)
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);

  if(!errors.isEmpty()){
    console.log(errors.array());
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage:errors.array()[0].msg,
      oldInput:{email:email,password:password,confirmPassword:req.body.confirmPassword},
      validationErrors:errors.array()
    });
  }

    bcrypt.hash(password,12)
    .then(hashedPassword=>{
      const user = new User({
        email:email,
        password:hashedPassword,
        cart:{items:[]}
      })
      return user.save();
    })
    .then(result=>{
      res.redirect("/login");
      // return main(email,'Sigup Successful',"You're account has been created!");
    }).catch(err => {
      const error = new Error('Failed to get Products');
      error.httpStatusCode = 500;
      return next(error)
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req,res,next)=>{
  let message = req.flash('error');
  
  if(message.length>0){
    message = message[0];
  }else{
    message=null;
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage:message
  });
}


exports.postReset = (req,res,next)=>{
  crypto.randomBytes(32,(err,buffer)=>{
    if(err){
      console.log(err);
      return res.edirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({email:req.body.email})
    .then(user=>{
      if(!user){
        req.flash('error','No user found for the email.');
        return redirect("/reset");
      }
      user.resetToken = token;
      user.resetTokenExpiration = Date.now() + 3600000;
      return user.save();
    })
    .then(result=>{
      res.redirect('/');
      const msg = `
      <p>You're requested password reset</p>
      <p>Click this <a href="http://localhost:5000/reset/${token}">link</a> to reset password</p>
      `
      main(req.body.email,'Password Reset',msg)
    })
    .catch(err => {
      const error = new Error('Failed to get Products');
      error.httpStatusCode = 500;
      return next(error)
    });
  })
}

exports.getNewPassword = (req,res,next)=>{

  const token = req.params.token;

  User.findOne({resetToken:token,resetTokenExpiration:{$gt:Date.now()}})
  .then(user=>{
    let message = req.flash('error');
    if(message.length>0){
      message = message[0];
    }else{
      message=null;
    }
    res.render('auth/new-password', {
      path: '/new-password',
      pageTitle: 'New Password',
      errorMessage:message,
      userId:user._id.toString(),
      passwordToken:token
    });
  })
  .catch(err => {
    const error = new Error('Failed to get Products');
    error.httpStatusCode = 500;
    return next(error)
  });

}

exports.postNewPassword = (req,res,next)=>{

  let resetUser;
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;

  User.findOne({resetToken:passwordToken,resetTokenExpiration:{$gt:Date.now()},_id:userId})
  .then(user=>{
    resetUser = user;
    return bcrypt.hash(newPassword,12)
  })
  .then(hashedPassword=>{
    resetUser.password = hashedPassword;
    resetUser.resetToken = undefined;
    resetUser.resetTokenExpiration = undefined;
    return resetUser.save();
  })
  .then(result=>{
    return res.redirect("/login");
  })
  .catch(err => {
    const error = new Error('Failed to get Products');
    error.httpStatusCode = 500;
    return next(error)
  });
}

async function main(userMail,subject,msg) {
  const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'vivianne.ruecker@ethereal.email',
        pass: 'aPM7sPS17be43pbSq7'
    }
  });
  let info = await transporter.sendMail({
    from: '"James Swanson" <foo@example.com>',
    to: userMail, // Test email address
    subject: subject,
    html:msg,
  });
  console.log("Message sent: %s", info.messageId);
  console.log("View email: %s", nodemailer.getTestMessageUrl(info));
  return info;
}