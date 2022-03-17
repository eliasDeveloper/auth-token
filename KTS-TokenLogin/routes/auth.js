const router = require('express').Router()
const User = require('../model/User')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
//VALIDATION
const Joi = require('@hapi/joi');
const schema = Joi.object({
    name: Joi.string().min(6).required(),
    email: Joi.string().min(6).required().email(),
    password: Joi.string() .min(6) .required()
 });

 const loginSchema = Joi.object({
    email: Joi.string().min(6).required().email(),
    password: Joi.string() .min(6) .required()
 });

router.post('/register', async (req, res)=> {
    const {error} = schema.validate(req.body);
    //const {error} = regsiterValidation(req.body);
    if(error){
        return res.status(400).send(error.details[0].message)
    }
    //Checking if the user is already in the db
    const emailExist = await User.findOne({email: req.body.email})
    if(emailExist){
        return res.status(400).send('email already exists')
    }
    //HASH the password
    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash(req.body.password, salt)
    //Create a new User
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword     
    })
    try{
        const savedUser = await user.save()
        res.send({user: user._id})
    }catch(err){
        res.status(400).send(err)
    }
 })

 router.post('/login', async (req, res)=>{
     const { error } = loginSchema.validate(req.body)
     if(error){
         return res.status(400).send(error.details[0].message)
     }
     //Checking if the email is already in the db
    const user = await User.findOne({email: req.body.email})
    if(!user){
        return res.status(400).send('failed login: invalid credentials')
    }
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if(!validPass){
        return res.status(400).send('failed login: invalid credentials')
    }
    jwt.sign({user}, 'secretkey',{expiresIn: '600s'}, (err, token)=>{
        res.json({
            token
        })
    });

 })

module.exports = router;