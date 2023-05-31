import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { UserSchema } from '../models/userModel';


const User = mongoose.model('User', UserSchema);

export const loginRequired = (req, res, next) => {
    if (req.user) {
        next()
    } else {
        return res.status(401).json({ message: 'Unauthorized User!' })
    }
}

export const register = async (req, res) => {
    try {
        const newUser = new User(req.body);
        newUser.hashPassword = bcrypt.hashSync(req.body.password, 10);
        const user = await newUser.save();
        user.hashPassword = undefined;
        return res.json(user);
    } catch (err) {
        return res.status(400).send({
            message: err.message
        });
    }
};


export const login = async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(401).json({ message: 'Authentication failed. No user found' });
        } else if (!user.comparePassword(req.body.password, user.hashPassword)) {
            return res.status(401).json({ message: 'Authentication failed. Wrong password' });
        } else {
            return res.json({
                token: jwt.sign({
                    email: user.email,
                    username: user.username,
                    _id: user.id
                }, 'RESTFULAPIs')
            });
        }
    } catch (err) {
        throw err;
    }
};
