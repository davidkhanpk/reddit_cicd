import {Request, Response, NextFunction } from 'express';
import { User } from '../entities/User';
import  jwt from 'jsonwebtoken';

export default async (req: Request, res: Response, next: NextFunction) => {
    try {
        const token = req.cookies.token;
        if(!token) {
            throw new Error('Unauthenticated');
        }
        const { username }: any = jwt.verify(token, process.env.JWT_SECRET);
        const user = User.findOne({username});
        if(!user) {
            return res.status(400).json({})
        }
        res.locals.user = user
    } catch (err) {

    }
}