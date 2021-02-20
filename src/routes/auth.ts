import { IsEmpty, validate } from "class-validator";
import { Request, Response, Router } from "express";
import { User } from "../entities/User";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';
import cookie from "cookie";

const register = async (req: Request, res: Response) => {
    const { email, username, password } = req.body;
    try {
        let errors: any = {};
        const emailUser = await User.findOne({email});
        const usernameUser = await User.findOne({username});
        const user = new User({ email, username, password});
        if (emailUser) errors.email = "Email is already taken";
        if (usernameUser) errors.email = "Username is already taken";

        if(Object.keys(errors).length > 0) {
            return res.status(400).json(errors);
        }
        errors = await validate(user);
        if(errors.length > 0 ) {
            return res.status(400).json(errors);
        }
        await user.save();
        return res.json(user);
    } catch (err) {
        return res.status(500).json(err)
    }
}

const login = async (req: Request,  res: Response ) => {
    let errors: any = {};
    const { username, password} = req.body;
    if(IsEmpty(username)) {
        errors.username = "Username must be atleast 3 characters long"
    }
    if(IsEmpty(password)) {
        errors.passowrd = "Password must be atleast 6 chatacters long";
    }
    if(Object.keys(errors).length) {
        return res.status(400).json({ errors })
    }
    try {
        const user = await User.findOne({ username });
        if(!user) {
            return res.status(400).json({error: " User not found "});
        }
        const passwordMatches = await bcrypt.compare(password, user.password);
        if(!passwordMatches) {
            return res.status(400).json({error: "Wrong Password"})
        }
        const token  =jwt.sign({username}, process.env.JWT_SECRET);
        res.set('Set-Cookie', cookie.serialize('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production' ? true : false,
            sameSite: 'strict',
            maxAge: 3600,
            path: '/'
        }))

        return res.json(user);
    } catch(err) {
        
    }
}

const me = async (req: Request, res: Response) => {
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
        return res.json(user);
    } catch(err) {
        return res.json(401).json({ error: "Unauthenticated"})
    }
}

const logout = async (req: Request, res: Response) => {
    res.set("Set-Cookie", cookie.serialize('token', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV == 'production' ? true : false,
        sameSite: 'strict',
        expires: new Date(0),
        path: '/'
    }))

    return res.status(200).json({success: true})
}

const router = Router();
router.post('/register', register);
router.post('/login', login);
router.post('/me', me);

export default router;
