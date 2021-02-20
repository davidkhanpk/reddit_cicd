import "reflect-metadata";
import {createConnection} from "typeorm";
import express from 'express';
import morgan from 'morgan'
import trim from './middlware/trim';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

dotenv.config();

import authRoutes from './routes/auth';

const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(trim)
app.use(cookieParser());
app.use('/api/auth', authRoutes);
app.listen(5000, async () => {
    console.log("Server Started");
    try {
        await createConnection();
        console.log("Database Connected");
    } catch (err) {
        
    }
})

