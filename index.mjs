import express from 'express';
import 'dotenv/config';
import cors from 'cors';
import path from 'path';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import { SignModel , TokenModel } from './Schema/Post.mjs';
import MainRoute from './Routes/Main.mjs';
import SMSRoute from './Routes/SMS.js'
import connection from './DB/db.mjs';

const PORT = process.env.PORT || 3437;
const app = express();

app.use(express.json());
app.use(cors());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

await connection();

const SessionManager = [];
let OneTime = [];
const ExpiredTokens = [];
const FetchUserDetails = [];

app.use('/assets', express.static(path.join(__dirname, 'assets')));

function clearOneTimeToken() {
    const maxTimeout = Math.pow(2, 31) - 1; // Maximum timeout value in JavaScript

    // Check for the minimum of desired timeout and maxTimeout to avoid overflow
    const timeoutDuration = Math.min(2.592E+09, maxTimeout); // 30 days or max timeout

    setTimeout(async() => {
        if (OneTime.length > 0) {
            console.log("OneTime token expired");
            OneTime.shift();
            const Token = OneTime[0];
            const signin = await SigninModel.findOneAndDelete({Token});
            console.log('Deleted Token', signin);
            // Additional logic can be added here, like notifying the user
        }
    }, timeoutDuration);
}

// Initially set the timeout to clear the token if already present
if (OneTime.length > 0) {
    clearOneTimeToken();
}

app.use((req, res, next) => {
    if (OneTime[0]) {
        const isValidToken = SessionManager.some(session => session.Token === OneTime[0]);

        if (!isValidToken) {
            console.log("Invalid Token");
            OneTime.shift();
            SessionManager.shift();
            return res.redirect('/signin');
        }

        if (req.path.toLowerCase() === '/signin' || req.path.toLowerCase() === '/signup') {
            return res.redirect('/');
        } else {
            console.log("Success");
            next();
        }
    } else {
        console.log('OneTime Token is not set');
        if (req.path.toLowerCase() === '/signin' || req.path.toLowerCase() === '/signup') {
            next();
        } else {
            return res.redirect('/signin');
        }
    }

    // Reset the timeout whenever a new token is set in OneTime array
    if (OneTime.length > 0) {
        clearOneTimeToken();
    }
});


app.get("/signup", (req, res) => {
    res.sendFile(path.resolve(__dirname, "./Views/signup.html"));
});

app.post("/signup", async (req, res) => {
    const { Name, Email, Password } = req.body;
    try {
        if (Name && Email && Password) {
            const hashedPassword = await bcrypt.hash(Password, 10);
            console.log('Hashed Password:', hashedPassword);
    
            const newId = uuidv4();
            const newUser = await SignModel.create({ 
                id: newId, 
                Name, 
                Email,
                Password: hashedPassword 
            });
            await newUser.save();
            console.log("User registered:", newUser);
            const formObject = {
                Email: newUser.Email,
                Password: Password
            }
            await fetch('http://localhost:4919/signin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formObject),
            });
            
            res.status(200)
        } else {
            console.log("Error: Missing fields");
            res.status(400).send("Error: Missing fields");
        }
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/signin", (req, res) => {
    res.sendFile(path.resolve(__dirname, "./Views/signin.html"));
});

app.post('/signin', async (req, res) => {
    const { Email, Password } = req.body;

    try {
        if (!Email || !Password) {
            return res.status(400).send('Error: Missing fields');
        }

        const user = await SignModel.findOne({ Email });
        if (!user) {
            console.log('User not found');
            return res.status(401).send('Error: Invalid email');
        }

        const isMatch = await bcrypt.compare(Password, user.Password);
        if (!isMatch) {
            console.log('Password does not match');
            return res.status(401).send('Error: Invalid password');
        }

        const token = uuidv4();
        const hashedToken = await bcrypt.hash(token, 10);
        await SessionManager.push({
            Token: hashedToken
        });
        const signin = await TokenModel.create({
            Token: hashedToken
        });
        await signin.save();
        await OneTime.push(hashedToken);
        await ExpiredTokens.push({
            Token: hashedToken
        });
        await FetchUserDetails.push({
            user
        });
        console.log('User logged in:', user);
        console.log('Uploaded Id on Database:', signin);
        console.log('Generated access token:', hashedToken);
        res.redirect('/');
    } catch (error) {
        console.error('Error during login:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/reset-Session', async (req, res) => {
    const Token = OneTime[0];
    const signin = await TokenModel.findOneAndDelete({Token});
    console.log('Deleted Token', signin);
    await OneTime.shift();
    await SessionManager.shift();
    await FetchUserDetails.shift();
    res.status(200).send("Session reset");
});

app.post('/user', async (req, res) => {
    const Data = FetchUserDetails[0];
    console.log(Data);
    try {
        if (!Data.Email || !Data.Password) {
            return res.status(400).send('Error: Missing fields');
        }
        const Id = Data._id;
        const user = await SignModel.findById(Id);
        if (!user) {
            console.log('User not found');
            return res.status(401).send('Error: Invalid email');
        }

        const isMatch = await bcrypt.compare(Password, user.Password);
        if (!isMatch) {
            console.log('Password does not match');
            return res.status(401).send('Error: Invalid password');
        }
        const data = {
            Name: user.Name,
            Email: user.Email,
            Password: user.Password
        };
        
        res.send(data);
    } catch (error) {
        console.error('Error during login:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.use('/', MainRoute);
app.use('/sms',SMSRoute)

app.use("*", (req, res) => {
    // res.status(404).sendFile(path.resolve(__dirname, './Views/Other/page-404.html'));
    res.status(404).send({
        message: "Page Not Found"
    })
});
export {
    FetchUserDetails ,
    OneTime ,
    SessionManager 
}