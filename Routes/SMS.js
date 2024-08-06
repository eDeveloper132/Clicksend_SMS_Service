import express from 'express';
import "dotenv/config";
import { fileURLToPath } from 'url';
import path from 'path';
import axios from 'axios'; // Use axios for HTTP requests
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const router = express.Router();
router.get('/', (req, res) => {
    res.sendFile(path.resolve(__dirname, "../Views/sms.html"));
});
router.post('/', (req, res) => {
    const { phonecode, phonenumber, message } = req.body;
    // console.log(req.body);
    if (phonecode && phonenumber && message) {
        const mix = phonecode + phonenumber;
        console.log(`We are delivering this message: ${message} to ${mix}`);
        const sendSms = async () => {
            const smsMessage = {
                // from: "+923198142225",
                to: `${mix}`,
                body: `${message}`
            };
            const apiUrl = 'https://rest.clicksend.com/v3/sms/send';
            try {
                const response = await axios.post(apiUrl, {
                    messages: [smsMessage]
                }, {
                    auth: {
                        username: process.env.USERNAME,
                        password: process.env.API_KEY
                    }
                });
                console.log(response.data);
            }
            catch (err) {
                console.error(err.response ? err.response.data : err.message);
            }
        };
        sendSms();
    }
    else {
        console.log('Server Error code 500');
        res.sendStatus(500);
    }
});
export default router;
