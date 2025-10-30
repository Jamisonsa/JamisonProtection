require('dotenv').config();
const twilio = require('twilio');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

(async () => {
    try {
        const message = await client.messages.create({
            body: '🚨 Test alert from Jamison Protection!',
            from: process.env.TWILIO_FROM || undefined,
            messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID || undefined,
            to: '+14434102459'
        });
        console.log('✅ Message sent:', message.sid);
    } catch (err) {
        console.error('❌ Error:', err.message);
    }
})();
