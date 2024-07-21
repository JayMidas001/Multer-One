const express = require('express')
require('./config/dbConfig.js')
const router = require('./router/userRouter.js');

const port = process.env.port || 5544

const app = express();
app.use(express.json())

app.use('/uploads', express.static('uploads'))

app.use('/api/v1/user', router)

app.listen(port, () => {
    console.log(`server running on PORT: ${port}`);
})