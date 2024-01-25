require('dotenv').config();
const express= require('express')
const app = express();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const PORT = 6500;

app.use(express.raw());
app.use(express.json());

mongoose.connect(process.env.DB_URL,{
    useNewUrlParser: true,
    useUnifiedTopology : true
}).then((data)=>{
    console.log('MongoDB Connected');
}).catch((err)=>{
    console.log(err)
});

app.use('/api',require('./routes/route'))
app.listen(PORT,()=>{
    console.log(`Server Running on port: ${PORT}`)
})