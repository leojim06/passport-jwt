'use static'

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const morgan = require('morgan');
const mongoose = require('mongoose');
const config = require('./config/main');
const router = require('./router');


const server = app.listen(config.port);
console.log('Servidor corriendo en puerto ' + config.port);

app.use(morgan('dev'));

// CORS para permitir peticiones del cliente
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "PUT, GET, POST, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Origin, X-Request-With, Content-Type, Accept, Authorization, Access-Control-Allow-Credentials");
    res.header("Access-Control-Allow-Credentials", "true");
    next();
});

// Conección a base de datos
mongoose.connect(config.database);

// bodyParser para permitir la recepción de información en el body del req.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Agregar las rutas a la aplicación
router(app);