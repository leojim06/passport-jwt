const AuthenticationController = require('./controllers/authentication');
const express = require('express');
const passportService = require('./config/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireLogin = passport.authenticate('local', { session: false });

const REQUIRE_ADMIN = "Admin";
const REQUIRE_OWNER = "Owner";
const REQUIRE_CLIENT = "Client";
const REQUIRE_MEMBER = "Member";

const User = require('./models/user');

module.exports = function (app) {

    // crea diferentes routers para las rutas
    const apiRoutes = express.Router();
    const authRoutes = express.Router();
    const userRoutes = express.Router();


    apiRoutes.use('/auth', authRoutes);

    // crea ruta de registro y usa el middleware de autenticación.
    authRoutes.post('/register', AuthenticationController.register);

    // crea ruta de login y usa la estrategia de passport para el login
    // también usa el middleware de autenticación para generar el token
    authRoutes.post('/login', requireLogin, AuthenticationController.login);

    // crea ruta segura que solo un miembro puede acceder si proporciona el token generado al logearse
    // usa la estrategia de passport para decifrar el token
    // usa el middleware de autenticación para permitir o negar el acceso según el rol que tenaga el usuario
    authRoutes.get('/secure', requireAuth, AuthenticationController.roleAuthorization(REQUIRE_MEMBER), function(req, res) {
        res.status(200).send('Mi clave secreta es: ---');
    });

    // ruta p{ublica que debuelve la lista de usuarios 
    userRoutes.get('/users', function (req, res) {
        User.find(function (err, users) {
            err ?
                res.status(500).send(err) :
                res.status(200).send(users);
        });
    });

    // ruta pública que debuelve un usuario por email
    userRoutes.get('/users/:email', function (req, res) {
        User.findOne({ email: req.params.email }, function (err, user) {
            err ?
                res.status(500).send(err) :
                !user ?
                    res.status(404).send('User Not Found') :
                    res.status(200).send(user);
        });
    });

    // agregar rutas públicas y protegidas a la aplicación
    app.use('/api', apiRoutes);
    app.use('/api', userRoutes);
}