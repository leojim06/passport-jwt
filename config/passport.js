'use strict'

const passport = require('passport');
const User = require('../models/user');
const config = require('./main');
const JwtStategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');



// -----------------------------------------
// ----------   PASSPORT LOCAL      --------
// -----------------------------------------
// opciones para la estrategia local
// usa el campo email como campo de inicio de sesión
const localOptions = { usernameField: 'email' };

// establecer la estrategia para el inicio de sesión local
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
    // encontrar un usuario por email
    User.findOne({ email: email }, function (err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false, { error: 'No se pudo iniciar sesión. Verifique password y contraseña' });
        }
        // compara el passport ingresado con el password dentro de la base de datos
        // con ayuda del metodo creado en el schema de usuario
        user.comparePassword(password, function (err, isMatch) {
            if (err) {
                return done(err);
            }
            if (!isMatch) {
                return done(null, false, { error: 'No se pudo iniciar sesión. Verifique password y contraseña' });
            }
            // login exitoso, debuelve información del usuario de la base de datos.
            return done(null, user);
        });
    });
});


// -----------------------------------------
// ----------   PASSPORT JWT      ----------
// -----------------------------------------
// opciones para decodificar token 
// especifica la extracción del token desde la cabecera de la solicitud
// solicita la clave para decodificar el token y verificarlo.
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeader(),
    secretOrKey: config.secret
}

// establecer la estrategia para validar el JWT
const jwtLogin = new JwtStategy(jwtOptions, function (payload, done) {
    // una vez decodificado el token, recupera del payload el id y lo busca
    User.findById(payload._id, function (err, user) {
        if (err) {
            return done(err, false);
        }
        if (!user) {
            done(null, false);
        }
        // debuelve usuario si corresponde con un usuario de la base de datos
        done(null, user);
    });
});


// incluye en passport el uso de las estrategias locales y de JWT
passport.use(jwtLogin);
passport.use(localLogin);