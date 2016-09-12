'use strict'

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/user');
const config = require('../config/main');


/**
 * Función que genera Token con información de usuario.
 * 
 * @param {any} user Información del usuario
 * @returns token con información de usuario cifrada y tiempo de expiración
 */
function generateToken(user) {
    return jwt.sign(user, config.secret, {
        expiresIn: 10080
    });
}


/**
 * Normaliza la información de usuario para incluir solo los datos necesarios 
 * 
 * @param {any} request Usuario recuperado de la base de datos.
 * @returns información de usuario normalizada
 */
function setUserInfo(request) {
    return {
        _id: request._id,
        firstName: request.profile.firstName,
        lastName: request.profile.lastName,
        email: request.email,
        role: request.role
    };
}

// función de login que usa la función @see setUserInfo
// para normalizar la info del usuario y retornar un 
// token con la función @see generateToken
exports.login = function (req, res, next) {
    let userInfo = setUserInfo(req.user);

    res.status(200).json({
        token: 'JWT ' + generateToken(userInfo),
        user: userInfo
    });
}


// función de registro de nuevos usuarios
exports.register = function (req, res, next) {
    const email = req.body.email;
    const firstName = req.body.firstName;
    const lastName = req.body.lastName;
    const password = req.body.password;

    // toma la información enviada dentro del body y valida su existencia
    if (!email) {
        return res.status(422).send({
            error: 'Debe ingresar email'
        });
    }

    if (!firstName || !lastName) {
        return res.status(422).send({
            error: 'Debe ingresar nombre'
        });
    }
    if (!password) {
        return res.status(422).send({
            error: 'Debe ingresar contraseña'
        });
    }

    // valida que no exista el email
    User.findOne({ email: email }, function (err, existingUser) {
        if (err) {
            return next(err);
        }

        if (existingUser) {
            return res.status(422).send({
                error: 'El correo electrónico ya esta en uso.'
            });
        }

        // crea un elemento user con la información registrada
        let user = new User({
            email: email,
            password: password,
            profile: {
                firstName: firstName,
                lastName: lastName
            }
        });

        // hace el intento de registrar los datos en la base de datos
        user.save(function (err, user) {
            if (err) {
                return next(err);
            }


            // si la información es registrada exitosamente en el repositorio
            // normaliza la información del usuario nuevo creado
            // genera un token y lo envia
            let userInfo = setUserInfo(user);

            res.status(201).json({
                token: 'JWT ' + generateToken(userInfo),
                user: userInfo
            });
        });
    });
}


// función que verifica la existencia del rol del usuario.
// recibe como parametro el rol que se quiere validar
exports.roleAuthorization = function (role) {
    return function (req, res, next) {
        const user = req.user;

        // busca el usuario con la información que llega en el req
        User.findById(user._id, function (err, foundUser) {
            if (err) {
                res.status(422).json({
                    error: 'Usuario no encontrado.'
                });
            }

            // si encuentra el usuario y tiene el mismo rol al que se solicita
            // en el parametro de entrada de la función continúa con el procedimiento
            if (foundUser.role === role) {
                return next();
            }

            res.status(401).json({
                error: 'No esta autorizado para ver esta página'
            });

            // si el rol es diferente al requerido, se desautoriza el ingreso
            return next('Unauthorized');
        })
    }
}