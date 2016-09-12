'use strict'

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Schema para usuario.
const UserSchema = new Schema({
    email: { type: String, lowercase: true, unique: true, required: true },
    password: { type: String, required: true },
    profile: { firstName: { type: String }, lastName: { type: String } },
    role: { type: String, enum: ['Member', 'Client', 'Owner', 'Admin'], default: 'Member' },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date }
}, { timestamps: true });

// procedimiento antes de guardar información en base de datos
UserSchema.pre('save', function (next) {
    const user = this;
    const SALT_FACTOR = 5;

    // Si usuario no ha modificado el password regresa
    if (!user.isModified('password')) {
        return next();
    }

    // de lo contrario se encripta el password nuevo o modificado
    bcrypt.genSalt(SALT_FACTOR, function (err, salt) {
        if (err) {
            return next(err);
        }

        bcrypt.hash(user.password, salt, null, function (err, hash) {
            if (err) {
                return next(err);
            }
            // password encriptado a usuario.password
            user.password = hash;
            next();
        });
    });
});

// Método para comparar password ingresado por usuario y registrado en base de datos
UserSchema.methods.comparePassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) {
            return cb(err);
        }
        cb(null, isMatch);
    });
}

module.exports = mongoose.model('User', UserSchema);