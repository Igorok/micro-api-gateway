import * as Joi from 'joi';

export const registrationJoi = Joi.object({
  login: Joi.string().max(100).required(),
  email: Joi.string().max(100).required().email(),
  password: Joi.string().max(100).required(),
  passwordRepeat: Joi.ref('password'),
}).with('password', 'passwordRepeat');

export const loginJoi = Joi.object({
  login: Joi.string().max(100).required(),
  password: Joi.string().max(100).required(),
});
