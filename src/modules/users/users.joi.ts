import * as Joi from 'joi';

export const findByIdJoi = Joi.object({
  id: Joi.string().length(24).required(),
});

export const findAllJoi = Joi.object({
  excludeIds: Joi.alternatives().try(
    Joi.array().items(Joi.string()),
    Joi.string(),
  ),
  login: Joi.string().min(3).max(100),
  skip: Joi.number().min(0),
  limit: Joi.number().min(1).max(100),
  sortField: Joi.string().valid(...['id', 'login']),
  sortAsc: Joi.string().valid(...['asc', 'desc']),
});
