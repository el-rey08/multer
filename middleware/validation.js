const joiValidation = require("@hapi/joi");

exports.singUpVlidator = async (req, res, next) => {
  const Schema = joiValidation.object({
    fullname: joiValidation
      .string()
      .required()
      .min(3)
      .trim()
      .regex(/^[A-Za-z]+(?: [A-Za-z]+)*$/)
      .messages({
        "any.required": "please provide first name",
        "string.empty": "first name cannot be empty",
        "string.min": "the minium name must be at least 3 character long",
        "string.pattern.base": "first name should only contain letters",
      }),

    email: joiValidation
    .string()
    .email()
    .min(7)
    .required()
    .messages({
      "any.required": "please provide your email address",
      "string.empty": "email cannot be empty",
      "string.email":
        "invalid email format. please enter a valid email address",
    }),

    password: joiValidation
      .string()
      .required()
      .min(8)
      .max(50)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z0-9!@#$%^&*(),.?":{}|<>]{8,50}$/
      )
      .messages({
        "string.pattern.base":
          "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character",
        "string.empty": "Password cannot be empty",
      }),
  });
  const { error } = Schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }
  next();
};

exports.logInValidator = async (req, res, next) => {
  const Schema = joiValidation.object({
    email: joiValidation.string().email().min(7).required().messages({
      "any.required": "please provide your email address",
      "string.empty": "email cannot be empty",
      "string.email":"invalid email format. please enter a valid email address",
    }),

    password: joiValidation
      .string()
      .required()
      .min(8)
      .max(50)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z0-9!@#$%^&*(),.?":{}|<>]{8,50}$/
      )
      .messages({
        "string.pattern.base":
          "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character",
        "string.empty": "Password cannot be empty",
      }),
  });
  const { error } = Schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      message: error.details[0].message,
    });
  }
  next();
};
